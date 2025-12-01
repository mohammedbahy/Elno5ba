package com.bahy.elno5ba.data.repository

import com.bahy.elno5ba.data.model.UserProfile
import com.google.firebase.Timestamp
import com.google.firebase.auth.FirebaseAuth
import com.google.firebase.firestore.FirebaseFirestore
import kotlinx.coroutines.tasks.await

class UserProfileRepository(
    private val firestore: FirebaseFirestore = FirebaseFirestore.getInstance()
) {
    
    /**
     * Get user profile from Firestore
     * الحصول على الملف الشخصي من Firestore
     */
    suspend fun getUserProfile(userId: String): Result<UserProfile?> {
        return try {
            val document = firestore.collection("userProfiles")
                .document(userId)
                .get()
                .await()
            
            if (document.exists()) {
                val profile = UserProfile.fromMap(document.data!!)
                Result.success(profile)
            } else {
                // Profile doesn't exist, return null
                Result.success(null)
            }
        } catch (e: Exception) {
            Result.failure(e)
        }
    }
    
    /**
     * Get current user profile
     * الحصول على الملف الشخصي للمستخدم الحالي
     */
    suspend fun getCurrentUserProfile(): Result<UserProfile?> {
        val currentUser = FirebaseAuth.getInstance().currentUser
        if (currentUser == null) {
            return Result.failure(Exception("User not authenticated"))
        }
        return getUserProfile(currentUser.uid)
    }
    
    /**
     * Save or update user profile
     * حفظ أو تحديث الملف الشخصي
     */
    suspend fun saveUserProfile(profile: UserProfile): Result<Unit> {
        return try {
            val currentUser = FirebaseAuth.getInstance().currentUser
            if (currentUser == null) {
                return Result.failure(Exception("User not authenticated"))
            }
            
            // Ensure userId matches current user
            val profileWithUserId = profile.copy(userId = currentUser.uid)
            
            // Check if profile exists
            val existingDoc = firestore.collection("userProfiles")
                .document(currentUser.uid)
                .get()
                .await()
            
            val profileToSave = if (existingDoc.exists()) {
                // Update existing profile
                profileWithUserId.copy(
                    createdAt = UserProfile.fromMap(existingDoc.data!!).createdAt,
                    updatedAt = Timestamp.now()
                )
            } else {
                // Create new profile
                profileWithUserId.copy(
                    createdAt = Timestamp.now(),
                    updatedAt = Timestamp.now()
                )
            }
            
            firestore.collection("userProfiles")
                .document(currentUser.uid)
                .set(profileToSave.toMap())
                .await()
            
            // Also save unencrypted name to users collection for admin access
            if (profileToSave.fullName.isNotEmpty()) {
                firestore.collection("users")
                    .document(currentUser.uid)
                    .set(mapOf(
                        "userId" to currentUser.uid,
                        "fullName" to profileToSave.fullName,
                        "email" to (profileToSave.email.ifEmpty { currentUser.email ?: "" }),
                        "updatedAt" to Timestamp.now()
                    ), com.google.firebase.firestore.SetOptions.merge())
                    .await()
            }
            
            // Update Firebase Auth display name
            val profileUpdates = com.google.firebase.auth.UserProfileChangeRequest.Builder()
                .setDisplayName(profileToSave.fullName.ifEmpty { null })
                .build()
            currentUser.updateProfile(profileUpdates).await()
            
            // Update Firebase Auth email if changed
            val currentEmail = currentUser.email
            val newEmail = profileToSave.email.trim().lowercase()
            if (currentEmail != null && currentEmail != newEmail && newEmail.isNotEmpty()) {
                try {
                    // Update email in Firebase Auth
                    currentUser.updateEmail(newEmail).await()
                    // Send verification email
                    currentUser.sendEmailVerification().await()
                } catch (e: Exception) {
                    // If email update fails, log but don't fail the whole operation
                    android.util.Log.e("UserProfileRepository", "Failed to update email in Firebase Auth: ${e.message}", e)
                }
            }
            
            Result.success(Unit)
        } catch (e: Exception) {
            Result.failure(e)
        }
    }
    
    /**
     * Update specific fields in user profile
     * تحديث حقول محددة في الملف الشخصي
     */
    suspend fun updateUserProfileFields(
        fullName: String? = null,
        nickName: String? = null,
        email: String? = null,
        phoneNumber: String? = null,
        dateOfBirth: String? = null,
        gender: String? = null
    ): Result<Unit> {
        return try {
            val currentUser = FirebaseAuth.getInstance().currentUser
            if (currentUser == null) {
                return Result.failure(Exception("User not authenticated"))
            }
            
            val updates = mutableMapOf<String, Any>()
            updates["updatedAt"] = Timestamp.now()
            
            fullName?.let { updates["fullName"] = it }
            nickName?.let { updates["nickName"] = it }
            email?.let { updates["email"] = it }
            phoneNumber?.let { updates["phoneNumber"] = it }
            dateOfBirth?.let { updates["dateOfBirth"] = it }
            gender?.let { updates["gender"] = it }
            
            firestore.collection("userProfiles")
                .document(currentUser.uid)
                .update(updates)
                .await()
            
            // Also update unencrypted name in users collection for admin access
            fullName?.let {
                firestore.collection("users")
                    .document(currentUser.uid)
                    .set(mapOf(
                        "userId" to currentUser.uid,
                        "fullName" to it,
                        "email" to (email ?: currentUser.email ?: ""),
                        "updatedAt" to Timestamp.now()
                    ), com.google.firebase.firestore.SetOptions.merge())
                    .await()
            }
            
            // Update Firebase Auth display name if fullName changed
            fullName?.let {
                val profileUpdates = com.google.firebase.auth.UserProfileChangeRequest.Builder()
                    .setDisplayName(it)
                    .build()
                currentUser.updateProfile(profileUpdates).await()
            }
            
            // Update Firebase Auth email if email changed
            email?.let { newEmail ->
                val currentEmail = currentUser.email
                val trimmedEmail = newEmail.trim().lowercase()
                if (currentEmail != null && currentEmail != trimmedEmail && trimmedEmail.isNotEmpty()) {
                    try {
                        // Update email in Firebase Auth
                        currentUser.updateEmail(trimmedEmail).await()
                        // Send verification email
                        currentUser.sendEmailVerification().await()
                    } catch (e: Exception) {
                        // If email update fails, log but don't fail the whole operation
                        android.util.Log.e("UserProfileRepository", "Failed to update email in Firebase Auth: ${e.message}", e)
                    }
                }
            }
            
            Result.success(Unit)
        } catch (e: Exception) {
            Result.failure(e)
        }
    }
}


