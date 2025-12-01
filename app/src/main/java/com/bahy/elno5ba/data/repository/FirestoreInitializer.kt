package com.bahy.elno5ba.data.repository

import com.bahy.elno5ba.data.model.UserRole
import com.google.firebase.Timestamp
import com.google.firebase.auth.FirebaseAuth
import com.google.firebase.firestore.FirebaseFirestore
import kotlinx.coroutines.tasks.await

/**
 * Utility class to initialize Firestore collections and set up default data
 * يمكن استخدام هذه الكلاس لتهيئة البيانات الأولية في Firestore
 */
object FirestoreInitializer {
    
    private val firestore = FirebaseFirestore.getInstance()
    private val auth = FirebaseAuth.getInstance()
    
    /**
     * Initialize user role for current user (default: student)
     * تهيئة دور المستخدم الحالي (افتراضياً: student)
     */
    suspend fun initializeUserRole(role: String = "student"): Result<Unit> {
        return try {
            val currentUser = auth.currentUser
            if (currentUser == null) {
                return Result.failure(Exception("User not authenticated"))
            }
            
            // Check if role already exists
            val existingRole = firestore.collection("userRoles")
                .document(currentUser.uid)
                .get()
                .await()
            
            if (existingRole.exists()) {
                // Role already exists, don't overwrite
                return Result.success(Unit)
            }
            
            // Create new role
            val userRole = UserRole(
                userId = currentUser.uid,
                role = role,
                createdAt = Timestamp.now()
            )
            
            firestore.collection("userRoles")
                .document(currentUser.uid)
                .set(userRole)
                .await()
            
            // Also save unencrypted name to users collection for admin access
            val displayName = currentUser.displayName
            if (displayName != null && displayName.isNotEmpty()) {
                firestore.collection("users")
                    .document(currentUser.uid)
                    .set(mapOf(
                        "userId" to currentUser.uid,
                        "fullName" to displayName,
                        "email" to (currentUser.email ?: ""),
                        "updatedAt" to Timestamp.now()
                    ), com.google.firebase.firestore.SetOptions.merge())
                    .await()
            }
            
            Result.success(Unit)
        } catch (e: Exception) {
            Result.failure(e)
        }
    }
    
    /**
     * Set user role to instructor (for testing/admin purposes)
     * تعيين دور المستخدم كمعلم (لأغراض الاختبار/الإدارة)
     */
    suspend fun setUserAsInstructor(userId: String): Result<Unit> {
        return try {
            val userRole = UserRole(
                userId = userId,
                role = "instructor",
                createdAt = Timestamp.now()
            )
            
            firestore.collection("userRoles")
                .document(userId)
                .set(userRole)
                .await()
            
            Result.success(Unit)
        } catch (e: Exception) {
            Result.failure(e)
        }
    }
    
    /**
     * Check if collections exist (they will be created automatically on first write)
     * التحقق من وجود Collections (سيتم إنشاؤها تلقائياً عند أول كتابة)
     */
    suspend fun verifyCollectionsExist(): Result<Map<String, Boolean>> {
        return try {
            // Try to read from collections (they will be created if they don't exist)
            // Collections are created automatically on first write, so we just verify access
            val userRolesExists = try {
                firestore.collection("userRoles").limit(1).get().await()
                true
            } catch (e: Exception) {
                false
            }
            
            val coursesExists = try {
                firestore.collection("courses").limit(1).get().await()
                true
            } catch (e: Exception) {
                false
            }
            
            Result.success(
                mapOf(
                    "userRoles" to userRolesExists,
                    "courses" to coursesExists
                )
            )
        } catch (e: Exception) {
            Result.failure(e)
        }
    }
}

