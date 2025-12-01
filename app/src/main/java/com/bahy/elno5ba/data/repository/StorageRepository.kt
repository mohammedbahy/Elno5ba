package com.bahy.elno5ba.data.repository

import android.net.Uri
import com.google.firebase.auth.FirebaseAuth
import com.google.firebase.storage.FirebaseStorage
import kotlinx.coroutines.tasks.await

class StorageRepository(
    private val storage: FirebaseStorage = FirebaseStorage.getInstance()
) {
    
    // Upload profile image
    suspend fun uploadProfileImage(imageUri: Uri): Result<String> {
        return try {
            val currentUser = FirebaseAuth.getInstance().currentUser
            if (currentUser == null) {
                return Result.failure(Exception("User not authenticated"))
            }
            
            // Create reference: profile_images/{userId}.jpg
            val imageRef = storage.reference
                .child("profile_images")
                .child("${currentUser.uid}.jpg")
            
            // Upload file
            val uploadTask = imageRef.putFile(imageUri)
            uploadTask.await()
            
            // Get download URL
            val downloadUrl = imageRef.downloadUrl.await()
            
            Result.success(downloadUrl.toString())
        } catch (e: Exception) {
            Result.failure(e)
        }
    }
    
    // Delete profile image
    suspend fun deleteProfileImage(): Result<Unit> {
        return try {
            val currentUser = FirebaseAuth.getInstance().currentUser
            if (currentUser == null) {
                return Result.failure(Exception("User not authenticated"))
            }
            
            val imageRef = storage.reference
                .child("profile_images")
                .child("${currentUser.uid}.jpg")
            
            imageRef.delete().await()
            Result.success(Unit)
        } catch (e: Exception) {
            Result.failure(e)
        }
    }
    
    // Get profile image URL
    suspend fun getProfileImageUrl(): Result<String?> {
        return try {
            val currentUser = FirebaseAuth.getInstance().currentUser
            if (currentUser == null) {
                return Result.failure(Exception("User not authenticated"))
            }
            
            val imageRef = storage.reference
                .child("profile_images")
                .child("${currentUser.uid}.jpg")
            
            // Try to get download URL
            try {
                val downloadUrl = imageRef.downloadUrl.await()
                Result.success(downloadUrl.toString())
            } catch (e: Exception) {
                // Image doesn't exist
                Result.success(null)
            }
        } catch (e: Exception) {
            Result.failure(e)
        }
    }
}

