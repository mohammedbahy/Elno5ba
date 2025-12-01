package com.bahy.elno5ba.data.repository

import com.bahy.elno5ba.data.model.Favorite
import com.bahy.elno5ba.data.model.Course
import com.google.firebase.Timestamp
import com.google.firebase.firestore.FirebaseFirestore
import kotlinx.coroutines.tasks.await

class FavoriteRepository(
    private val firestore: FirebaseFirestore = FirebaseFirestore.getInstance()
) {
    
    // Add course to favorites
    suspend fun addFavorite(userId: String, courseId: String): Result<String> {
        return try {
            // Check if already favorited
            val existing = firestore.collection("favorites")
                .whereEqualTo("userId", userId)
                .whereEqualTo("courseId", courseId)
                .limit(1)
                .get()
                .await()
            
            if (!existing.isEmpty) {
                return Result.failure(Exception("Course already in favorites"))
            }
            
            val favorite = Favorite(
                userId = userId,
                courseId = courseId,
                createdAt = Timestamp.now()
            )
            
            val documentRef = firestore.collection("favorites")
                .add(favorite)
                .await()
            
            Result.success(documentRef.id)
        } catch (e: Exception) {
            Result.failure(e)
        }
    }
    
    // Remove course from favorites
    suspend fun removeFavorite(userId: String, courseId: String): Result<Unit> {
        return try {
            val snapshot = firestore.collection("favorites")
                .whereEqualTo("userId", userId)
                .whereEqualTo("courseId", courseId)
                .limit(1)
                .get()
                .await()
            
            if (snapshot.isEmpty) {
                return Result.failure(Exception("Favorite not found"))
            }
            
            val favoriteId = snapshot.documents.first().id
            firestore.collection("favorites")
                .document(favoriteId)
                .delete()
                .await()
            
            Result.success(Unit)
        } catch (e: Exception) {
            Result.failure(e)
        }
    }
    
    // Check if course is favorited
    suspend fun isFavorited(userId: String, courseId: String): Boolean {
        return try {
            val snapshot = firestore.collection("favorites")
                .whereEqualTo("userId", userId)
                .whereEqualTo("courseId", courseId)
                .limit(1)
                .get()
                .await()
            !snapshot.isEmpty
        } catch (e: Exception) {
            false
        }
    }
    
    // Get user's favorite courses
    suspend fun getFavoriteCourses(userId: String): Result<List<Course>> {
        return try {
            // Get user's favorites
            val favoritesSnapshot = firestore.collection("favorites")
                .whereEqualTo("userId", userId)
                .get()
                .await()
            
            if (favoritesSnapshot.isEmpty) {
                return Result.success(emptyList())
            }
            
            val courseIds = favoritesSnapshot.documents.mapNotNull { it.getString("courseId") }
            
            if (courseIds.isEmpty()) {
                return Result.success(emptyList())
            }
            
            // Get courses data
            val courses = mutableListOf<Course>()
            for (courseId in courseIds) {
                try {
                    val courseDoc = firestore.collection("courses")
                        .document(courseId)
                        .get()
                        .await()
                    
                    if (courseDoc.exists()) {
                        val course = courseDoc.toObject(Course::class.java)?.copy(id = courseDoc.id)
                        if (course != null) {
                            courses.add(course)
                        }
                    }
                } catch (e: Exception) {
                    android.util.Log.e("FavoriteRepository", "Error loading course $courseId: ${e.message}")
                }
            }
            
            Result.success(courses)
        } catch (e: Exception) {
            Result.failure(e)
        }
    }
}

