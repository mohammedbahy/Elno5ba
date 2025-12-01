package com.bahy.elno5ba.data.repository

import com.bahy.elno5ba.data.model.Review
import com.google.firebase.Timestamp
import com.google.firebase.firestore.FirebaseFirestore
import com.google.firebase.firestore.Query
import kotlinx.coroutines.tasks.await

class ReviewRepository(
    private val firestore: FirebaseFirestore = FirebaseFirestore.getInstance()
) {
    
    // Add review
    suspend fun addReview(review: Review): Result<String> {
        return try {
            // Check if student already reviewed this course
            val existing = firestore.collection("reviews")
                .whereEqualTo("courseId", review.courseId)
                .whereEqualTo("studentId", review.studentId)
                .limit(1)
                .get()
                .await()
            
            if (!existing.isEmpty) {
                // Update existing review
                val existingId = existing.documents.first().id
                val updatedReview = review.copy(
                    id = existingId,
                    createdAt = existing.documents.first().getTimestamp("createdAt")?.let { 
                        Timestamp(it.seconds, it.nanoseconds) 
                    } ?: Timestamp.now()
                )
                firestore.collection("reviews")
                    .document(existingId)
                    .set(updatedReview)
                    .await()
                updateCourseRating(review.courseId)
                return Result.success(existingId)
            }
            
            val reviewWithTimestamp = review.copy(
                createdAt = Timestamp.now()
            )
            val documentRef = firestore.collection("reviews")
                .add(reviewWithTimestamp)
                .await()
            
            updateCourseRating(review.courseId)
            Result.success(documentRef.id)
        } catch (e: Exception) {
            Result.failure(e)
        }
    }
    
    // Get reviews for a course
    suspend fun getCourseReviews(courseId: String): Result<List<Review>> {
        return try {
            val snapshot = firestore.collection("reviews")
                .whereEqualTo("courseId", courseId)
                .orderBy("createdAt", Query.Direction.DESCENDING)
                .get()
                .await()
            
            val reviews = snapshot.documents.mapNotNull { doc ->
                doc.toObject(Review::class.java)?.copy(id = doc.id)
            }
            Result.success(reviews)
        } catch (e: Exception) {
            Result.failure(e)
        }
    }
    
    // Update course rating based on reviews
    private suspend fun updateCourseRating(courseId: String) {
        try {
            val reviews = getCourseReviews(courseId).getOrNull() ?: return
            
            if (reviews.isEmpty()) return
            
            val averageRating = reviews.map { it.rating }.average()
            val totalRatings = reviews.size
            
            firestore.collection("courses")
                .document(courseId)
                .update(
                    mapOf(
                        "rating" to averageRating,
                        "totalRatings" to totalRatings
                    )
                )
                .await()
        } catch (e: Exception) {
            // Silently fail - rating update is not critical
        }
    }
    
    // Get student's review for a course
    suspend fun getStudentReview(courseId: String, studentId: String): Result<Review?> {
        return try {
            val snapshot = firestore.collection("reviews")
                .whereEqualTo("courseId", courseId)
                .whereEqualTo("studentId", studentId)
                .limit(1)
                .get()
                .await()
            
            if (snapshot.isEmpty) {
                Result.success(null)
            } else {
                val review = snapshot.documents.first().toObject(Review::class.java)
                    ?.copy(id = snapshot.documents.first().id)
                Result.success(review)
            }
        } catch (e: Exception) {
            Result.failure(e)
        }
    }
}

