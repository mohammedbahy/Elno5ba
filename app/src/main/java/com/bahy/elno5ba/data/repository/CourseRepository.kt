package com.bahy.elno5ba.data.repository

import com.bahy.elno5ba.data.model.Course
import com.bahy.elno5ba.data.model.EnrollmentCode
import com.bahy.elno5ba.data.model.UserRole
import com.google.firebase.Timestamp
import com.google.firebase.firestore.FirebaseFirestore
import com.google.firebase.firestore.Query
import kotlinx.coroutines.tasks.await
import java.util.UUID

class CourseRepository(
    private val firestore: FirebaseFirestore = FirebaseFirestore.getInstance()
) {
    
    // Get user role
    suspend fun getUserRole(userId: String): UserRole? {
        return try {
            val document = firestore.collection("userRoles")
                .document(userId)
                .get()
                .await()
            
            if (document.exists()) {
                document.toObject(UserRole::class.java)
            } else {
                null
            }
        } catch (e: Exception) {
            null
        }
    }
    
    // Set user role (only for first time setup)
    suspend fun setUserRole(userId: String, role: String): Result<Unit> {
        return try {
            val userRole = UserRole(
                userId = userId,
                role = role,
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
    
    // Create course (only for instructors)
    suspend fun createCourse(course: Course): Result<String> {
        return try {
            val courseWithTimestamp = course.copy(
                createdAt = Timestamp.now(),
                updatedAt = Timestamp.now()
            )
            val documentRef = firestore.collection("courses")
                .add(courseWithTimestamp)
                .await()
            Result.success(documentRef.id)
        } catch (e: Exception) {
            Result.failure(e)
        }
    }
    
    // Update course (only for instructors who own the course)
    suspend fun updateCourse(courseId: String, course: Course): Result<Unit> {
        return try {
            val courseWithTimestamp = course.copy(
                updatedAt = Timestamp.now()
            )
            firestore.collection("courses")
                .document(courseId)
                .set(courseWithTimestamp, com.google.firebase.firestore.SetOptions.merge())
                .await()
            Result.success(Unit)
        } catch (e: Exception) {
            Result.failure(e)
        }
    }
    
    // Get all courses (for students and instructors)
    suspend fun getAllCourses(): Result<List<Course>> {
        return try {
            // Check authentication first
            val currentUser = com.google.firebase.auth.FirebaseAuth.getInstance().currentUser
            if (currentUser == null) {
                android.util.Log.e("CourseRepository", "User not authenticated")
                return Result.failure(Exception("User not authenticated. Please log in first."))
            }
            
            android.util.Log.d("CourseRepository", "Loading courses for user: ${currentUser.uid}")
            
            // Get all courses first (simpler query, no index needed)
            val snapshot = firestore.collection("courses")
                .get()
                .await()
            
            android.util.Log.d("CourseRepository", "Total documents fetched: ${snapshot.documents.size}")
            
            val allCourses = snapshot.documents.mapNotNull { doc ->
                try {
                    android.util.Log.d("CourseRepository", "Processing course document: ${doc.id}")
                    android.util.Log.d("CourseRepository", "Document data: ${doc.data}")
                    
                    // Try to get isPublished flag directly
                    val isPublishedFlag = doc.getBoolean("isPublished")
                    android.util.Log.d("CourseRepository", "isPublished flag: $isPublishedFlag")
                    
                    // Convert document to Course object
                    val course = doc.toObject(Course::class.java)
                    if (course == null) {
                        android.util.Log.e("CourseRepository", "Failed to convert document ${doc.id} to Course object")
                        android.util.Log.e("CourseRepository", "Document fields: ${doc.data?.keys?.joinToString()}")
                        return@mapNotNull null
                    }
                    
                    // Validate required fields
                    if (course.title.isEmpty()) {
                        android.util.Log.w("CourseRepository", "Course ${doc.id} has empty title, skipping")
                        return@mapNotNull null
                    }
                    
                    // Use isPublished from document if available, otherwise default to true (for backward compatibility)
                    // If field doesn't exist, treat as published
                    val published = when {
                        isPublishedFlag != null -> isPublishedFlag
                        course.isPublished -> true
                        else -> true // Default to true if not specified (backward compatibility)
                    }
                    
                    // Get timestamps
                    val createdAt = doc.getTimestamp("createdAt") ?: course.createdAt
                    val updatedAt = doc.getTimestamp("updatedAt") ?: course.updatedAt
                    
                    val finalCourse = course.copy(
                        id = doc.id,
                        isPublished = published,
                        createdAt = createdAt,
                        updatedAt = updatedAt
                    )
                    
                    android.util.Log.d("CourseRepository", "Course parsed: ${finalCourse.title}, isPublished: ${finalCourse.isPublished}, id: ${finalCourse.id}")
                    finalCourse
                } catch (e: Exception) {
                    android.util.Log.e("CourseRepository", "Error parsing course ${doc.id}: ${e.message}", e)
                    null
                }
            }
            
            android.util.Log.d("CourseRepository", "Total courses parsed: ${allCourses.size}")
            
            // Filter published courses
            // Show all courses (isPublished will be true by default if not set)
            // Only filter out courses explicitly marked as unpublished (isPublished = false)
            val publishedCourses = allCourses.filter { course ->
                val shouldShow = course.isPublished != false
                android.util.Log.d("CourseRepository", "Course '${course.title}' (id: ${course.id}): isPublished=${course.isPublished}, willShow=$shouldShow")
                shouldShow
            }
            
            android.util.Log.d("CourseRepository", "Published courses count: ${publishedCourses.size}")
            
            // Sort by creation date
            val sortedCourses = publishedCourses.sortedByDescending { course ->
                course.createdAt?.seconds ?: 0L
            }
            
            android.util.Log.d("CourseRepository", "Final courses count: ${sortedCourses.size}")
            
            android.util.Log.d("CourseRepository", "Successfully returning ${sortedCourses.size} courses")
            Result.success(sortedCourses)
        } catch (e: com.google.firebase.firestore.FirebaseFirestoreException) {
            // Log Firestore-specific errors
            android.util.Log.e("CourseRepository", "Firestore error loading courses: ${e.message}", e)
            android.util.Log.e("CourseRepository", "Error code: ${e.code}, message: ${e.message}")
            Result.failure(e)
        } catch (e: Exception) {
            // Log error for debugging
            android.util.Log.e("CourseRepository", "Error loading courses: ${e.message}", e)
            android.util.Log.e("CourseRepository", "Error type: ${e.javaClass.simpleName}")
            e.printStackTrace()
            Result.failure(e)
        }
    }
    
    // Get courses by instructor
    suspend fun getCoursesByInstructor(instructorId: String): Result<List<Course>> {
        return try {
            val snapshot = firestore.collection("courses")
                .whereEqualTo("instructorId", instructorId)
                .orderBy("createdAt", Query.Direction.DESCENDING)
                .get()
                .await()
            
            val courses = snapshot.documents.mapNotNull { doc ->
                doc.toObject(Course::class.java)?.copy(id = doc.id)
            }
            Result.success(courses)
        } catch (e: Exception) {
            Result.failure(e)
        }
    }
    
    // Get course by ID
    suspend fun getCourseById(courseId: String): Result<Course?> {
        return try {
            val document = firestore.collection("courses")
                .document(courseId)
                .get()
                .await()
            
            if (document.exists()) {
                val course = document.toObject(Course::class.java)?.copy(id = document.id)
                Result.success(course)
            } else {
                Result.success(null)
            }
        } catch (e: Exception) {
            Result.failure(e)
        }
    }
    
    // Delete course (only for instructors who own the course)
    suspend fun deleteCourse(courseId: String): Result<Unit> {
        return try {
            firestore.collection("courses")
                .document(courseId)
                .delete()
                .await()
            Result.success(Unit)
        } catch (e: Exception) {
            Result.failure(e)
        }
    }
    
    // Generate enrollment codes for a course
    suspend fun generateEnrollmentCodes(courseId: String, count: Int): Result<List<String>> {
        return try {
            val codes = mutableListOf<String>()
            val enrollmentCodes = mutableListOf<EnrollmentCode>()
            
            repeat(count) {
                val code = generateRandomCode()
                codes.add(code)
                enrollmentCodes.add(
                    EnrollmentCode(
                        code = code,
                        courseId = courseId,
                        isUsed = false,
                        createdAt = Timestamp.now()
                    )
                )
            }
            
            // Save codes to enrollmentCodes collection
            enrollmentCodes.forEach { enrollmentCode ->
                firestore.collection("enrollmentCodes")
                    .add(enrollmentCode)
                    .await()
            }
            
            // Update course with codes list
            val courseRef = firestore.collection("courses").document(courseId)
            val courseDoc = courseRef.get().await()
            if (courseDoc.exists()) {
                val existingCodes = courseDoc.get("enrollmentCodes") as? List<*> ?: emptyList<String>()
                val updatedCodes = (existingCodes + codes) as List<String>
                courseRef.update("enrollmentCodes", updatedCodes).await()
            }
            
            Result.success(codes)
        } catch (e: Exception) {
            Result.failure(e)
        }
    }
    
    // Check if enrollment code is valid and available
    suspend fun validateEnrollmentCode(code: String, courseId: String): Result<EnrollmentCode?> {
        return try {
            val snapshot = firestore.collection("enrollmentCodes")
                .whereEqualTo("code", code)
                .whereEqualTo("courseId", courseId)
                .limit(1)
                .get()
                .await()
            
            if (snapshot.isEmpty) {
                return Result.failure(Exception("Invalid enrollment code"))
            }
            
            val enrollmentCodeDoc = snapshot.documents.first()
            val enrollmentCode = enrollmentCodeDoc.toObject(EnrollmentCode::class.java)
                ?.copy(id = enrollmentCodeDoc.id)
            
            if (enrollmentCode == null) {
                return Result.failure(Exception("Invalid enrollment code"))
            }
            
            if (enrollmentCode.isUsed) {
                return Result.failure(Exception("This code has already been used"))
            }
            
            Result.success(enrollmentCode)
        } catch (e: Exception) {
            Result.failure(e)
        }
    }
    
    // Mark enrollment code as used
    suspend fun markCodeAsUsed(codeId: String, studentId: String): Result<Unit> {
        return try {
            firestore.collection("enrollmentCodes")
                .document(codeId)
                .update(
                    mapOf(
                        "isUsed" to true,
                        "usedBy" to studentId,
                        "usedAt" to Timestamp.now()
                    )
                )
                .await()
            Result.success(Unit)
        } catch (e: Exception) {
            Result.failure(e)
        }
    }
    
    // Generate random code (8 characters, alphanumeric)
    private fun generateRandomCode(): String {
        val chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
        return (1..8)
            .map { chars.random() }
            .joinToString("")
    }
}
