package com.bahy.elno5ba.data.repository

import com.bahy.elno5ba.data.model.Enrollment
import com.google.firebase.Timestamp
import com.google.firebase.firestore.FirebaseFirestore
import kotlinx.coroutines.tasks.await

class EnrollmentRepository(
    private val firestore: FirebaseFirestore = FirebaseFirestore.getInstance()
) {

    // Enroll in a course using enrollment code
    suspend fun enrollInCourseWithCode(courseId: String, studentId: String, code: String): Result<String> {
        return try {
            // Check if already enrolled
            val existing = firestore.collection("enrollments")
                .whereEqualTo("courseId", courseId)
                .whereEqualTo("studentId", studentId)
                .limit(1)
                .get()
                .await()

            if (!existing.isEmpty) {
                return Result.failure(Exception("Already enrolled in this course"))
            }

            // Validate code
            val courseRepository = CourseRepository()
            val codeValidation = courseRepository.validateEnrollmentCode(code, courseId)

            codeValidation.fold(
                onSuccess = { enrollmentCode ->
                    if (enrollmentCode == null) {
                        return Result.failure(Exception("Invalid enrollment code"))
                    }

                    // Create enrollment
                    val enrollment = Enrollment(
                        courseId = courseId,
                        studentId = studentId,
                        enrolledAt = Timestamp.now(),
                        progress = 0.0,
                        completed = false
                    )

                    val documentRef = firestore.collection("enrollments")
                        .add(enrollment)
                        .await()

                    // Mark code as used
                    courseRepository.markCodeAsUsed(enrollmentCode.id, studentId)

                    // Update course enrolledStudents count
                    val courseRef = firestore.collection("courses").document(courseId)
                    val courseDoc = courseRef.get().await()
                    if (courseDoc.exists()) {
                        val currentCount = courseDoc.getLong("enrolledStudents")?.toInt() ?: 0
                        courseRef.update("enrolledStudents", currentCount + 1).await()
                    }

                    Result.success(documentRef.id)
                },
                onFailure = { error ->
                    Result.failure(error)
                }
            )
        } catch (e: Exception) {
            Result.failure(e)
        }
    }

    // Enroll in a course (purchase) - kept for backward compatibility
    suspend fun enrollInCourse(courseId: String, studentId: String): Result<String> {
        return try {
            // Check if already enrolled
            val existing = firestore.collection("enrollments")
                .whereEqualTo("courseId", courseId)
                .whereEqualTo("studentId", studentId)
                .limit(1)
                .get()
                .await()

            if (!existing.isEmpty) {
                return Result.failure(Exception("Already enrolled in this course"))
            }

            val enrollment = Enrollment(
                courseId = courseId,
                studentId = studentId,
                enrolledAt = Timestamp.now(),
                progress = 0.0,
                completed = false
            )

            val documentRef = firestore.collection("enrollments")
                .add(enrollment)
                .await()

            // Update course enrolledStudents count
            val courseRef = firestore.collection("courses").document(courseId)
            val courseDoc = courseRef.get().await()
            if (courseDoc.exists()) {
                val currentCount = courseDoc.getLong("enrolledStudents")?.toInt() ?: 0
                courseRef.update("enrolledStudents", currentCount + 1).await()
            }

            Result.success(documentRef.id)
        } catch (e: Exception) {
            Result.failure(e)
        }
    }

    // Check if student is enrolled
    suspend fun isEnrolled(courseId: String, studentId: String): Boolean {
        return try {
            val snapshot = firestore.collection("enrollments")
                .whereEqualTo("courseId", courseId)
                .whereEqualTo("studentId", studentId)
                .limit(1)
                .get()
                .await()
            !snapshot.isEmpty
        } catch (e: Exception) {
            false
        }
    }

    // Get student's enrollments
    suspend fun getStudentEnrollments(studentId: String): Result<List<Enrollment>> {
        return try {
            val snapshot = firestore.collection("enrollments")
                .whereEqualTo("studentId", studentId)
                .get()
                .await()

            val enrollments = snapshot.documents.mapNotNull { doc ->
                doc.toObject(Enrollment::class.java)?.copy(id = doc.id)
            }
            Result.success(enrollments)
        } catch (e: Exception) {
            Result.failure(e)
        }
    }

    // Update progress
    suspend fun updateProgress(enrollmentId: String, progress: Double): Result<Unit> {
        return try {
            firestore.collection("enrollments")
                .document(enrollmentId)
                .update("progress", progress.coerceIn(0.0, 1.0))
                .await()
            Result.success(Unit)
        } catch (e: Exception) {
            Result.failure(e)
        }
    }
}


