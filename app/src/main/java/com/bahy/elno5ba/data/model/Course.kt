package com.bahy.elno5ba.data.model

import com.google.firebase.Timestamp
import com.google.firebase.firestore.DocumentId
import com.google.firebase.firestore.PropertyName

data class VideoItem(
    val title: String = "",
    val url: String = ""
)

data class Course(
    @DocumentId
    val id: String = "",
    val title: String = "",
    val category: String = "",
    val price: Double = 0.0,
    val description: String = "",
    val coverImageUrl: String = "",
    val introVideoUrl: String = "",
    val instructorId: String = "",
    val instructorName: String = "",
    val rating: Double = 0.0,
    val totalRatings: Int = 0,
    val enrolledStudents: Int = 0,
    val videos: List<String> = emptyList(), // Legacy list of video URLs from instructor portal
    val videoItems: List<VideoItem> = emptyList(), // New: videos with titles
    val enrollmentCodes: List<String> = emptyList(), // List of enrollment codes
    val createdAt: Timestamp? = null,
    val updatedAt: Timestamp? = null,
    val isPublished: Boolean = false
)

