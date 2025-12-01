package com.bahy.elno5ba.data.model

import com.google.firebase.Timestamp
import com.google.firebase.firestore.DocumentId

data class Review(
    @DocumentId
    val id: String = "",
    val courseId: String = "",
    val studentId: String = "",
    val studentName: String = "",
    val rating: Double = 0.0, // 1.0 to 5.0
    val comment: String = "",
    val createdAt: Timestamp? = null
)

