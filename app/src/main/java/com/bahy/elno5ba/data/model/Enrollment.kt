package com.bahy.elno5ba.data.model

import com.google.firebase.Timestamp
import com.google.firebase.firestore.DocumentId

data class Enrollment(
    @DocumentId
    val id: String = "",
    val courseId: String = "",
    val studentId: String = "",
    val enrolledAt: Timestamp? = null,
    val progress: Double = 0.0, // 0.0 to 1.0
    val completed: Boolean = false
)

