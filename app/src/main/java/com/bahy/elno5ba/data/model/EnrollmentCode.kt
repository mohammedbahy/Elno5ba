package com.bahy.elno5ba.data.model

import com.google.firebase.firestore.DocumentId

data class EnrollmentCode(
    @DocumentId
    val id: String = "",
    val code: String = "",
    val courseId: String = "",
    val isUsed: Boolean = false,
    val usedBy: String? = null, // Student ID who used it
    val usedAt: com.google.firebase.Timestamp? = null,
    val createdAt: com.google.firebase.Timestamp? = null
)

