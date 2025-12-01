package com.bahy.elno5ba.data.model

data class UserRole(
    val userId: String = "",
    val role: String = "student", // "student" or "instructor"
    val createdAt: com.google.firebase.Timestamp? = null
)

