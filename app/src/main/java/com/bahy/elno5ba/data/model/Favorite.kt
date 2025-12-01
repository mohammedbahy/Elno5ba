package com.bahy.elno5ba.data.model

import com.google.firebase.Timestamp
import com.google.firebase.firestore.DocumentId

data class Favorite(
    @DocumentId
    val id: String = "",
    val userId: String = "",
    val courseId: String = "",
    val createdAt: Timestamp? = null
)

