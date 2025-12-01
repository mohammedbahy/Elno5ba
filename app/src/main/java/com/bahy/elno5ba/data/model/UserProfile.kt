package com.bahy.elno5ba.data.model

import com.google.firebase.Timestamp

/**
 * User Profile data model
 * نموذج بيانات الملف الشخصي للمستخدم
 */
data class UserProfile(
    val userId: String = "",
    val fullName: String = "",
    val nickName: String = "",
    val email: String = "",
    val phoneNumber: String = "",
    val dateOfBirth: String = "", // Format: "dd/MM/yyyy"
    val gender: String = "", // "Male" or "Female"
    val photoUrl: String? = null,
    val createdAt: Timestamp? = null,
    val updatedAt: Timestamp? = null
) {
    /**
     * Convert to Firestore map
     */
    fun toMap(): Map<String, Any?> {
        return mapOf(
            "userId" to userId,
            "fullName" to fullName,
            "nickName" to nickName,
            "email" to email,
            "phoneNumber" to phoneNumber,
            "dateOfBirth" to dateOfBirth,
            "gender" to gender,
            "photoUrl" to photoUrl,
            "createdAt" to (createdAt ?: Timestamp.now()),
            "updatedAt" to Timestamp.now()
        )
    }

    companion object {
        /**
         * Create from Firestore document
         */
        fun fromMap(map: Map<String, Any?>): UserProfile {
            return UserProfile(
                userId = map["userId"] as? String ?: "",
                fullName = map["fullName"] as? String ?: "",
                nickName = map["nickName"] as? String ?: "",
                email = map["email"] as? String ?: "",
                phoneNumber = map["phoneNumber"] as? String ?: "",
                dateOfBirth = map["dateOfBirth"] as? String ?: "",
                gender = map["gender"] as? String ?: "",
                photoUrl = map["photoUrl"] as? String?,
                createdAt = map["createdAt"] as? Timestamp,
                updatedAt = map["updatedAt"] as? Timestamp
            )
        }
    }
}


