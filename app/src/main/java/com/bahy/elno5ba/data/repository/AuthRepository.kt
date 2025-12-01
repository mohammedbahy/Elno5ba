package com.bahy.elno5ba.data.repository

import com.google.android.gms.auth.api.identity.SignInCredential
import com.google.firebase.auth.FirebaseAuth
import com.google.firebase.auth.FirebaseUser
import com.google.firebase.auth.GoogleAuthProvider
import com.google.firebase.auth.UserProfileChangeRequest
import kotlinx.coroutines.tasks.await

class AuthRepository(
    private val firebaseAuth: FirebaseAuth
) {
    val currentUser: FirebaseUser?
        get() = firebaseAuth.currentUser

    val isUserLoggedIn: Boolean
        get() = currentUser != null

    suspend fun signInWithEmailAndPassword(email: String, password: String): Result<FirebaseUser> {
        return try {
            val result = firebaseAuth.signInWithEmailAndPassword(email, password).await()
            Result.success(result.user!!)
        } catch (e: Exception) {
            Result.failure(e)
        }
    }

    suspend fun createUserWithEmailAndPassword(
        email: String,
        password: String,
        fullName: String
    ): Result<FirebaseUser> {
        return try {
            val result = firebaseAuth.createUserWithEmailAndPassword(email, password).await()
            result.user?.let { user ->
                // Update user profile with display name
                val profileUpdates = UserProfileChangeRequest.Builder()
                    .setDisplayName(fullName)
                    .build()
                user.updateProfile(profileUpdates).await()
                Result.success(user)
            } ?: Result.failure(Exception("User creation failed"))
        } catch (e: Exception) {
            Result.failure(e)
        }
    }

    suspend fun signOut() {
        firebaseAuth.signOut()
    }

    suspend fun sendPasswordResetEmail(email: String): Result<Unit> {
        return try {
            firebaseAuth.sendPasswordResetEmail(email).await()
            Result.success(Unit)
        } catch (e: Exception) {
            Result.failure(e)
        }
    }

    suspend fun signInWithGoogle(credential: SignInCredential): Result<FirebaseUser> {
        return try {
            val googleIdToken = credential.googleIdToken
            val firebaseCredential = GoogleAuthProvider.getCredential(googleIdToken, null)
            val result = firebaseAuth.signInWithCredential(firebaseCredential).await()
            result.user?.let { user ->
                // Update user profile with display name if available
                if (user.displayName == null && credential.displayName != null) {
                    val profileUpdates = UserProfileChangeRequest.Builder()
                        .setDisplayName(credential.displayName)
                        .build()
                    user.updateProfile(profileUpdates).await()
                }
                Result.success(user)
            } ?: Result.failure(Exception("Google sign-in failed"))
        } catch (e: Exception) {
            Result.failure(e)
        }
    }
}

