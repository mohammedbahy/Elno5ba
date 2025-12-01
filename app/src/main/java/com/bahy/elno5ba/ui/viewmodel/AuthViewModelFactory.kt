package com.bahy.elno5ba.ui.viewmodel

import androidx.lifecycle.ViewModel
import androidx.lifecycle.ViewModelProvider
import com.bahy.elno5ba.data.repository.AuthRepository
import com.google.firebase.auth.FirebaseAuth

class AuthViewModelFactory(
    private val context: android.content.Context
) : ViewModelProvider.Factory {
    override fun <T : ViewModel> create(modelClass: Class<T>): T {
        if (modelClass.isAssignableFrom(AuthViewModel::class.java)) {
            val authRepository = AuthRepository(FirebaseAuth.getInstance())
            @Suppress("UNCHECKED_CAST")
            return AuthViewModel(authRepository) as T
        }
        throw IllegalArgumentException("Unknown ViewModel class")
    }
}

