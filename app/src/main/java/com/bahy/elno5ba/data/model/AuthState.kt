package com.bahy.elno5ba.data.model

sealed class AuthState {
    data object Idle : AuthState()
    data object Loading : AuthState()
    data class Success(val message: String? = null) : AuthState()
    data class Error(val message: String) : AuthState()
}

