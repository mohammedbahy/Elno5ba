package com.bahy.elno5ba.ui.viewmodel

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.bahy.elno5ba.data.model.AuthState
import com.bahy.elno5ba.data.repository.AuthRepository
import com.bahy.elno5ba.data.repository.FirestoreInitializer
import com.google.android.gms.auth.api.identity.SignInCredential
import com.google.firebase.auth.FirebaseAuth
import com.google.firebase.auth.FirebaseAuthException
import com.google.firebase.auth.FirebaseUser
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch

class AuthViewModel(
    private val authRepository: AuthRepository = AuthRepository(FirebaseAuth.getInstance())
) : ViewModel() {

    private val _authState = MutableStateFlow<AuthState>(AuthState.Idle)
    val authState: StateFlow<AuthState> = _authState.asStateFlow()

    private val _currentUser = MutableStateFlow<FirebaseUser?>(null)
    val currentUser: StateFlow<FirebaseUser?> = _currentUser.asStateFlow()

    init {
        _currentUser.value = authRepository.currentUser
    }

    fun signInWithEmailAndPassword(email: String, password: String) {
        viewModelScope.launch {
            _authState.value = AuthState.Loading
            val result = authRepository.signInWithEmailAndPassword(email, password)
            _authState.value = result.fold(
                onSuccess = { user ->
                    _currentUser.value = user
                    // Initialize user role in Firestore (default: student)
                    launch {
                        FirestoreInitializer.initializeUserRole("student")
                    }
                    AuthState.Success("Login successful")
                },
                onFailure = { exception ->
                    val errorMessage = when (exception) {
                        is FirebaseAuthException -> {
                            when (exception.errorCode) {
                                "ERROR_INVALID_EMAIL",
                                "ERROR_WRONG_PASSWORD",
                                "ERROR_USER_NOT_FOUND",
                                "ERROR_INVALID_CREDENTIAL" -> {
                                    "Email or password isn't correct"
                                }
                                "ERROR_USER_DISABLED" -> {
                                    "This account has been disabled"
                                }
                                "ERROR_TOO_MANY_REQUESTS" -> {
                                    "Too many requests. Please try again later"
                                }
                                else -> exception.message ?: "Login failed"
                            }
                        }
                        else -> exception.message ?: "Login failed"
                    }
                    AuthState.Error(errorMessage)
                }
            )
        }
    }

    fun signUpWithEmailAndPassword(email: String, password: String, fullName: String) {
        viewModelScope.launch {
            _authState.value = AuthState.Loading
            val result = authRepository.createUserWithEmailAndPassword(email, password, fullName)
            _authState.value = result.fold(
                onSuccess = { user ->
                    _currentUser.value = user
                    // Initialize user role in Firestore (default: student)
                    launch {
                        FirestoreInitializer.initializeUserRole("student")
                    }
                    AuthState.Success("Account created successfully")
                },
                onFailure = { AuthState.Error(it.message ?: "Sign up failed") }
            )
        }
    }

    fun sendPasswordResetEmail(email: String) {
        viewModelScope.launch {
            _authState.value = AuthState.Loading
            val result = authRepository.sendPasswordResetEmail(email)
            _authState.value = result.fold(
                onSuccess = { 
                    AuthState.Success("Password reset email sent. Please check your inbox.")
                },
                onFailure = { exception ->
                    val errorMessage = when (exception) {
                        is FirebaseAuthException -> {
                            when (exception.errorCode) {
                                "ERROR_INVALID_EMAIL" -> {
                                    "Invalid email address"
                                }
                                "ERROR_USER_NOT_FOUND" -> {
                                    "No account found with this email address"
                                }
                                else -> exception.message ?: "Failed to send reset email"
                            }
                        }
                        else -> exception.message ?: "Failed to send reset email"
                    }
                    AuthState.Error(errorMessage)
                }
            )
        }
    }

    fun signOut() {
        viewModelScope.launch {
            authRepository.signOut()
            _currentUser.value = null
            _authState.value = AuthState.Idle
        }
    }

    fun signInWithGoogle(credential: SignInCredential) {
        viewModelScope.launch {
            _authState.value = AuthState.Loading
            val result = authRepository.signInWithGoogle(credential)
            _authState.value = result.fold(
                onSuccess = { user ->
                    _currentUser.value = user
                    // Initialize user role in Firestore (default: student)
                    launch {
                        FirestoreInitializer.initializeUserRole("student")
                    }
                    AuthState.Success("Google sign-in successful")
                },
                onFailure = { exception ->
                    val errorMessage = when (exception) {
                        is FirebaseAuthException -> {
                            when (exception.errorCode) {
                                "ERROR_ACCOUNT_EXISTS_WITH_DIFFERENT_CREDENTIAL" -> {
                                    "An account already exists with the same email address"
                                }
                                else -> exception.message ?: "Google sign-in failed"
                            }
                        }
                        else -> exception.message ?: "Google sign-in failed"
                    }
                    AuthState.Error(errorMessage)
                }
            )
        }
    }

    fun resetAuthState() {
        _authState.value = AuthState.Idle
    }
}

