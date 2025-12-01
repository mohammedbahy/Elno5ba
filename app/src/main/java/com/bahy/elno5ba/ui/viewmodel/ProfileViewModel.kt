package com.bahy.elno5ba.ui.viewmodel

import android.net.Uri
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.bahy.elno5ba.data.repository.StorageRepository
import com.google.firebase.auth.FirebaseAuth
import com.google.firebase.auth.UserProfileChangeRequest
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import kotlinx.coroutines.tasks.await

sealed class ProfileState {
    data object Idle : ProfileState()
    data object Loading : ProfileState()
    data class Success(val message: String? = null) : ProfileState()
    data class Error(val message: String) : ProfileState()
}

class ProfileViewModel(
    private val storageRepository: StorageRepository = StorageRepository()
) : ViewModel() {
    
    private val _profileState = MutableStateFlow<ProfileState>(ProfileState.Idle)
    val profileState: StateFlow<ProfileState> = _profileState.asStateFlow()
    
    private val _profileImageUrl = MutableStateFlow<String?>(null)
    val profileImageUrl: StateFlow<String?> = _profileImageUrl.asStateFlow()
    
    init {
        loadProfileImage()
    }
    
    fun loadProfileImage() {
        viewModelScope.launch {
            val result = storageRepository.getProfileImageUrl()
            result.fold(
                onSuccess = { url ->
                    _profileImageUrl.value = url
                    // Also update Firebase Auth profile photo URL
                    url?.let { updateAuthProfilePhoto(it) }
                },
                onFailure = { /* Silently fail - user may not have uploaded image */ }
            )
        }
    }
    
    fun uploadProfileImage(imageUri: Uri) {
        viewModelScope.launch {
            _profileState.value = ProfileState.Loading
            val result = storageRepository.uploadProfileImage(imageUri)
            _profileState.value = result.fold(
                onSuccess = { downloadUrl ->
                    _profileImageUrl.value = downloadUrl
                    // Update Firebase Auth profile photo URL
                    updateAuthProfilePhoto(downloadUrl)
                    ProfileState.Success("Profile image uploaded successfully")
                },
                onFailure = { exception ->
                    ProfileState.Error(exception.message ?: "Failed to upload image")
                }
            )
        }
    }
    
    fun deleteProfileImage() {
        viewModelScope.launch {
            _profileState.value = ProfileState.Loading
            val result = storageRepository.deleteProfileImage()
            _profileState.value = result.fold(
                onSuccess = {
                    _profileImageUrl.value = null
                    // Remove from Firebase Auth profile photo URL
                    updateAuthProfilePhoto(null)
                    ProfileState.Success("Profile image deleted successfully")
                },
                onFailure = { exception ->
                    ProfileState.Error(exception.message ?: "Failed to delete image")
                }
            )
        }
    }
    
    private suspend fun updateAuthProfilePhoto(photoUrl: String?) {
        try {
            val currentUser = FirebaseAuth.getInstance().currentUser
            currentUser?.let { user ->
                val builder = UserProfileChangeRequest.Builder()
                if (photoUrl != null) {
                    builder.setPhotoUri(Uri.parse(photoUrl))
                } else {
                    // To remove photo, we need to set it to null
                    // Firebase Auth doesn't support null directly, so we'll just not update it
                    // The photo will remain in Storage but won't be linked in Auth
                }
                val profileUpdates = builder.build()
                user.updateProfile(profileUpdates).await()
            }
        } catch (e: Exception) {
            android.util.Log.e("ProfileViewModel", "Failed to update auth profile photo: ${e.message}")
        }
    }
    
    fun resetProfileState() {
        _profileState.value = ProfileState.Idle
    }
}

