package com.bahy.elno5ba.ui.viewmodel

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.bahy.elno5ba.data.model.Course
import com.bahy.elno5ba.data.repository.FavoriteRepository
import com.google.firebase.auth.FirebaseAuth
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch

sealed class FavoriteState {
    data object Idle : FavoriteState()
    data object Loading : FavoriteState()
    data class Success(val message: String? = null) : FavoriteState()
    data class Error(val message: String) : FavoriteState()
}

class FavoriteViewModel(
    private val favoriteRepository: FavoriteRepository = FavoriteRepository()
) : ViewModel() {
    
    private val _favoriteState = MutableStateFlow<FavoriteState>(FavoriteState.Idle)
    val favoriteState: StateFlow<FavoriteState> = _favoriteState.asStateFlow()
    
    private val _favoriteCourses = MutableStateFlow<List<Course>>(emptyList())
    val favoriteCourses: StateFlow<List<Course>> = _favoriteCourses.asStateFlow()
    
    fun loadFavoriteCourses() {
        viewModelScope.launch {
            _favoriteState.value = FavoriteState.Loading
            val currentUser = FirebaseAuth.getInstance().currentUser
            if (currentUser == null) {
                _favoriteState.value = FavoriteState.Error("User not authenticated")
                return@launch
            }
            
            val result = favoriteRepository.getFavoriteCourses(currentUser.uid)
            _favoriteState.value = result.fold(
                onSuccess = { courses ->
                    android.util.Log.d("FavoriteViewModel", "Favorite courses loaded: ${courses.size}")
                    _favoriteCourses.value = courses
                    FavoriteState.Success()
                },
                onFailure = { exception ->
                    android.util.Log.e("FavoriteViewModel", "Failed to load favorites: ${exception.message}", exception)
                    FavoriteState.Error(exception.message ?: "Failed to load favorite courses")
                }
            )
        }
    }
    
    fun addFavorite(courseId: String) {
        viewModelScope.launch {
            val currentUser = FirebaseAuth.getInstance().currentUser
            if (currentUser == null) {
                _favoriteState.value = FavoriteState.Error("User not authenticated")
                return@launch
            }
            
            val result = favoriteRepository.addFavorite(currentUser.uid, courseId)
            _favoriteState.value = result.fold(
                onSuccess = {
                    loadFavoriteCourses() // Reload favorites
                    FavoriteState.Success("Course added to favorites")
                },
                onFailure = { exception ->
                    FavoriteState.Error(exception.message ?: "Failed to add to favorites")
                }
            )
        }
    }
    
    fun removeFavorite(courseId: String) {
        viewModelScope.launch {
            val currentUser = FirebaseAuth.getInstance().currentUser
            if (currentUser == null) {
                _favoriteState.value = FavoriteState.Error("User not authenticated")
                return@launch
            }
            
            val result = favoriteRepository.removeFavorite(currentUser.uid, courseId)
            _favoriteState.value = result.fold(
                onSuccess = {
                    loadFavoriteCourses() // Reload favorites
                    FavoriteState.Success("Course removed from favorites")
                },
                onFailure = { exception ->
                    FavoriteState.Error(exception.message ?: "Failed to remove from favorites")
                }
            )
        }
    }
    
    fun isFavorited(courseId: String, onResult: (Boolean) -> Unit) {
        viewModelScope.launch {
            val currentUser = FirebaseAuth.getInstance().currentUser
            if (currentUser == null) {
                onResult(false)
                return@launch
            }
            val isFav = favoriteRepository.isFavorited(currentUser.uid, courseId)
            onResult(isFav)
        }
    }
    
    fun resetFavoriteState() {
        _favoriteState.value = FavoriteState.Idle
    }
}

