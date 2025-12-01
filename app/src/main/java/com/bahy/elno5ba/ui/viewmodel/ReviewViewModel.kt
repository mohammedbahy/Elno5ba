package com.bahy.elno5ba.ui.viewmodel

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.bahy.elno5ba.data.model.Review
import com.bahy.elno5ba.data.repository.ReviewRepository
import com.google.firebase.auth.FirebaseAuth
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch

sealed class ReviewState {
    data object Idle : ReviewState()
    data object Loading : ReviewState()
    data class Success(val message: String) : ReviewState()
    data class Error(val message: String) : ReviewState()
}

class ReviewViewModel(
    private val reviewRepository: ReviewRepository = ReviewRepository()
) : ViewModel() {
    
    private val _reviewState = MutableStateFlow<ReviewState>(ReviewState.Idle)
    val reviewState: StateFlow<ReviewState> = _reviewState.asStateFlow()
    
    private val _reviews = MutableStateFlow<List<Review>>(emptyList())
    val reviews: StateFlow<List<Review>> = _reviews.asStateFlow()
    
    private val _studentReview = MutableStateFlow<Review?>(null)
    val studentReview: StateFlow<Review?> = _studentReview.asStateFlow()
    
    fun addReview(courseId: String, rating: Double, comment: String) {
        viewModelScope.launch {
            _reviewState.value = ReviewState.Loading
            val currentUser = FirebaseAuth.getInstance().currentUser
            if (currentUser == null) {
                _reviewState.value = ReviewState.Error("User not authenticated")
                return@launch
            }
            
            val review = Review(
                courseId = courseId,
                studentId = currentUser.uid,
                studentName = currentUser.displayName ?: "Student",
                rating = rating.coerceIn(1.0, 5.0),
                comment = comment.trim()
            )
            
            val result = reviewRepository.addReview(review)
            _reviewState.value = result.fold(
                onSuccess = {
                    loadCourseReviews(courseId)
                    ReviewState.Success("Review submitted successfully!")
                },
                onFailure = { exception ->
                    ReviewState.Error(exception.message ?: "Failed to submit review")
                }
            )
        }
    }
    
    fun loadCourseReviews(courseId: String) {
        viewModelScope.launch {
            val result = reviewRepository.getCourseReviews(courseId)
            result.fold(
                onSuccess = { reviews ->
                    _reviews.value = reviews
                },
                onFailure = { /* Handle error */ }
            )
        }
    }
    
    fun loadStudentReview(courseId: String) {
        viewModelScope.launch {
            val currentUser = FirebaseAuth.getInstance().currentUser
            if (currentUser != null) {
                val result = reviewRepository.getStudentReview(courseId, currentUser.uid)
                result.fold(
                    onSuccess = { review ->
                        _studentReview.value = review
                    },
                    onFailure = { /* Handle error */ }
                )
            }
        }
    }
    
    fun resetReviewState() {
        _reviewState.value = ReviewState.Idle
    }
}

