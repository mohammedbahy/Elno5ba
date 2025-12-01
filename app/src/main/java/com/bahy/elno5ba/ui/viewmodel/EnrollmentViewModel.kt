package com.bahy.elno5ba.ui.viewmodel

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.bahy.elno5ba.data.model.Enrollment
import com.bahy.elno5ba.data.repository.EnrollmentRepository
import com.google.firebase.auth.FirebaseAuth
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch

sealed class EnrollmentState {
    data object Idle : EnrollmentState()
    data object Loading : EnrollmentState()
    data class Success(val message: String) : EnrollmentState()
    data class Error(val message: String) : EnrollmentState()
}

class EnrollmentViewModel(
    private val enrollmentRepository: EnrollmentRepository = EnrollmentRepository()
) : ViewModel() {
    
    private val _enrollmentState = MutableStateFlow<EnrollmentState>(EnrollmentState.Idle)
    val enrollmentState: StateFlow<EnrollmentState> = _enrollmentState.asStateFlow()
    
    private val _enrollments = MutableStateFlow<List<Enrollment>>(emptyList())
    val enrollments: StateFlow<List<Enrollment>> = _enrollments.asStateFlow()
    
    fun enrollInCourse(courseId: String) {
        viewModelScope.launch {
            _enrollmentState.value = EnrollmentState.Loading
            val currentUser = FirebaseAuth.getInstance().currentUser
            if (currentUser == null) {
                _enrollmentState.value = EnrollmentState.Error("User not authenticated")
                return@launch
            }
            
            val result = enrollmentRepository.enrollInCourse(courseId, currentUser.uid)
            _enrollmentState.value = result.fold(
                onSuccess = {
                    EnrollmentState.Success("Successfully enrolled in course!")
                },
                onFailure = { exception ->
                    EnrollmentState.Error(exception.message ?: "Failed to enroll in course")
                }
            )
        }
    }
    
    fun checkEnrollment(courseId: String, onResult: (Boolean) -> Unit) {
        viewModelScope.launch {
            val currentUser = FirebaseAuth.getInstance().currentUser
            if (currentUser == null) {
                onResult(false)
                return@launch
            }
            val isEnrolled = enrollmentRepository.isEnrolled(courseId, currentUser.uid)
            onResult(isEnrolled)
        }
    }
    
    fun loadStudentEnrollments() {
        viewModelScope.launch {
            val currentUser = FirebaseAuth.getInstance().currentUser
            if (currentUser != null) {
                val result = enrollmentRepository.getStudentEnrollments(currentUser.uid)
                result.fold(
                    onSuccess = { enrollments ->
                        _enrollments.value = enrollments
                    },
                    onFailure = { /* Handle error */ }
                )
            }
        }
    }
    
    fun enrollInCourseWithCode(courseId: String, code: String) {
        viewModelScope.launch {
            _enrollmentState.value = EnrollmentState.Loading
            val currentUser = FirebaseAuth.getInstance().currentUser
            if (currentUser == null) {
                _enrollmentState.value = EnrollmentState.Error("User not authenticated")
                return@launch
            }
            
            val result = enrollmentRepository.enrollInCourseWithCode(courseId, currentUser.uid, code)
            _enrollmentState.value = result.fold(
                onSuccess = {
                    EnrollmentState.Success("Successfully enrolled in course!")
                },
                onFailure = { exception ->
                    EnrollmentState.Error(exception.message ?: "Failed to enroll in course")
                }
            )
        }
    }
    
    fun resetEnrollmentState() {
        _enrollmentState.value = EnrollmentState.Idle
    }
}

