package com.bahy.elno5ba.ui.viewmodel

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.bahy.elno5ba.data.model.Course
import com.bahy.elno5ba.data.model.UserRole
import com.bahy.elno5ba.data.repository.CourseRepository
import com.google.firebase.auth.FirebaseAuth
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch

sealed class CourseState {
    data object Idle : CourseState()
    data object Loading : CourseState()
    data class Success(val message: String? = null) : CourseState()
    data class Error(val message: String) : CourseState()
}

class CourseViewModel(
    private val courseRepository: CourseRepository = CourseRepository()
) : ViewModel() {
    
    private val _courseState = MutableStateFlow<CourseState>(CourseState.Idle)
    val courseState: StateFlow<CourseState> = _courseState.asStateFlow()
    
    private val _courses = MutableStateFlow<List<Course>>(emptyList())
    val courses: StateFlow<List<Course>> = _courses.asStateFlow()
    
    private val _userRole = MutableStateFlow<UserRole?>(null)
    val userRole: StateFlow<UserRole?> = _userRole.asStateFlow()
    
    init {
        loadUserRole()
        loadAllCourses()
    }
    
    private fun loadUserRole() {
        val currentUser = FirebaseAuth.getInstance().currentUser
        if (currentUser != null) {
            viewModelScope.launch {
                _userRole.value = courseRepository.getUserRole(currentUser.uid)
            }
        }
    }
    
    fun setUserRole(role: String) {
        val currentUser = FirebaseAuth.getInstance().currentUser
        if (currentUser != null) {
            viewModelScope.launch {
                _courseState.value = CourseState.Loading
                val result = courseRepository.setUserRole(currentUser.uid, role)
                result.fold(
                    onSuccess = {
                        loadUserRole()
                        _courseState.value = CourseState.Success("Role set successfully")
                    },
                    onFailure = { 
                        _courseState.value = CourseState.Error(it.message ?: "Failed to set role")
                    }
                )
            }
        }
    }
    
    fun loadAllCourses() {
        viewModelScope.launch {
            // Only set loading state if not already in a success/error state from a user action
            if (_courseState.value is CourseState.Idle) {
                _courseState.value = CourseState.Loading
            }
            val result = courseRepository.getAllCourses()
            result.fold(
                onSuccess = { courses ->
                    android.util.Log.d("CourseViewModel", "Courses loaded successfully: ${courses.size} courses")
                    courses.forEach { course ->
                        android.util.Log.d("CourseViewModel", "Course: ${course.title}, isPublished: ${course.isPublished}, id: ${course.id}")
                    }
                    _courses.value = courses
                    // Only reset to Idle if we were in Loading state (not from user action)
                    if (_courseState.value is CourseState.Loading) {
                        _courseState.value = CourseState.Idle
                    }
                },
                onFailure = { exception ->
                    android.util.Log.e("CourseViewModel", "Failed to load courses: ${exception.message}", exception)
                    // Only set error if we were in Loading state (not from user action)
                    if (_courseState.value is CourseState.Loading) {
                        _courseState.value = CourseState.Error(exception.message ?: "Failed to load courses")
                    }
                }
            )
        }
    }
    
    private val _createdCourseId = MutableStateFlow<String?>(null)
    val createdCourseId: StateFlow<String?> = _createdCourseId.asStateFlow()
    
    fun createCourse(course: Course) {
        viewModelScope.launch {
            _courseState.value = CourseState.Loading
            val currentUser = FirebaseAuth.getInstance().currentUser
            if (currentUser == null) {
                _courseState.value = CourseState.Error("User not authenticated. Please log in first.")
                return@launch
            }
            
            // Check if user is instructor
            val userRole = courseRepository.getUserRole(currentUser.uid)
            if (userRole?.role != "instructor") {
                _courseState.value = CourseState.Error("Only instructors can create courses. Your role: ${userRole?.role ?: "not set"}. Please contact admin to set your role as instructor.")
                return@launch
            }
            
            val courseWithInstructor = course.copy(
                instructorId = currentUser.uid,
                instructorName = currentUser.displayName ?: "Instructor"
            )
            val result = courseRepository.createCourse(courseWithInstructor)
            result.fold(
                onSuccess = { courseId ->
                    _createdCourseId.value = courseId
                    // Reload courses silently (without changing state)
                    val result = courseRepository.getAllCourses()
                    result.fold(
                        onSuccess = { courses ->
                            _courses.value = courses
                        },
                        onFailure = { /* Ignore reload errors */ }
                    )
                    _courseState.value = CourseState.Success("Course created successfully")
                },
                onFailure = { exception ->
                    val errorMessage = when {
                        exception.message?.contains("PERMISSION_DENIED") == true -> 
                            "Permission denied. Make sure you are logged in as an instructor and Firestore rules are set correctly."
                        exception.message?.contains("index") == true -> 
                            "Index required. Please create the Firestore index or wait a few minutes."
                        else -> 
                            exception.message ?: "Failed to create course. Error: ${exception.javaClass.simpleName}"
                    }
                    _courseState.value = CourseState.Error(errorMessage)
                }
            )
        }
    }
    
    
    fun updateCourse(courseId: String, course: Course) {
        viewModelScope.launch {
            _courseState.value = CourseState.Loading
            val result = courseRepository.updateCourse(courseId, course)
            result.fold(
                onSuccess = {
                    // Reload courses silently (without changing state)
                    val reloadResult = courseRepository.getAllCourses()
                    reloadResult.fold(
                        onSuccess = { courses ->
                            _courses.value = courses
                        },
                        onFailure = { /* Ignore reload errors */ }
                    )
                    _courseState.value = CourseState.Success("Course updated successfully")
                },
                onFailure = { 
                    _courseState.value = CourseState.Error(it.message ?: "Failed to update course")
                }
            )
        }
    }
    
    fun deleteCourse(courseId: String) {
        viewModelScope.launch {
            _courseState.value = CourseState.Loading
            val result = courseRepository.deleteCourse(courseId)
            result.fold(
                onSuccess = {
                    loadAllCourses()
                    _courseState.value = CourseState.Success("Course deleted successfully")
                },
                onFailure = { 
                    _courseState.value = CourseState.Error(it.message ?: "Failed to delete course")
                }
            )
        }
    }
    
    fun resetCourseState() {
        _courseState.value = CourseState.Idle
    }
    
    // Load a single course by ID
    suspend fun getCourseById(courseId: String): Result<Course?> {
        return courseRepository.getCourseById(courseId)
    }
}

