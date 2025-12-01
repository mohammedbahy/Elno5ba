package com.bahy.elno5ba.ui.screens

import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.WindowInsets
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.navigationBars
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.statusBars
import androidx.compose.foundation.layout.windowInsetsPadding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.filled.Add
import androidx.compose.material.icons.filled.Delete
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.SnackbarHost
import androidx.compose.material3.SnackbarHostState
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.material3.TopAppBarDefaults
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.remember
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.tooling.preview.Preview
import androidx.compose.ui.unit.dp
import androidx.lifecycle.viewmodel.compose.viewModel
import com.bahy.elno5ba.R
import com.bahy.elno5ba.ui.utils.stringResource
import androidx.compose.ui.platform.LocalContext
import com.bahy.elno5ba.data.model.Course
import com.bahy.elno5ba.data.model.VideoItem
import com.bahy.elno5ba.data.repository.CourseRepository
import com.bahy.elno5ba.ui.components.GenerateCodesDialog
import com.bahy.elno5ba.ui.components.SaveCodesDialog
import com.bahy.elno5ba.ui.viewmodel.CourseViewModel
import com.bahy.elno5ba.ui.viewmodel.CourseState
import com.google.firebase.auth.FirebaseAuth
import kotlinx.coroutines.launch

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun InstructorScreen(
    courseId: String = "",
    onBack: () -> Unit,
    onSubmitSuccess: () -> Unit = {},
    viewModel: CourseViewModel = viewModel()
) {
    val snackbarHostState = remember { SnackbarHostState() }
    val scope = rememberCoroutineScope()
    val context = LocalContext.current
    val courseState by viewModel.courseState.collectAsState()
    val allCourses by viewModel.courses.collectAsState()
    val courseRepository = remember { CourseRepository() }

    var title by remember { mutableStateOf("") }
    var showGenerateCodesDialog by remember { mutableStateOf(false) }
    var showSaveCodesDialog by remember { mutableStateOf(false) }
    var createdCourseId by remember { mutableStateOf("") }
    var isGeneratingCodes by remember { mutableStateOf(false) }
    var generatedCodes by remember { mutableStateOf<List<String>>(emptyList()) }
    var courseTitleForCodes by remember { mutableStateOf("") }
    var category by remember { mutableStateOf("") }
    var price by remember { mutableStateOf("") }
    var description by remember { mutableStateOf("") }
    var imageUrl by remember { mutableStateOf("") }
    var videoUrl by remember { mutableStateOf("") }

    data class VideoFormItem(val title: String, val url: String)
    var videoItems by remember { mutableStateOf(listOf(VideoFormItem(title = "", url = ""))) } // Dynamic list of videos with titles
    var isDataLoaded by remember { mutableStateOf(false) }

    val isEditMode = courseId.isNotEmpty()
    
    // Load course data if editing (only once)
    LaunchedEffect(courseId) {
        if (isEditMode && !isDataLoaded) {
            val course = allCourses.find { it.id == courseId }
            if (course != null) {
                title = course.title
                category = course.category
                price = course.price.toString()
                description = course.description
                imageUrl = course.coverImageUrl
                videoUrl = course.introVideoUrl
                videoItems = when {
                    course.videoItems.isNotEmpty() -> {
                        course.videoItems.map { VideoFormItem(title = it.title, url = it.url) }
                    }
                    course.videos.isNotEmpty() -> {
                        course.videos.mapIndexed { index, url ->
                            VideoFormItem(title = "Video ${index + 1}", url = url)
                        }
                    }
                    else -> listOf(VideoFormItem(title = "", url = ""))
                }
                isDataLoaded = true
            } else {
                // Try to load from repository
                viewModel.loadAllCourses()
            }
        } else if (!isEditMode) {
            // Reset form when creating new course
            title = ""
            category = ""
            price = ""
            description = ""
            imageUrl = ""
            videoUrl = ""
            videoItems = listOf(VideoFormItem(title = "", url = "")) // Start with one empty field
            isDataLoaded = false
        }
    }
    
    // Reload course data when courses list updates (only if editing and data not loaded yet)
    LaunchedEffect(allCourses) {
        if (isEditMode && !isDataLoaded && courseId.isNotEmpty()) {
            val course = allCourses.find { it.id == courseId }
            if (course != null) {
                title = course.title
                category = course.category
                price = course.price.toString()
                description = course.description
                imageUrl = course.coverImageUrl
                videoUrl = course.introVideoUrl
                videoItems = when {
                    course.videoItems.isNotEmpty() -> {
                        course.videoItems.map { VideoFormItem(title = it.title, url = it.url) }
                    }
                    course.videos.isNotEmpty() -> {
                        course.videos.mapIndexed { index, url ->
                            VideoFormItem(title = "Video ${index + 1}", url = url)
                        }
                    }
                    else -> listOf(VideoFormItem(title = "", url = ""))
                }
                isDataLoaded = true
            }
        }
    }

    val isValid =
        title.isNotBlank() && category.isNotBlank() && price.isNotBlank() && description.isNotBlank()
    
    val isLoading = courseState is CourseState.Loading
    
    // Get created course ID
    val createdCourseIdFlow by viewModel.createdCourseId.collectAsState()
    
    // Handle course state changes (only show messages for user actions, not background loads)
    LaunchedEffect(courseState) {
        when (courseState) {
            is CourseState.Success -> {
                // Only show message if there's an actual message (from create/update action)
                val message = (courseState as CourseState.Success).message
                if (message != null) {
                    snackbarHostState.showSnackbar(message)
                    if (!isEditMode) {
                        // Show dialog to generate codes for new courses
                        createdCourseIdFlow?.let { courseId ->
                            createdCourseId = courseId
                            showGenerateCodesDialog = true
                        }
                        // Clear form only for new courses after successful creation
                        title = ""
                        category = ""
                        price = ""
                        description = ""
                        imageUrl = ""
                        videoUrl = ""
                        videoItems = listOf(VideoFormItem(title = "", url = ""))
                        isDataLoaded = false
                    } else {
                        // Mark data as loaded after successful update
                        isDataLoaded = true
                    }
                    // Reload courses to show the new/updated one
                    viewModel.loadAllCourses()
                    viewModel.resetCourseState()
                    // Only navigate away when editing, stay on screen when creating new course
                    if (isEditMode) {
                        onSubmitSuccess()
                    }
                } else {
                    // No message means it's just a background load, reset state silently
                    viewModel.resetCourseState()
                }
            }
            is CourseState.Error -> {
                // Only show error if it's from a user action (has a message)
                val errorMessage = (courseState as CourseState.Error).message
                if (errorMessage.isNotEmpty()) {
                    snackbarHostState.showSnackbar(errorMessage)
                    viewModel.resetCourseState()
                }
            }
            else -> {}
        }
    }

    Scaffold(
        modifier = Modifier
            .fillMaxSize()
            .windowInsetsPadding(WindowInsets.statusBars),
        topBar = {
            TopAppBar(
                title = {
                    Text(
                        text = "Instructor Portal",
                        style = MaterialTheme.typography.titleLarge,
                        fontWeight = FontWeight.Bold,
                        color = Color(0xFF1A1A2E)
                    )
                },
                navigationIcon = {
                    IconButton(onClick = onBack) {
                        Icon(
                            Icons.AutoMirrored.Filled.ArrowBack,
                            contentDescription = "Back",
                            tint = Color(0xFF1A1A2E)
                        )
                    }
                },
                colors = TopAppBarDefaults.topAppBarColors(containerColor = Color.White)
            )
        },
        snackbarHost = { SnackbarHost(hostState = snackbarHostState) }
    ) { innerPadding ->
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(innerPadding)
                .background(Color(0xFFF5F5F5))
                .padding(horizontal = 16.dp)
                .padding(top = 16.dp, bottom = 8.dp)
                .verticalScroll(rememberScrollState())
                .windowInsetsPadding(WindowInsets.navigationBars),
            verticalArrangement = Arrangement.spacedBy(14.dp)
        ) {
            Text(
                text = if (isEditMode) stringResource(R.string.instructor_edit_course) else stringResource(R.string.instructor_create_course),
                style = MaterialTheme.typography.titleMedium,
                color = Color(0xFF444444)
            )

            OutlinedTextField(
                value = title,
                onValueChange = { title = it },
                label = { Text(stringResource(R.string.instructor_course_title)) },
                modifier = Modifier.fillMaxWidth()
            )

            Row(horizontalArrangement = Arrangement.spacedBy(12.dp)) {
                OutlinedTextField(
                    value = category,
                    onValueChange = { category = it },
                    label = { Text(stringResource(R.string.instructor_category)) },
                    modifier = Modifier
                        .weight(1f)
                )
                OutlinedTextField(
                    value = price,
                    onValueChange = { price = it.filter { ch -> ch.isDigit() } },
                    label = { Text(stringResource(R.string.instructor_price)) },
                    modifier = Modifier
                        .weight(1f),
                    keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Number)
                )
            }

            OutlinedTextField(
                value = description,
                onValueChange = { description = it },
                label = { Text(stringResource(R.string.instructor_description)) },
                modifier = Modifier
                    .fillMaxWidth()
                    .height(120.dp)
            )

            OutlinedTextField(
                value = imageUrl,
                onValueChange = { imageUrl = it },
                label = { Text(stringResource(R.string.instructor_cover_image_url)) },
                modifier = Modifier.fillMaxWidth()
            )

            OutlinedTextField(
                value = videoUrl,
                onValueChange = { videoUrl = it },
                label = { Text(stringResource(R.string.instructor_intro_video_url)) },
                modifier = Modifier.fillMaxWidth()
            )

            Spacer(modifier = Modifier.height(8.dp))
            
            // Course Videos Section
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically
            ) {
                Text(
                    text = "Course Videos",
                    style = MaterialTheme.typography.titleMedium,
                    fontWeight = FontWeight.Bold,
                    color = Color(0xFF1A1A2E)
                )
                IconButton(
                    onClick = {
                        videoItems = videoItems + VideoFormItem(title = "", url = "")
                    },
                    modifier = Modifier.size(40.dp)
                ) {
                    Icon(
                        imageVector = Icons.Filled.Add,
                        contentDescription = "Add Video",
                        tint = Color(0xFFFF6B35)
                    )
                }
            }

            // Dynamic video fields (title + URL for each video)
            videoItems.forEachIndexed { index, item ->
                Row(
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(vertical = 4.dp),
                    horizontalArrangement = Arrangement.spacedBy(8.dp),
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    OutlinedTextField(
                        value = item.title,
                        onValueChange = { newTitle ->
                            videoItems = videoItems.toMutableList().apply {
                                this[index] = this[index].copy(title = newTitle)
                            }
                        },
                        label = { Text("Video ${index + 1} Name") },
                        placeholder = { Text("Introduction, Lesson ${index + 1}, ...") },
                        modifier = Modifier.weight(1f),
                        singleLine = true
                    )
                    OutlinedTextField(
                        value = item.url,
                        onValueChange = { newUrl ->
                            videoItems = videoItems.toMutableList().apply {
                                this[index] = this[index].copy(url = newUrl)
                            }
                        },
                        label = { Text("Video ${index + 1} URL") },
                        placeholder = { Text("https://example.com/video${index + 1}") },
                        modifier = Modifier.weight(1f),
                        singleLine = true
                    )
                    IconButton(
                        onClick = {
                            if (videoItems.size > 1) {
                                videoItems = videoItems.toMutableList().apply {
                                    removeAt(index)
                                }
                            } else {
                                // If only one field, just clear it
                                videoItems = listOf(VideoFormItem(title = "", url = ""))
                            }
                        },
                        modifier = Modifier.size(48.dp)
                    ) {
                        Icon(
                            imageVector = Icons.Filled.Delete,
                            contentDescription = "Delete Video",
                            tint = Color(0xFFE53935)
                        )
                    }
                }
            }

            Spacer(modifier = Modifier.height(4.dp))
            
            // Generate More Codes Button (only in edit mode)
            if (isEditMode && courseId.isNotEmpty()) {
                Button(
                    onClick = {
                        createdCourseId = courseId
                        showGenerateCodesDialog = true
                    },
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(bottom = 8.dp),
                    colors = ButtonDefaults.buttonColors(containerColor = Color(0xFF4CAF50))
                ) {
                    Text("Generate More Enrollment Codes", color = Color.White)
                }
            }

            Button(
                onClick = {
                    try {
                        val currentUser = FirebaseAuth.getInstance().currentUser
                        if (currentUser == null) {
                            scope.launch {
                                snackbarHostState.showSnackbar("User not authenticated. Please log in first.")
                            }
                            return@Button
                        }
                        
                        val coursePrice = price.toDoubleOrNull() ?: 0.0
                        // Filter out empty video URLs and build video items with titles
                        val cleanedVideoItems = videoItems
                            .map { it.copy(title = it.title.trim(), url = it.url.trim()) }
                            .filter { it.url.isNotEmpty() }

                        val videos = cleanedVideoItems.map { it.url }
                        val videoItemsForCourse = cleanedVideoItems.map {
                            VideoItem(
                                title = if (it.title.isNotEmpty()) it.title else it.url,
                                url = it.url
                            )
                        }
                        
                        // Get existing course data to preserve instructorId and other fields
                        val existingCourse = if (isEditMode) {
                            allCourses.find { it.id == courseId }
                        } else {
                            null
                        }
                        
                        val course = Course(
                            id = courseId,
                            title = title.trim(),
                            category = category.trim(),
                            price = coursePrice,
                            description = description.trim(),
                            coverImageUrl = imageUrl.trim(),
                            introVideoUrl = videoUrl.trim(),
                            videos = videos,
                            videoItems = videoItemsForCourse,
                            isPublished = true,
                            // Preserve instructorId and instructorName when editing
                            instructorId = existingCourse?.instructorId ?: currentUser.uid,
                            instructorName = existingCourse?.instructorName ?: (currentUser.displayName ?: "Instructor"),
                            // Preserve rating and enrollment data
                            rating = existingCourse?.rating ?: 0.0,
                            totalRatings = existingCourse?.totalRatings ?: 0,
                            enrolledStudents = existingCourse?.enrolledStudents ?: 0,
                            createdAt = existingCourse?.createdAt,
                            updatedAt = null // Will be set by repository
                        )
                        if (isEditMode) {
                            viewModel.updateCourse(courseId, course)
                        } else {
                            viewModel.createCourse(course)
                        }
                    } catch (e: Exception) {
                        scope.launch {
                            snackbarHostState.showSnackbar("Error: ${e.message}")
                        }
                    }
                },
                enabled = isValid && !isLoading,
                modifier = Modifier.fillMaxWidth(),
                colors = ButtonDefaults.buttonColors(containerColor = Color(0xFFFF6B35))
            ) {
                if (isLoading) {
                    Text(text = if (isEditMode) stringResource(R.string.instructor_updating) else stringResource(R.string.instructor_submitting), color = Color.White)
                } else {
                    Text(text = if (isEditMode) stringResource(R.string.instructor_update_course) else stringResource(R.string.instructor_submit_course), color = Color.White)
                }
            }
        }
    }
    
    // Generate Codes Dialog
    if (showGenerateCodesDialog) {
        GenerateCodesDialog(
            onDismiss = { 
                showGenerateCodesDialog = false
                createdCourseId = ""
            },
            onConfirm = { count ->
                isGeneratingCodes = true
                scope.launch {
                    val result = courseRepository.generateEnrollmentCodes(createdCourseId, count)
                    result.fold(
                        onSuccess = { codes ->
                            isGeneratingCodes = false
                            showGenerateCodesDialog = false
                            // Show save dialog
                            val course = allCourses.find { it.id == createdCourseId }
                            if (course != null) {
                                generatedCodes = codes
                                courseTitleForCodes = course.title
                                showSaveCodesDialog = true
                            } else {
                                snackbarHostState.showSnackbar("Codes generated successfully!")
                            }
                            createdCourseId = ""
                        },
                        onFailure = { error ->
                            isGeneratingCodes = false
                            snackbarHostState.showSnackbar("Error generating codes: ${error.message}")
                        }
                    )
                }
            },
            isLoading = isGeneratingCodes
        )
    }
    
    // Save Codes Dialog
    if (showSaveCodesDialog && generatedCodes.isNotEmpty()) {
        SaveCodesDialog(
            courseTitle = courseTitleForCodes,
            codes = generatedCodes,
            onDismiss = {
                showSaveCodesDialog = false
                generatedCodes = emptyList()
                courseTitleForCodes = ""
            },
            onSaveComplete = {
                showSaveCodesDialog = false
                scope.launch {
                    snackbarHostState.showSnackbar("Codes saved successfully!")
                }
                generatedCodes = emptyList()
                courseTitleForCodes = ""
            },
            onSaveError = { error ->
                scope.launch {
                    snackbarHostState.showSnackbar("Error saving file: $error")
                }
            }
        )
    }
}

@Preview(showBackground = true)
@Composable
private fun PreviewInstructor() {
    InstructorScreen(onBack = {})
}


