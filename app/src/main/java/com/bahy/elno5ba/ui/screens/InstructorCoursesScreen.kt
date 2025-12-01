package com.bahy.elno5ba.ui.screens

import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.WindowInsets
import androidx.compose.foundation.layout.navigationBars
import androidx.compose.foundation.layout.statusBars
import androidx.compose.foundation.layout.windowInsetsPadding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.filled.Delete
import androidx.compose.material.icons.filled.Edit
import androidx.compose.material.icons.filled.Person
import androidx.compose.material.icons.filled.Star
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBar
import androidx.compose.material3.TopAppBarDefaults
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.layout.ContentScale
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.compose.ui.tooling.preview.Preview
import androidx.lifecycle.viewmodel.compose.viewModel
import coil.compose.AsyncImage
import com.bahy.elno5ba.R
import com.bahy.elno5ba.ui.utils.stringResource
import com.bahy.elno5ba.data.model.Course
import com.bahy.elno5ba.ui.viewmodel.CourseViewModel
import com.bahy.elno5ba.ui.viewmodel.CourseState
import com.google.firebase.auth.FirebaseAuth

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun InstructorCoursesScreen(
    onBack: () -> Unit,
    onEditCourse: (String) -> Unit,
    viewModel: CourseViewModel = viewModel()
) {
    val currentUser = FirebaseAuth.getInstance().currentUser
    val instructorId = currentUser?.uid ?: ""
    
    val courseState by viewModel.courseState.collectAsState()
    val allCourses by viewModel.courses.collectAsState()
    
    // Filter courses by instructor
    val instructorCourses = allCourses.filter { it.instructorId == instructorId }
    
    var showDeleteDialog by remember { mutableStateOf(false) }
    var courseToDelete by remember { mutableStateOf<Course?>(null) }
    
    val isLoading = courseState is CourseState.Loading
    
    // Load courses when screen is displayed
    LaunchedEffect(Unit) {
        viewModel.loadAllCourses()
    }
    
    Column(
        modifier = Modifier
            .fillMaxSize()
            .windowInsetsPadding(WindowInsets.statusBars)
    ) {
        // Top App Bar
        TopAppBar(
            title = {
                Text(
                    text = stringResource(R.string.instructor_my_courses, instructorCourses.size),
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
        
        // Content
        if (isLoading && instructorCourses.isEmpty()) {
            Box(
                modifier = Modifier
                    .fillMaxSize()
                    .windowInsetsPadding(WindowInsets.navigationBars),
                contentAlignment = Alignment.Center
            ) {
                CircularProgressIndicator()
            }
        } else if (instructorCourses.isEmpty()) {
            Box(
                modifier = Modifier
                    .fillMaxSize()
                    .windowInsetsPadding(WindowInsets.navigationBars),
                contentAlignment = Alignment.Center
            ) {
                Column(
                    horizontalAlignment = Alignment.CenterHorizontally,
                    verticalArrangement = Arrangement.spacedBy(8.dp)
                ) {
                    Icon(
                        Icons.Filled.Person,
                        contentDescription = null,
                        modifier = Modifier.size(64.dp),
                        tint = Color(0xFF999999)
                    )
                    Text(
                        text = "No courses yet",
                        style = MaterialTheme.typography.titleMedium,
                        color = Color(0xFF666666)
                    )
                    Text(
                        text = "Create your first course to get started",
                        style = MaterialTheme.typography.bodyMedium,
                        color = Color(0xFF999999)
                    )
                }
            }
        } else {
            LazyColumn(
                modifier = Modifier
                    .weight(1f)
                    .fillMaxWidth()
                    .background(Color(0xFFF5F5F5))
                    .windowInsetsPadding(WindowInsets.navigationBars),
                contentPadding = PaddingValues(16.dp),
                verticalArrangement = Arrangement.spacedBy(12.dp)
            ) {
                items(instructorCourses) { course ->
                    InstructorCourseCard(
                        course = course,
                        onEdit = { onEditCourse(course.id) },
                        onDelete = {
                            courseToDelete = course
                            showDeleteDialog = true
                        }
                    )
                }
            }
        }
    }
    
    // Delete Confirmation Dialog
    if (showDeleteDialog && courseToDelete != null) {
        AlertDialog(
            onDismissRequest = { showDeleteDialog = false },
            title = { Text(stringResource(R.string.instructor_delete_course)) },
            text = {
                Text(stringResource(R.string.instructor_delete_course_message, courseToDelete?.title ?: ""))
            },
            confirmButton = {
                TextButton(
                    onClick = {
                        courseToDelete?.let { course ->
                            viewModel.deleteCourse(course.id)
                            showDeleteDialog = false
                            courseToDelete = null
                        }
                    }
                ) {
                    Text(stringResource(R.string.instructor_delete), color = Color(0xFFD32F2F))
                }
            },
            dismissButton = {
                TextButton(onClick = { showDeleteDialog = false }) {
                    Text(stringResource(R.string.common_cancel))
                }
            }
        )
    }
}

@Composable
private fun InstructorCourseCard(
    course: Course,
    onEdit: () -> Unit,
    onDelete: () -> Unit
) {
    Card(
        modifier = Modifier.fillMaxWidth(),
        shape = RoundedCornerShape(12.dp),
        colors = CardDefaults.cardColors(containerColor = Color.White),
        elevation = CardDefaults.cardElevation(defaultElevation = 2.dp)
    ) {
        Column(
            modifier = Modifier
                .fillMaxWidth()
                .padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(12.dp)
        ) {
            // Course Image and Title Row
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.spacedBy(12.dp)
            ) {
                // Course Image
                Box(
                    modifier = Modifier
                        .size(80.dp)
                        .clip(RoundedCornerShape(8.dp))
                        .background(Color(0xFFE0E0E0))
                ) {
                    val coverImageUrl = course.coverImageUrl.trim()
                    if (coverImageUrl.isNotEmpty() && coverImageUrl.isNotBlank()) {
                        AsyncImage(
                            model = coverImageUrl,
                            contentDescription = course.title,
                            modifier = Modifier.fillMaxSize(),
                            contentScale = ContentScale.Crop,
                            placeholder = painterResource(id = R.drawable.ic_launcher_foreground),
                            error = painterResource(id = R.drawable.ic_launcher_foreground),
                            onError = {
                                android.util.Log.e("InstructorCoursesScreen", "Error loading image: $coverImageUrl")
                            }
                        )
                    } else {
                        Box(
                            modifier = Modifier.fillMaxSize(),
                            contentAlignment = Alignment.Center
                        ) {
                            Text(
                                text = "No Image",
                                fontSize = 10.sp,
                                color = Color(0xFF999999)
                            )
                        }
                    }
                }
                
                // Course Info
                Column(
                    modifier = Modifier.weight(1f),
                    verticalArrangement = Arrangement.spacedBy(4.dp)
                ) {
                    Text(
                        text = course.title,
                        style = MaterialTheme.typography.titleMedium,
                        fontWeight = FontWeight.Bold,
                        maxLines = 2,
                        overflow = TextOverflow.Ellipsis
                    )
                    Text(
                        text = course.category,
                        style = MaterialTheme.typography.bodySmall,
                        color = Color(0xFFFF6B35)
                    )
                    Text(
                        text = "${course.price} EGP",
                        style = MaterialTheme.typography.bodyMedium,
                        fontWeight = FontWeight.Medium,
                        color = Color(0xFF1A1A2E)
                    )
                }
            }
            
            // Statistics Row
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically
            ) {
                // Enrolled Students Count
                Row(
                    verticalAlignment = Alignment.CenterVertically,
                    horizontalArrangement = Arrangement.spacedBy(4.dp)
                ) {
                    Icon(
                        Icons.Filled.Person,
                        contentDescription = null,
                        modifier = Modifier.size(16.dp),
                        tint = Color(0xFF666666)
                    )
                    Text(
                        text = "${course.enrolledStudents} enrolled",
                        style = MaterialTheme.typography.bodySmall,
                        color = Color(0xFF666666)
                    )
                }
                
                // Rating
                if (course.totalRatings > 0) {
                    Row(
                        verticalAlignment = Alignment.CenterVertically,
                        horizontalArrangement = Arrangement.spacedBy(4.dp)
                    ) {
                        Icon(
                            Icons.Filled.Star,
                            contentDescription = null,
                            modifier = Modifier.size(16.dp),
                            tint = Color(0xFFFFD700)
                        )
                        Text(
                            text = String.format("%.1f", course.rating),
                            style = MaterialTheme.typography.bodySmall,
                            color = Color(0xFF666666)
                        )
                        Text(
                            text = "(${course.totalRatings})",
                            style = MaterialTheme.typography.bodySmall,
                            color = Color(0xFF999999)
                        )
                    }
                }
            }
            
            // Action Buttons
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.spacedBy(8.dp)
            ) {
                // Edit Button
                androidx.compose.material3.Button(
                    onClick = onEdit,
                    modifier = Modifier.weight(1f),
                    colors = androidx.compose.material3.ButtonDefaults.buttonColors(
                        containerColor = Color(0xFFFF6B35)
                    )
                ) {
                    Icon(
                        Icons.Filled.Edit,
                        contentDescription = "Edit",
                        modifier = Modifier.size(18.dp)
                    )
                    Spacer(modifier = Modifier.size(4.dp))
                    Text(stringResource(R.string.instructor_edit))
                }
                
                // Delete Button
                androidx.compose.material3.Button(
                    onClick = onDelete,
                    modifier = Modifier.weight(1f),
                    colors = androidx.compose.material3.ButtonDefaults.buttonColors(
                        containerColor = Color(0xFFD32F2F)
                    )
                ) {
                    Icon(
                        Icons.Filled.Delete,
                        contentDescription = "Delete",
                        modifier = Modifier.size(18.dp)
                    )
                    Spacer(modifier = Modifier.size(4.dp))
                    Text(stringResource(R.string.instructor_delete))
                }
            }
        }
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Preview(showBackground = true)
@Composable
private fun PreviewInstructorCourses() {
    // Preview without ViewModel - use mock data
    val mockCourses = remember {
        listOf(
            Course(
                id = "1",
                title = "Introduction to Graphic Design",
                category = "Graphic Design",
                price = 500.0,
                description = "Learn the fundamentals of graphic design",
                coverImageUrl = "",
                introVideoUrl = "",
                instructorId = "instructor1",
                instructorName = "John Doe",
                rating = 4.5,
                totalRatings = 120,
                enrolledStudents = 500,
                isPublished = true
            ),
            Course(
                id = "2",
                title = "Advanced UI/UX Design",
                category = "UI/UX",
                price = 750.0,
                description = "Master advanced UI/UX design principles",
                coverImageUrl = "",
                introVideoUrl = "",
                instructorId = "instructor1",
                instructorName = "John Doe",
                rating = 4.8,
                totalRatings = 200,
                enrolledStudents = 800,
                isPublished = true
            )
        )
    }
    
    Column(
        modifier = Modifier
            .fillMaxSize()
            .windowInsetsPadding(WindowInsets.statusBars)
    ) {
        TopAppBar(
            title = {
                Text(
                    text = "My Courses (${mockCourses.size})",
                    style = MaterialTheme.typography.titleLarge,
                    fontWeight = FontWeight.Bold,
                    color = Color(0xFF1A1A2E)
                )
            },
            navigationIcon = {
                IconButton(onClick = { }) {
                    Icon(
                        Icons.AutoMirrored.Filled.ArrowBack,
                        contentDescription = "Back",
                        tint = Color(0xFF1A1A2E)
                    )
                }
            },
            colors = TopAppBarDefaults.topAppBarColors(containerColor = Color.White)
        )
        
        LazyColumn(
            modifier = Modifier
                .weight(1f)
                .fillMaxWidth()
                .background(Color(0xFFF5F5F5))
                .windowInsetsPadding(WindowInsets.navigationBars),
            contentPadding = PaddingValues(16.dp),
            verticalArrangement = Arrangement.spacedBy(12.dp)
        ) {
            items(mockCourses) { course ->
                InstructorCourseCard(
                    course = course,
                    onEdit = { },
                    onDelete = { }
                )
            }
        }
    }
}