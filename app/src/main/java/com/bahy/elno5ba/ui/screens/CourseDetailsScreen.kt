package com.bahy.elno5ba.ui.screens

import androidx.compose.foundation.Image
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.offset
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.layout.WindowInsets
import androidx.compose.foundation.layout.navigationBars
import androidx.compose.foundation.layout.statusBars
import androidx.compose.foundation.layout.windowInsetsPadding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.automirrored.filled.ArrowForward
import androidx.compose.material.icons.filled.Person
import androidx.compose.material.icons.filled.PlayArrow
import androidx.compose.material.icons.filled.Star
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.NavigationBar
import androidx.compose.material3.NavigationBarItem
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableIntStateOf
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
import androidx.compose.ui.tooling.preview.Preview
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.compose.ui.zIndex
import androidx.compose.ui.platform.LocalContext
import androidx.lifecycle.viewmodel.compose.viewModel
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.collectAsState
import android.content.Intent
import android.net.Uri
import coil.compose.AsyncImage
import com.bahy.elno5ba.R
import com.bahy.elno5ba.ui.utils.stringResource
import com.bahy.elno5ba.ui.viewmodel.CourseViewModel
import com.bahy.elno5ba.ui.viewmodel.EnrollmentViewModel
import com.bahy.elno5ba.ui.viewmodel.ReviewViewModel
import com.bahy.elno5ba.ui.viewmodel.ReviewState
import com.bahy.elno5ba.ui.viewmodel.FavoriteViewModel
import com.bahy.elno5ba.ui.components.AddReviewDialog
import com.bahy.elno5ba.ui.components.EnrollmentCodeDialog
import com.bahy.elno5ba.data.repository.CourseRepository
import androidx.compose.material.icons.filled.Favorite
import androidx.compose.runtime.rememberCoroutineScope
import com.google.firebase.auth.FirebaseAuth
import kotlinx.coroutines.launch
import java.util.Locale

@Composable
fun CourseDetailsScreen(
    courseId: String,
    onBack: () -> Unit = {},
    onPay: (String) -> Unit = {},
    onOpenVideo: (String, String) -> Unit = { _, _ -> }, // Kept for backward compatibility but not used
    onOpenCourses: () -> Unit = {},
    onOpenFavourites: () -> Unit = {},
    onOpenProfile: () -> Unit = {},
    onOpenHome: () -> Unit = {},
    courseViewModel: CourseViewModel = viewModel(),
    enrollmentViewModel: EnrollmentViewModel = viewModel(),
    reviewViewModel: ReviewViewModel = viewModel(),
    favoriteViewModel: FavoriteViewModel = viewModel()
) {
    val context = LocalContext.current
    var selectedTab by remember { mutableIntStateOf(0) } // About or Videos
    var isDescriptionExpanded by remember { mutableStateOf(false) }
    var showAddReviewDialog by remember { mutableStateOf(false) }
    var showEnrollmentCodeDialog by remember { mutableStateOf(false) }
    var isEnrolled by remember { mutableStateOf(false) }
    var isFavorited by remember { mutableStateOf(false) }
    var isInstructor by remember { mutableStateOf(false) }
    
    val coroutineScope = rememberCoroutineScope()
    val courseRepository = remember { CourseRepository() }
    val currentUser = FirebaseAuth.getInstance().currentUser
    
    // Load course data
    var course by remember { mutableStateOf<com.bahy.elno5ba.data.model.Course?>(null) }
    
    // Load reviews
    val reviews by reviewViewModel.reviews.collectAsState()
    val reviewState by reviewViewModel.reviewState.collectAsState()
    
    LaunchedEffect(courseId) {
        // Load course using ViewModel
        val courseResult = courseViewModel.getCourseById(courseId)
        courseResult.fold(
            onSuccess = { loadedCourse: com.bahy.elno5ba.data.model.Course? -> 
                course = loadedCourse
            },
            onFailure = { /* Handle error */ }
        )
        
        // Check if course is favorited
        favoriteViewModel.isFavorited(courseId) { favorited ->
            isFavorited = favorited
        }
        
        // Load reviews
        reviewViewModel.loadCourseReviews(courseId)
        
        // Check enrollment using ViewModel
        enrollmentViewModel.checkEnrollment(courseId) { enrolled ->
            isEnrolled = enrolled
        }
        
        // Check if user is instructor
        val currentUser = FirebaseAuth.getInstance().currentUser
        if (currentUser != null) {
            coroutineScope.launch {
                val userRole = courseRepository.getUserRole(currentUser.uid)
                isInstructor = userRole?.role == "instructor"
            }
        }
    }
    
    val fullDescription = course?.description ?: "No description available"
    val shortDescription = fullDescription.take(150) + if (fullDescription.length > 150) "..." else ""
    
    var selectedNavTab by remember { mutableIntStateOf(1) } // Courses tab
    
    Column(
        modifier = Modifier
            .fillMaxSize()
            .windowInsetsPadding(WindowInsets.statusBars)
    ) {
        LazyColumn(
            modifier = Modifier
                .weight(1f)
                .windowInsetsPadding(WindowInsets.navigationBars),
            contentPadding = PaddingValues(bottom = 8.dp)
        ) {
            // Header Image
            item {
                Box(modifier = Modifier.fillMaxWidth().height(280.dp)) {
                    // Back Button
                    IconButton(
                        onClick = onBack,
                        modifier = Modifier
                            .padding(16.dp)
                            .zIndex(2f)
                    ) {
                        Card(
                            shape = CircleShape,
                            colors = CardDefaults.cardColors(containerColor = Color(0xFFFFD700)),
                            modifier = Modifier.size(40.dp)
                        ) {
                            Box(
                                modifier = Modifier.fillMaxSize(),
                                contentAlignment = Alignment.Center
                            ) {
                                Icon(
                                    Icons.AutoMirrored.Filled.ArrowBack,
                                    contentDescription = "Back",
                                    tint = Color.White,
                                    modifier = Modifier.size(24.dp)
                                )
                            }
                        }
                    }
                    
                    // Header Image
                    val coverImageUrl = course?.coverImageUrl?.trim()
                    if (!coverImageUrl.isNullOrEmpty() && coverImageUrl.isNotBlank()) {
                        AsyncImage(
                            model = coverImageUrl,
                            contentDescription = "Course Header",
                            modifier = Modifier
                                .fillMaxWidth()
                                .height(280.dp),
                            contentScale = ContentScale.Crop,
                            placeholder = painterResource(id = R.drawable.ic_launcher_foreground),
                            error = painterResource(id = R.drawable.ic_launcher_foreground),
                            onError = {
                                android.util.Log.e("CourseDetailsScreen", "Error loading cover image: $coverImageUrl")
                            }
                        )
                    } else {
                        Image(
                            painter = painterResource(id = R.drawable.ic_launcher_foreground),
                            contentDescription = "Course Header",
                            modifier = Modifier
                                .fillMaxWidth()
                                .height(280.dp),
                            contentScale = ContentScale.Crop
                        )
                    }
                    
                    // Play Button Overlay
                    Card(
                        shape = CircleShape,
                        colors = CardDefaults.cardColors(containerColor = Color(0xFFFF6B35)),
                        modifier = Modifier
                            .align(Alignment.BottomEnd)
                            .offset(x = (-16).dp, y = 40.dp)
                            .size(60.dp)
                            .zIndex(1f)
                    ) {
                        Box(
                            modifier = Modifier.fillMaxSize(),
                            contentAlignment = Alignment.Center
                        ) {
                            Icon(
                                Icons.Filled.PlayArrow,
                                contentDescription = "Play",
                                tint = Color.White,
                                modifier = Modifier.size(30.dp)
                            )
                        }
                    }
                }
            }
            
            // Course Info Card
            item {
                Card(
                    modifier = Modifier
                        .fillMaxWidth()
                        .offset(y = (-20).dp),
                    shape = RoundedCornerShape(topStart = 24.dp, topEnd = 24.dp),
                    colors = CardDefaults.cardColors(containerColor = Color.White),
                    elevation = CardDefaults.cardElevation(defaultElevation = 4.dp)
                ) {
                    Column(
                        modifier = Modifier
                            .fillMaxWidth()
                            .padding(20.dp),
                        verticalArrangement = Arrangement.spacedBy(12.dp)
                    ) {
                        // Category & Title
                        Text(
                            text = course?.category ?: "Course",
                            color = Color(0xFFFFD700),
                            fontSize = 14.sp,
                            fontWeight = FontWeight.Medium
                        )
                        
                        Row(
                            modifier = Modifier.fillMaxWidth(),
                            horizontalArrangement = Arrangement.SpaceBetween,
                            verticalAlignment = Alignment.CenterVertically
                        ) {
                            Text(
                                text = course?.title ?: "Course Title",
                                style = MaterialTheme.typography.headlineSmall,
                                fontWeight = FontWeight.Bold,
                                modifier = Modifier.weight(1f),
                                maxLines = 2,
                                overflow = TextOverflow.Ellipsis
                            )
                            // Favorite icon
                            IconButton(
                                onClick = {
                                    if (isFavorited) {
                                        favoriteViewModel.removeFavorite(courseId)
                                    } else {
                                        favoriteViewModel.addFavorite(courseId)
                                    }
                                    isFavorited = !isFavorited
                                }
                            ) {
                                Icon(
                                    Icons.Filled.Favorite,
                                    contentDescription = "Toggle Favorite",
                                    tint = if (isFavorited) Color(0xFFFF0000) else Color(0xFF999999),
                                    modifier = Modifier.size(24.dp)
                                )
                            }
                            course?.let { currentCourse ->
                                val rating = currentCourse.rating
                                if (rating > 0) {
                                    Row(
                                        verticalAlignment = Alignment.CenterVertically,
                                        horizontalArrangement = Arrangement.spacedBy(4.dp)
                                    ) {
                                        Icon(
                                            Icons.Filled.Star,
                                            contentDescription = null,
                                            tint = Color(0xFFFFD700),
                                            modifier = Modifier.size(16.dp)
                                        )
                                        Text(
                                            text = String.format(Locale.getDefault(), "%.1f", rating),
                                            fontSize = 14.sp,
                                            fontWeight = FontWeight.Medium
                                        )
                                    }
                                }
                            }
                        }
                        
                        // Price
                        Row(
                            modifier = Modifier.fillMaxWidth(),
                            horizontalArrangement = Arrangement.SpaceBetween,
                            verticalAlignment = Alignment.CenterVertically
                        ) {
                            course?.let { currentCourse ->
                                val enrolledCount = currentCourse.enrolledStudents
                                if (enrolledCount > 0) {
                                    Row(verticalAlignment = Alignment.CenterVertically) {
                                        Icon(
                                            Icons.Filled.Person,
                                            contentDescription = null,
                                            tint = Color(0xFF666666),
                                            modifier = Modifier.size(16.dp)
                                        )
                                        Spacer(modifier = Modifier.width(4.dp))
                                        Text(
                                            "$enrolledCount enrolled",
                                            fontSize = 12.sp,
                                            color = Color(0xFF666666)
                                        )
                                    }
                                }
                            }
                            Spacer(modifier = Modifier.weight(1f))
                            Text(
                                text = "${course?.price?.toInt() ?: 0} EGP",
                                fontSize = 16.sp,
                                fontWeight = FontWeight.Bold,
                                color = Color(0xFF1A1A2E)
                            )
                        }
                        
                        // About/Start Course or Pay Buttons
                        Row(
                            modifier = Modifier.fillMaxWidth(),
                            horizontalArrangement = Arrangement.spacedBy(12.dp)
                        ) {
                            // About tab - always visible
                            Button(
                                onClick = { selectedTab = 0 },
                                modifier = Modifier.weight(1f),
                                colors = ButtonDefaults.buttonColors(
                                    containerColor = if (selectedTab == 0) Color(0xFFCCCCCC) else Color(0xFFF5F5F5)
                                ),
                                shape = RoundedCornerShape(8.dp)
                            ) {
                                Text(
                                    "About",
                                    color = if (selectedTab == 0) Color.White else Color.Black
                                )
                            }
                            // Add Code tab (if not enrolled) or Start Course tab (if enrolled or instructor owns course)
                            val isInstructorOwner = isInstructor && course?.instructorId == currentUser?.uid
                            if (!isEnrolled && !isInstructorOwner) {
                                Button(
                                    onClick = { 
                                        showEnrollmentCodeDialog = true
                                    },
                                    modifier = Modifier.weight(1f),
                                    colors = ButtonDefaults.buttonColors(
                                        containerColor = Color(0xFFFF6B35)
                                    ),
                                    shape = RoundedCornerShape(8.dp)
                                ) {
                                    Text(
                                        "Add Code",
                                        color = Color.White
                                    )
                                }
                            } else {
                                // Start Course tab (shows Videos when clicked)
                                Button(
                                    onClick = { selectedTab = 1 },
                                    modifier = Modifier.weight(1f),
                                    colors = ButtonDefaults.buttonColors(
                                        containerColor = if (selectedTab == 1) Color(0xFF4CAF50) else Color(0xFFF5F5F5)
                                    ),
                                    shape = RoundedCornerShape(8.dp)
                                ) {
                                    Text(
                                        "Start Course",
                                        color = if (selectedTab == 1) Color.White else Color.Black
                                    )
                                }
                            }
                        }
                        
                        // Description
                        if (selectedTab == 0) {
                            Text(
                                text = if (isDescriptionExpanded) fullDescription else shortDescription,
                                fontSize = 14.sp,
                                color = Color(0xFF666666),
                                lineHeight = 20.sp
                            )
                            if (!isDescriptionExpanded) {
                                TextButton(
                                    onClick = { isDescriptionExpanded = true },
                                    modifier = Modifier.padding(start = 0.dp)
                                ) {
                                    Text(stringResource(R.string.course_read_more), color = Color(0xFF2196F3))
                                }
                            }
                        }
                        
                        // Videos Section (shown when Start Course tab is selected)
                        // Only show videos, no instructor section
                        // Allow access if enrolled OR current user is the instructor who owns the course
                        val isInstructorOwnerForVideos = isInstructor && course?.instructorId == currentUser?.uid
                        if (selectedTab == 1 && (isEnrolled || isInstructorOwnerForVideos)) {
                            Column(
                                modifier = Modifier.fillMaxWidth(),
                                verticalArrangement = Arrangement.spacedBy(16.dp)
                            ) {
                                Text(
                                    text = "Videos",
                                    style = MaterialTheme.typography.titleLarge,
                                    fontWeight = FontWeight.Bold,
                                    color = Color(0xFF1A1A2E)
                                )

                                val videoItems = course?.videoItems ?: emptyList()
                                val legacyVideos = course?.videos ?: emptyList()

                                val videosToShow: List<Pair<String, String>> =
                                    if (videoItems.isNotEmpty()) {
                                        videoItems.mapIndexed { index, v ->
                                            val title = if (v.title.isNotBlank()) v.title else "Video ${index + 1}"
                                            title to v.url
                                        }
                                    } else {
                                        legacyVideos.mapIndexed { index, url ->
                                            "Video ${index + 1}" to url
                                        }
                                    }

                                if (videosToShow.isEmpty()) {
                                    Text(
                                        text = "No videos available for this course yet.",
                                        fontSize = 14.sp,
                                        color = Color(0xFF666666),
                                        modifier = Modifier.padding(vertical = 16.dp)
                                    )
                                } else {
                                    Column(
                                        verticalArrangement = Arrangement.spacedBy(12.dp)
                                    ) {
                                        videosToShow.forEach { (title, videoUrl) ->
                                            Card(
                                                modifier = Modifier
                                                    .fillMaxWidth()
                                                    .clickable {
                                                        try {
                                                            val intent = Intent(Intent.ACTION_VIEW, Uri.parse(videoUrl))
                                                            intent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
                                                            context.startActivity(intent)
                                                        } catch (e: Exception) {
                                                            android.util.Log.e("CourseDetailsScreen", "Error opening video URL: ${e.message}")
                                                        }
                                                    },
                                                colors = CardDefaults.cardColors(
                                                    containerColor = Color.White
                                                ),
                                                elevation = CardDefaults.cardElevation(defaultElevation = 2.dp)
                                            ) {
                                                Row(
                                                    modifier = Modifier
                                                        .fillMaxWidth()
                                                        .padding(16.dp),
                                                    verticalAlignment = Alignment.CenterVertically,
                                                    horizontalArrangement = Arrangement.spacedBy(12.dp)
                                                ) {
                                                    Icon(
                                                        Icons.Filled.PlayArrow,
                                                        contentDescription = "Play Video",
                                                        tint = Color(0xFFFF6B35),
                                                        modifier = Modifier.size(32.dp)
                                                    )
                                                    Column(
                                                        modifier = Modifier.weight(1f)
                                                    ) {
                                                        Text(
                                                            text = title,
                                                            fontSize = 16.sp,
                                                            fontWeight = FontWeight.Bold,
                                                            color = Color(0xFF1A1A2E)
                                                        )
                                                        Text(
                                                            text = videoUrl,
                                                            fontSize = 12.sp,
                                                            color = Color(0xFF666666),
                                                            maxLines = 1,
                                                            overflow = TextOverflow.Ellipsis
                                                        )
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
            
            // Instructor Section - Only show when NOT in Start Course tab (selectedTab != 1)
            if (selectedTab != 1) {
                item {
                    Column(
                        modifier = Modifier
                            .fillMaxWidth()
                            .padding(horizontal = 20.dp, vertical = 16.dp),
                        verticalArrangement = Arrangement.spacedBy(12.dp)
                    ) {
                        Text(
                            text = stringResource(R.string.course_instructor),
                            style = MaterialTheme.typography.titleLarge,
                            fontWeight = FontWeight.Bold
                        )
                        Row(
                            verticalAlignment = Alignment.CenterVertically,
                            horizontalArrangement = Arrangement.spacedBy(12.dp)
                        ) {
                            Box(
                                modifier = Modifier
                                    .size(50.dp)
                                    .clip(CircleShape)
                                    .background(Color(0xFFE0E0E0)),
                                contentAlignment = Alignment.Center
                            ) {
                                Icon(
                                    Icons.Filled.Person,
                                    contentDescription = null,
                                    tint = Color(0xFF999999),
                                    modifier = Modifier.size(30.dp)
                                )
                            }
                            Column {
                                Text(
                                    text = course?.instructorName ?: stringResource(R.string.course_instructor),
                                    style = MaterialTheme.typography.titleMedium,
                                    fontWeight = FontWeight.Bold
                                )
                                Text(
                                    text = course?.category ?: "Category",
                                    fontSize = 14.sp,
                                    color = Color(0xFF666666)
                                )
                            }
                        }
                    }
                }
            }
            
            // What You'll Get Section - Only show when NOT in Start Course tab
            if (selectedTab != 1) {
                item {
                    Column(
                        modifier = Modifier
                            .fillMaxWidth()
                            .padding(horizontal = 20.dp, vertical = 16.dp),
                        verticalArrangement = Arrangement.spacedBy(16.dp)
                    ) {
                        Text(
                            text = "What You'll Get",
                            style = MaterialTheme.typography.titleLarge,
                            fontWeight = FontWeight.Bold
                        )
                        val benefits = listOf(
                            Pair(R.drawable.ic_book, "25 Lessons"),
                            Pair(R.drawable.ic_quizzes, "100 Quizzes")
                        )
                        benefits.forEach { (iconRes, text) ->
                            Row(
                                verticalAlignment = Alignment.CenterVertically,
                                horizontalArrangement = Arrangement.spacedBy(12.dp)
                            ) {
                                Icon(
                                    painter = painterResource(id = iconRes),
                                    contentDescription = null,
                                    tint = Color(0xFFFF6B35),
                                    modifier = Modifier.size(24.dp)
                                )
                                Text(text, fontSize = 14.sp, color = Color(0xFF666666))
                            }
                        }
                    }
                }
            }
            
            // Reviews Section - Only show when NOT in Start Course tab
            if (selectedTab != 1) {
                item {
                    Column(
                        modifier = Modifier
                            .fillMaxWidth()
                            .padding(horizontal = 20.dp, vertical = 16.dp),
                        verticalArrangement = Arrangement.spacedBy(16.dp)
                    ) {
                        Row(
                            modifier = Modifier.fillMaxWidth(),
                            horizontalArrangement = Arrangement.SpaceBetween,
                            verticalAlignment = Alignment.CenterVertically
                        ) {
                            Text(
                                text = stringResource(R.string.course_reviews_count, reviews.size),
                                style = MaterialTheme.typography.titleLarge,
                                fontWeight = FontWeight.Bold
                            )
                            if (isEnrolled) {
                                Text(
                                    text = stringResource(R.string.course_add_review),
                                    color = Color(0xFFFF6B35),
                                    fontWeight = FontWeight.Bold,
                                    fontSize = 14.sp,
                                    modifier = Modifier.clickable { showAddReviewDialog = true }
                                )
                            }
                        }
                        
                        // Reviews List
                        if (reviews.isEmpty()) {
                            Text(
                                text = stringResource(R.string.course_no_reviews),
                                color = Color(0xFF666666),
                                fontSize = 14.sp,
                                modifier = Modifier.padding(vertical = 16.dp)
                            )
                        }
                    }
                }
                
                // Reviews Items - Only show when NOT in Start Course tab
                items(reviews.size) { index ->
                    val review = reviews[index]
                    ReviewItem(
                        name = review.studentName,
                        rating = review.rating,
                        review = review.comment.ifEmpty { "No comment" }
                    )
                }
            }
            
            item {
                Spacer(modifier = Modifier.height(80.dp)) // Space for bottom button
            }
        }
        
        // Add Review Dialog (outside LazyColumn)
        if (showAddReviewDialog) {
            AddReviewDialog(
                onDismiss = { 
                    showAddReviewDialog = false
                    reviewViewModel.resetReviewState()
                },
                onSubmit = { rating, comment ->
                    reviewViewModel.addReview(courseId, rating, comment)
                    showAddReviewDialog = false
                },
                isLoading = reviewState is ReviewState.Loading
            )
        }
        
        // Enrollment Code Dialog
        val enrollmentState by enrollmentViewModel.enrollmentState.collectAsState()
        if (showEnrollmentCodeDialog) {
            EnrollmentCodeDialog(
                onDismiss = { 
                    showEnrollmentCodeDialog = false
                    enrollmentViewModel.resetEnrollmentState()
                },
                onConfirm = { code ->
                    enrollmentViewModel.enrollInCourseWithCode(courseId, code)
                },
                isLoading = enrollmentState is com.bahy.elno5ba.ui.viewmodel.EnrollmentState.Loading,
                errorMessage = if (enrollmentState is com.bahy.elno5ba.ui.viewmodel.EnrollmentState.Error) {
                    (enrollmentState as com.bahy.elno5ba.ui.viewmodel.EnrollmentState.Error).message
                } else null
            )
        }
        
        // Handle enrollment success
        LaunchedEffect(enrollmentState) {
            if (enrollmentState is com.bahy.elno5ba.ui.viewmodel.EnrollmentState.Success) {
                showEnrollmentCodeDialog = false
                isEnrolled = true
                enrollmentViewModel.resetEnrollmentState()
            }
        }
        
        // No bottom button needed - Start Course is now a tab
        
        // Bottom Navigation Bar
        NavigationBar(
            containerColor = Color.White,
            modifier = Modifier
                .fillMaxWidth()
                .windowInsetsPadding(WindowInsets.navigationBars)
        ) {
            NavigationBarItem(
                selected = selectedNavTab == 0,
                onClick = { selectedNavTab = 0; onOpenHome() },
                icon = {
                    Icon(
                        painter = painterResource(id = R.drawable.ic_nav_for_you),
                        contentDescription = "For You",
                        tint = if (selectedNavTab == 0) Color(0xFF1A1A2E) else Color(0xFF999999),
                        modifier = Modifier.size(24.dp)
                    )
                },
                label = { Text("For You", fontSize = 12.sp, color = if (selectedNavTab == 0) Color(0xFF1A1A2E) else Color(0xFF999999)) }
            )
            NavigationBarItem(
                selected = selectedNavTab == 1,
                onClick = { selectedNavTab = 1; onOpenCourses() },
                icon = {
                    Icon(
                        painter = painterResource(id = R.drawable.ic_nav_courses),
                        contentDescription = "Courses",
                        tint = if (selectedNavTab == 1) Color(0xFF1A1A2E) else Color(0xFF999999),
                        modifier = Modifier.size(24.dp)
                    )
                },
                label = { Text("Courses", fontSize = 12.sp, color = if (selectedNavTab == 1) Color(0xFF1A1A2E) else Color(0xFF999999)) }
            )
            NavigationBarItem(
                selected = selectedNavTab == 2,
                onClick = { selectedNavTab = 2; onOpenFavourites() },
                icon = {
                    Icon(
                        painter = painterResource(id = R.drawable.ic_nav_favorite),
                        contentDescription = "Favorite",
                        tint = if (selectedNavTab == 2) Color(0xFF1A1A2E) else Color(0xFF999999),
                        modifier = Modifier.size(24.dp)
                    )
                },
                label = { Text("Favorite", fontSize = 12.sp, color = if (selectedNavTab == 2) Color(0xFF1A1A2E) else Color(0xFF999999)) }
            )
            NavigationBarItem(
                selected = selectedNavTab == 3,
                onClick = { selectedNavTab = 3; onOpenProfile() },
                icon = {
                    Icon(
                        painter = painterResource(id = R.drawable.ic_nav_profile),
                        contentDescription = "Profile",
                        tint = if (selectedNavTab == 3) Color(0xFF1A1A2E) else Color(0xFF999999),
                        modifier = Modifier.size(24.dp)
                    )
                },
                label = { Text("Profile", fontSize = 12.sp, color = if (selectedNavTab == 3) Color(0xFF1A1A2E) else Color(0xFF999999)) }
            )
        }
    }
}

@Composable
private fun ReviewItem(name: String, rating: Double, review: String) {
    Row(
        modifier = Modifier.fillMaxWidth(),
        horizontalArrangement = Arrangement.spacedBy(12.dp)
    ) {
        Box(
            modifier = Modifier
                .size(40.dp)
                .clip(CircleShape)
                .background(Color(0xFFE0E0E0)),
            contentAlignment = Alignment.Center
        ) {
            Icon(
                Icons.Filled.Person,
                contentDescription = null,
                tint = Color(0xFF999999),
                modifier = Modifier.size(24.dp)
            )
        }
        Column(
            modifier = Modifier.weight(1f),
            verticalArrangement = Arrangement.spacedBy(4.dp)
        ) {
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically
            ) {
                Text(
                    text = name,
                    fontWeight = FontWeight.Bold,
                    fontSize = 14.sp
                )
                Card(
                    shape = RoundedCornerShape(12.dp),
                    colors = CardDefaults.cardColors(containerColor = Color(0xFFF5F5F5))
                ) {
                    Row(
                        modifier = Modifier.padding(horizontal = 8.dp, vertical = 4.dp),
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Icon(
                            Icons.Filled.Star,
                            contentDescription = null,
                            tint = Color(0xFFFFD700),
                            modifier = Modifier.size(14.dp)
                        )
                        Text(
                            text = "$rating",
                            fontSize = 12.sp,
                            fontWeight = FontWeight.Bold
                        )
                    }
                }
            }
            Text(
                text = review,
                fontSize = 13.sp,
                color = Color(0xFF666666),
                lineHeight = 18.sp
            )
        }
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Preview(showBackground = true)
@Composable
private fun PreviewCourseDetails() {
    // Preview without ViewModel - use mock data
    val mockCourse = remember {
        com.bahy.elno5ba.data.model.Course(
            id = "1",
            title = "Introduction to Graphic Design",
            category = "Graphic Design",
            price = 500.0,
            description = "Learn the fundamentals of graphic design. This comprehensive course covers everything from basic principles to advanced techniques. You'll learn about color theory, typography, layout design, and much more. Perfect for beginners and intermediate designers looking to enhance their skills.",
            coverImageUrl = "",
            introVideoUrl = "",
            instructorId = "instructor1",
            instructorName = "Hana Azzam",
            rating = 4.2,
            totalRatings = 120,
            enrolledStudents = 500,
            isPublished = true
        )
    }
    
    var selectedTab by remember { mutableIntStateOf(0) }
    var isDescriptionExpanded by remember { mutableStateOf(false) }
    var selectedNavTab by remember { mutableIntStateOf(1) }
    
    val fullDescription = mockCourse.description
    val shortDescription = fullDescription.take(150) + if (fullDescription.length > 150) "..." else ""
    
    Column(
        modifier = Modifier
            .fillMaxSize()
            .windowInsetsPadding(WindowInsets.statusBars)
    ) {
        LazyColumn(
            modifier = Modifier
                .weight(1f)
                .windowInsetsPadding(WindowInsets.navigationBars),
            contentPadding = PaddingValues(bottom = 8.dp)
        ) {
            // Header Image
            item {
                Box(modifier = Modifier.fillMaxWidth().height(280.dp)) {
                    IconButton(
                        onClick = { },
                        modifier = Modifier
                            .padding(16.dp)
                            .zIndex(2f)
                    ) {
                        Card(
                            shape = CircleShape,
                            colors = CardDefaults.cardColors(containerColor = Color(0xFFFFD700)),
                            modifier = Modifier.size(40.dp)
                        ) {
                            Box(
                                modifier = Modifier.fillMaxSize(),
                                contentAlignment = Alignment.Center
                            ) {
                                Icon(
                                    Icons.AutoMirrored.Filled.ArrowBack,
                                    contentDescription = "Back",
                                    tint = Color.White,
                                    modifier = Modifier.size(24.dp)
                                )
                            }
                        }
                    }
                    
                    Image(
                        painter = painterResource(id = R.drawable.ic_launcher_foreground),
                        contentDescription = "Course Header",
                        modifier = Modifier
                            .fillMaxWidth()
                            .height(280.dp),
                        contentScale = ContentScale.Crop
                    )
                    
                    Card(
                        shape = CircleShape,
                        colors = CardDefaults.cardColors(containerColor = Color(0xFFFF6B35)),
                        modifier = Modifier
                            .align(Alignment.BottomEnd)
                            .offset(x = (-16).dp, y = 40.dp)
                            .size(60.dp)
                            .zIndex(1f)
                    ) {
                        Box(
                            modifier = Modifier.fillMaxSize(),
                            contentAlignment = Alignment.Center
                        ) {
                            Icon(
                                Icons.Filled.PlayArrow,
                                contentDescription = "Play",
                                tint = Color.White,
                                modifier = Modifier.size(30.dp)
                            )
                        }
                    }
                }
            }
            
            // Course Info Card
            item {
                Card(
                    modifier = Modifier
                        .fillMaxWidth()
                        .offset(y = (-20).dp),
                    shape = RoundedCornerShape(topStart = 24.dp, topEnd = 24.dp),
                    colors = CardDefaults.cardColors(containerColor = Color.White),
                    elevation = CardDefaults.cardElevation(defaultElevation = 4.dp)
                ) {
                    Column(
                        modifier = Modifier
                            .fillMaxWidth()
                            .padding(20.dp),
                        verticalArrangement = Arrangement.spacedBy(12.dp)
                    ) {
                        Text(
                            text = mockCourse.category,
                            color = Color(0xFFFFD700),
                            fontSize = 14.sp,
                            fontWeight = FontWeight.Medium
                        )
                        
                        Row(
                            modifier = Modifier.fillMaxWidth(),
                            horizontalArrangement = Arrangement.SpaceBetween,
                            verticalAlignment = Alignment.CenterVertically
                        ) {
                            Text(
                                text = mockCourse.title,
                                style = MaterialTheme.typography.headlineSmall,
                                fontWeight = FontWeight.Bold,
                                modifier = Modifier.weight(1f),
                                maxLines = 2,
                                overflow = TextOverflow.Ellipsis
                            )
                            Row(
                                verticalAlignment = Alignment.CenterVertically,
                                horizontalArrangement = Arrangement.spacedBy(4.dp)
                            ) {
                                Icon(
                                    Icons.Filled.Star,
                                    contentDescription = null,
                                    tint = Color(0xFFFFD700),
                                    modifier = Modifier.size(16.dp)
                                )
                                Text(
                                    text = "${mockCourse.rating}",
                                    fontSize = 14.sp,
                                    fontWeight = FontWeight.Medium
                                )
                            }
                        }
                        
                        Row(
                            modifier = Modifier.fillMaxWidth(),
                            horizontalArrangement = Arrangement.spacedBy(16.dp),
                            verticalAlignment = Alignment.CenterVertically
                        ) {
                            Row(verticalAlignment = Alignment.CenterVertically) {
                                Icon(
                                    painter = painterResource(id = R.drawable.ic_video),
                                    contentDescription = null,
                                    tint = Color(0xFF666666),
                                    modifier = Modifier.size(16.dp)
                                )
                                Spacer(modifier = Modifier.width(4.dp))
                                Text("21 Class", fontSize = 12.sp, color = Color(0xFF666666))
                            }
                            Text("|", color = Color(0xFFCCCCCC))
                            Row(verticalAlignment = Alignment.CenterVertically) {
                                Icon(
                                    painter = painterResource(id = R.drawable.ic_clock),
                                    contentDescription = null,
                                    tint = Color(0xFF666666),
                                    modifier = Modifier.size(16.dp)
                                )
                                Spacer(modifier = Modifier.width(4.dp))
                                Text("42 Hours", fontSize = 12.sp, color = Color(0xFF666666))
                            }
                            Spacer(modifier = Modifier.weight(1f))
                            Text(
                                text = "${mockCourse.price.toInt()} EGP",
                                fontSize = 16.sp,
                                fontWeight = FontWeight.Bold,
                                color = Color(0xFF1A1A2E)
                            )
                        }
                        
                        Row(
                            modifier = Modifier.fillMaxWidth(),
                            horizontalArrangement = Arrangement.spacedBy(12.dp)
                        ) {
                            Button(
                                onClick = { selectedTab = 0 },
                                modifier = Modifier.weight(1f),
                                colors = ButtonDefaults.buttonColors(
                                    containerColor = if (selectedTab == 0) Color(0xFFCCCCCC) else Color(0xFFF5F5F5)
                                ),
                                shape = RoundedCornerShape(8.dp)
                            ) {
                                Text(
                                    "About",
                                    color = if (selectedTab == 0) Color.White else Color.Black
                                )
                            }
                            Button(
                                onClick = { selectedTab = 1 },
                                modifier = Modifier.weight(1f),
                                colors = ButtonDefaults.buttonColors(
                                    containerColor = if (selectedTab == 1) Color(0xFFDC143C) else Color(0xFFF5F5F5)
                                ),
                                shape = RoundedCornerShape(8.dp)
                            ) {
                                Text(
                                    "Pay",
                                    color = if (selectedTab == 1) Color.White else Color.Black
                                )
                            }
                        }
                        
                        if (selectedTab == 0) {
                            Text(
                                text = if (isDescriptionExpanded) fullDescription else shortDescription,
                                fontSize = 14.sp,
                                color = Color(0xFF666666),
                                lineHeight = 20.sp
                            )
                            if (!isDescriptionExpanded) {
                                TextButton(
                                    onClick = { isDescriptionExpanded = true },
                                    modifier = Modifier.padding(start = 0.dp)
                                ) {
                                    Text(stringResource(R.string.course_read_more), color = Color(0xFF2196F3))
                                }
                            }
                        }
                    }
                }
            }
            
            // Instructor Section
            item {
                Column(
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(horizontal = 20.dp, vertical = 16.dp),
                    verticalArrangement = Arrangement.spacedBy(12.dp)
                ) {
                    Text(
                        text = stringResource(R.string.course_instructor),
                        style = MaterialTheme.typography.titleLarge,
                        fontWeight = FontWeight.Bold
                    )
                    Row(
                        verticalAlignment = Alignment.CenterVertically,
                        horizontalArrangement = Arrangement.spacedBy(12.dp)
                    ) {
                        Box(
                            modifier = Modifier
                                .size(50.dp)
                                .clip(CircleShape)
                                .background(Color(0xFFE0E0E0)),
                            contentAlignment = Alignment.Center
                        ) {
                            Icon(
                                Icons.Filled.Person,
                                contentDescription = null,
                                tint = Color(0xFF999999),
                                modifier = Modifier.size(30.dp)
                            )
                        }
                        Column {
                            Text(
                                text = mockCourse.instructorName,
                                style = MaterialTheme.typography.titleMedium,
                                fontWeight = FontWeight.Bold
                            )
                            Text(
                                text = mockCourse.category,
                                fontSize = 14.sp,
                                color = Color(0xFF666666)
                            )
                        }
                    }
                }
            }
            
            item {
                Spacer(modifier = Modifier.height(80.dp))
            }
        }
        
        Button(
            onClick = { },
            modifier = Modifier
                .fillMaxWidth()
                .padding(16.dp),
            colors = ButtonDefaults.buttonColors(
                containerColor = Color(0xFFFF6B35)
            ),
            shape = RoundedCornerShape(12.dp)
        ) {
            Text(
                text = "Pay Course - ${mockCourse.price.toInt()} EGP",
                color = Color.White,
                fontWeight = FontWeight.Bold,
                modifier = Modifier.weight(1f)
            )
            Icon(
                Icons.AutoMirrored.Filled.ArrowForward,
                contentDescription = null,
                tint = Color.White
            )
        }
        
        NavigationBar(
            containerColor = Color.White,
            modifier = Modifier
                .fillMaxWidth()
                .windowInsetsPadding(WindowInsets.navigationBars)
        ) {
            NavigationBarItem(
                selected = selectedNavTab == 0,
                onClick = { },
                icon = {
                    Icon(
                        painter = painterResource(id = R.drawable.ic_nav_for_you),
                        contentDescription = stringResource(R.string.nav_for_you),
                        tint = if (selectedNavTab == 0) Color(0xFF1A1A2E) else Color(0xFF999999),
                        modifier = Modifier.size(24.dp)
                    )
                },
                label = { Text(stringResource(R.string.nav_for_you), fontSize = 12.sp, color = if (selectedNavTab == 0) Color(0xFF1A1A2E) else Color(0xFF999999)) }
            )
            NavigationBarItem(
                selected = selectedNavTab == 1,
                onClick = { },
                icon = {
                    Icon(
                        painter = painterResource(id = R.drawable.ic_nav_courses),
                        contentDescription = stringResource(R.string.nav_courses),
                        tint = if (selectedNavTab == 1) Color(0xFF1A1A2E) else Color(0xFF999999),
                        modifier = Modifier.size(24.dp)
                    )
                },
                label = { Text(stringResource(R.string.nav_courses), fontSize = 12.sp, color = if (selectedNavTab == 1) Color(0xFF1A1A2E) else Color(0xFF999999)) }
            )
            NavigationBarItem(
                selected = selectedNavTab == 2,
                onClick = { },
                icon = {
                    Icon(
                        painter = painterResource(id = R.drawable.ic_nav_favorite),
                        contentDescription = stringResource(R.string.nav_favorite),
                        tint = if (selectedNavTab == 2) Color(0xFF1A1A2E) else Color(0xFF999999),
                        modifier = Modifier.size(24.dp)
                    )
                },
                label = { Text(stringResource(R.string.nav_favorite), fontSize = 12.sp, color = if (selectedNavTab == 2) Color(0xFF1A1A2E) else Color(0xFF999999)) }
            )
            NavigationBarItem(
                selected = selectedNavTab == 3,
                onClick = { },
                icon = {
                    Icon(
                        painter = painterResource(id = R.drawable.ic_nav_profile),
                        contentDescription = stringResource(R.string.nav_profile),
                        tint = if (selectedNavTab == 3) Color(0xFF1A1A2E) else Color(0xFF999999),
                        modifier = Modifier.size(24.dp)
                    )
                },
                label = { Text(stringResource(R.string.nav_profile), fontSize = 12.sp, color = if (selectedNavTab == 3) Color(0xFF1A1A2E) else Color(0xFF999999)) }
            )
        }
    }
}
