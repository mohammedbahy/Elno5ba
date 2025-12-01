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
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.layout.WindowInsets
import androidx.compose.foundation.layout.navigationBars
import androidx.compose.foundation.layout.statusBars
import androidx.compose.foundation.layout.windowInsetsPadding
import androidx.compose.foundation.lazy.LazyRow
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Favorite
import androidx.compose.material.icons.filled.Home
import androidx.compose.material.icons.filled.Menu
import androidx.compose.material.icons.filled.Person
import androidx.compose.material.icons.filled.Star
import androidx.compose.material.icons.filled.PlayArrow
import androidx.compose.material.icons.filled.Search
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
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.collectAsState
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
import androidx.lifecycle.viewmodel.compose.viewModel
import coil.compose.AsyncImage
import com.bahy.elno5ba.R
import com.bahy.elno5ba.ui.utils.stringResource
import com.bahy.elno5ba.data.model.Course
import com.bahy.elno5ba.ui.viewmodel.CourseViewModel
import com.bahy.elno5ba.data.repository.UserProfileRepository
import com.bahy.elno5ba.data.repository.LanguageRepository
import com.google.firebase.auth.FirebaseAuth
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.remember
import kotlinx.coroutines.launch
import android.content.Context
import androidx.compose.ui.platform.LocalContext

@Composable
fun HomeScreen(
    onOpenCourses: () -> Unit,
    onOpenFavourites: () -> Unit,
    onOpenProfile: () -> Unit,
    onOpenCourseDetails: (String) -> Unit = {},
    viewModel: CourseViewModel = viewModel()
) {
    val context = LocalContext.current
    val languageRepository = remember { LanguageRepository(context) }
    val userProfileRepository = remember { UserProfileRepository() }
    val coroutineScope = rememberCoroutineScope()
    val currentUser = FirebaseAuth.getInstance().currentUser
    
    var selectedTab by remember { mutableIntStateOf(0) }
    val courses by viewModel.courses.collectAsState()
    
    // Get user name
    var userName by remember { mutableStateOf<String>("") }
    
    // Load user name
    LaunchedEffect(Unit) {
        // Try to load from Firestore first
        val profileResult = userProfileRepository.getCurrentUserProfile()
        profileResult.fold(
            onSuccess = { profile ->
                userName = profile?.fullName?.ifEmpty {
                    currentUser?.displayName ?: currentUser?.email?.substringBefore("@") ?: "User"
                } ?: (currentUser?.displayName ?: currentUser?.email?.substringBefore("@") ?: "User")
            },
            onFailure = {
                // Fallback to Firebase Auth
                userName = currentUser?.displayName ?: currentUser?.email?.substringBefore("@") ?: "User"
            }
        )
    }
    
    // Get greeting text based on language
    val greetingText = remember(languageRepository.getSelectedLanguage()) {
        if (languageRepository.getSelectedLanguage() == "ar") {
            "مرحباً"
        } else {
            "Hi"
        }
    }
    
    // Load courses when screen is displayed
    LaunchedEffect(Unit) {
        viewModel.loadAllCourses()
    }
    
    Column(
        modifier = Modifier
            .fillMaxSize()
            .windowInsetsPadding(WindowInsets.statusBars)
    ) {
        // Content
        Column(
            modifier = Modifier
                .weight(1f)
                .fillMaxWidth()
                .verticalScroll(rememberScrollState())
                .padding(horizontal = 16.dp)
                .windowInsetsPadding(WindowInsets.navigationBars),
            verticalArrangement = Arrangement.spacedBy(16.dp)
        ) {
            Spacer(modifier = Modifier.height(16.dp))
            
            // Header with greeting and logo
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically
            ) {
                Column {
                    Text(
                        text = "$greetingText, $userName",
                        style = MaterialTheme.typography.headlineSmall,
                        fontWeight = FontWeight.Bold
                    )
                }
                // Logo small
                Image(
                    painter = painterResource(id = R.drawable.logo),
                    contentDescription = "Logo",
                    modifier = Modifier.size(60.dp),
                    contentScale = ContentScale.Fit
                )
            }
            
            // Popular Courses Section
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically
            ) {
                Text(
                    text = stringResource(R.string.home_popular_courses),
                    style = MaterialTheme.typography.titleLarge,
                    fontWeight = FontWeight.Bold
                )
                Text(
                    text = stringResource(R.string.home_see_all) + " >",
                    color = Color(0xFFFF6B35),
                    fontWeight = FontWeight.Bold,
                    fontSize = 14.sp,
                    modifier = Modifier.clickable { onOpenCourses() }
                )
            }
            
            // Popular Courses List
            LazyRow(
                horizontalArrangement = Arrangement.spacedBy(12.dp)
            ) {
                items(courses.take(5)) { course ->
                    PopularCourseCard(
                        course = course,
                        onClick = { onOpenCourseDetails(course.id) }
                    )
                }
            }
            
            Spacer(modifier = Modifier.height(16.dp))
        }
        
        // Bottom Navigation Bar
        NavigationBar(
            containerColor = Color.White,
            modifier = Modifier
                .fillMaxWidth()
                .windowInsetsPadding(WindowInsets.navigationBars)
        ) {
            NavigationBarItem(
                selected = selectedTab == 0,
                onClick = { selectedTab = 0 },
                icon = {
                    Icon(
                        painter = painterResource(id = R.drawable.ic_nav_for_you),
                        contentDescription = "For You",
                        tint = if (selectedTab == 0) Color(0xFFFF6B35) else Color(0xFF999999),
                        modifier = Modifier.size(24.dp)
                    )
                },
                label = { Text(stringResource(R.string.nav_for_you), fontSize = 12.sp, color = if (selectedTab == 0) Color(0xFFFF6B35) else Color(0xFF999999)) }
            )
            NavigationBarItem(
                selected = selectedTab == 1,
                onClick = { selectedTab = 1; onOpenCourses() },
                icon = {
                    Icon(
                        painter = painterResource(id = R.drawable.ic_nav_courses),
                        contentDescription = stringResource(R.string.nav_courses),
                        tint = if (selectedTab == 1) Color(0xFFFF6B35) else Color(0xFF999999),
                        modifier = Modifier.size(24.dp)
                    )
                },
                label = { Text(stringResource(R.string.nav_courses), fontSize = 12.sp, color = if (selectedTab == 1) Color(0xFFFF6B35) else Color(0xFF999999)) }
            )
            NavigationBarItem(
                selected = selectedTab == 2,
                onClick = { selectedTab = 2; onOpenFavourites() },
                icon = {
                    Icon(
                        painter = painterResource(id = R.drawable.ic_nav_favorite),
                        contentDescription = stringResource(R.string.nav_favorite),
                        tint = if (selectedTab == 2) Color(0xFFFF6B35) else Color(0xFF999999),
                        modifier = Modifier.size(24.dp)
                    )
                },
                label = { Text(stringResource(R.string.nav_favorite), fontSize = 12.sp, color = if (selectedTab == 2) Color(0xFFFF6B35) else Color(0xFF999999)) }
            )
            NavigationBarItem(
                selected = selectedTab == 3,
                onClick = { selectedTab = 3; onOpenProfile() },
                icon = {
                    Icon(
                        painter = painterResource(id = R.drawable.ic_nav_profile),
                        contentDescription = stringResource(R.string.nav_profile),
                        tint = if (selectedTab == 3) Color(0xFFFF6B35) else Color(0xFF999999),
                        modifier = Modifier.size(24.dp)
                    )
                },
                label = { Text(stringResource(R.string.nav_profile), fontSize = 12.sp, color = if (selectedTab == 3) Color(0xFFFF6B35) else Color(0xFF999999)) }
            )
        }
    }
}

@Composable
private fun PopularCourseCard(course: Course, onClick: () -> Unit) {
    Card(
        modifier = Modifier
            .width(200.dp)
            .height(280.dp) // Fixed height for all cards
            .clickable(onClick = onClick),
        shape = RoundedCornerShape(16.dp),
        colors = CardDefaults.cardColors(containerColor = Color.White),
        elevation = CardDefaults.cardElevation(defaultElevation = 4.dp)
    ) {
        Column(
            modifier = Modifier.fillMaxSize() // Ensure column fills card
        ) {
            // Course Image - fixed height
            Box(
                modifier = Modifier
                    .fillMaxWidth()
                    .height(120.dp)
                    .background(Color(0xFFE0E0E0))
            ) {
                val coverImageUrl = course.coverImageUrl.trim()
                if (coverImageUrl.isNotEmpty() && coverImageUrl.isNotBlank()) {
                    AsyncImage(
                        model = coverImageUrl,
                        contentDescription = course.title,
                        modifier = Modifier
                            .fillMaxSize()
                            .clip(RoundedCornerShape(topStart = 16.dp, topEnd = 16.dp)),
                        contentScale = ContentScale.Crop,
                        placeholder = painterResource(id = R.drawable.ic_launcher_foreground),
                        error = painterResource(id = R.drawable.ic_launcher_foreground),
                        onError = {
                            android.util.Log.e("HomeScreen", "Error loading image: $coverImageUrl")
                        }
                    )
                } else {
                    Image(
                        painter = painterResource(id = R.drawable.ic_launcher_foreground),
                        contentDescription = course.title,
                        modifier = Modifier
                            .fillMaxSize()
                            .clip(RoundedCornerShape(topStart = 16.dp, topEnd = 16.dp)),
                        contentScale = ContentScale.Crop
                    )
                }
                // Favorite Icon
                IconButton(
                    onClick = { /* TODO: Add to favorites */ },
                    modifier = Modifier
                        .align(Alignment.TopEnd)
                        .padding(8.dp)
                ) {
                    Icon(
                        Icons.Filled.Favorite,
                        contentDescription = "Favorite",
                        tint = Color(0xFFD32F2F),
                        modifier = Modifier.size(20.dp)
                    )
                }
            }
            
            // Course Details - fixed height section
            Column(
                modifier = Modifier
                    .fillMaxWidth()
                    .weight(1f) // Take remaining space
                    .padding(12.dp)
            ) {
                // Rating
                Row(verticalAlignment = Alignment.CenterVertically) {
                    val fullStars = course.rating.toInt()
                    val hasHalfStar = (course.rating - fullStars) >= 0.5
                    repeat(fullStars.coerceAtMost(5)) {
                        Icon(
                            Icons.Filled.Star,
                            contentDescription = null,
                            tint = Color(0xFFFFD700),
                            modifier = Modifier.size(14.dp)
                        )
                    }
                    repeat(5 - fullStars - if (hasHalfStar) 1 else 0) {
                        Icon(
                            Icons.Filled.Star,
                            contentDescription = null,
                            tint = Color(0xFFCCCCCC),
                            modifier = Modifier.size(14.dp)
                        )
                    }
                }
                
                Spacer(modifier = Modifier.height(8.dp))
                
                // Course Title - limit to 2 lines
                Text(
                    text = course.title,
                    style = MaterialTheme.typography.titleMedium,
                    fontWeight = FontWeight.Bold,
                    maxLines = 2,
                    overflow = TextOverflow.Ellipsis
                )
                
                Spacer(modifier = Modifier.height(4.dp))
                
                // Instructor and Price
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.SpaceBetween,
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Icon(
                            Icons.Filled.Person,
                            contentDescription = null,
                            tint = Color(0xFF666666),
                            modifier = Modifier.size(14.dp)
                        )
                        Spacer(modifier = Modifier.width(4.dp))
                        Text(
                            text = course.instructorName.ifEmpty { "Instructor" },
                            style = MaterialTheme.typography.bodySmall,
                            color = Color(0xFF666666),
                            fontWeight = FontWeight.Bold,
                            maxLines = 1,
                            overflow = TextOverflow.Ellipsis
                        )
                    }
                    Text(
                        text = "${course.price.toInt()} EGP",
                        style = MaterialTheme.typography.bodyMedium,
                        color = Color(0xFFFF6B35),
                        fontWeight = FontWeight.Bold
                    )
                }
            }
        }
    }
}

@Preview(showBackground = true)
@Composable
private fun PreviewHome() { HomeScreen(onOpenCourses = {}, onOpenFavourites = {}, onOpenProfile = {}) }


