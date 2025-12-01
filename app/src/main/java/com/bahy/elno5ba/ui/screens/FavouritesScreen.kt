package com.bahy.elno5ba.ui.screens

import androidx.compose.foundation.Image
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
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.layout.WindowInsets
import androidx.compose.foundation.layout.navigationBars
import androidx.compose.foundation.layout.statusBars
import androidx.compose.foundation.layout.windowInsetsPadding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.filled.Favorite
import androidx.compose.material.icons.filled.Star
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.NavigationBar
import androidx.compose.material3.NavigationBarItem
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.material3.TopAppBarDefaults
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableIntStateOf
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
import androidx.compose.runtime.LaunchedEffect
import java.util.Locale
import androidx.compose.runtime.collectAsState
import androidx.lifecycle.viewmodel.compose.viewModel
import coil.compose.AsyncImage
import com.bahy.elno5ba.R
import com.bahy.elno5ba.ui.utils.stringResource
import com.bahy.elno5ba.data.model.Course
import com.bahy.elno5ba.ui.viewmodel.FavoriteViewModel
import com.bahy.elno5ba.ui.viewmodel.FavoriteState
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun FavouritesScreen(
    onBack: () -> Unit = {},
    onOpenCourse: (String) -> Unit = {},
    onOpenCourses: () -> Unit = {},
    onOpenProfile: () -> Unit = {},
    onOpenHome: () -> Unit = {},
    favoriteViewModel: FavoriteViewModel = viewModel()
) {
    val favoriteCourses by favoriteViewModel.favoriteCourses.collectAsState()
    val favoriteState by favoriteViewModel.favoriteState.collectAsState()
    
    // Load favorites when screen is displayed
    LaunchedEffect(Unit) {
        favoriteViewModel.loadFavoriteCourses()
    }
    
    var selectedTab by remember { mutableIntStateOf(2) } // Favourites tab is selected
    
    Column(
        modifier = Modifier
            .fillMaxSize()
            .windowInsetsPadding(WindowInsets.statusBars)
    ) {
        // Top App Bar
        TopAppBar(
            title = {
                Text(
                    text = stringResource(R.string.favourites_count, favoriteCourses.size),
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
            colors = TopAppBarDefaults.topAppBarColors(
                containerColor = Color.White
            )
        )
        
        // Favourites List
        when {
            favoriteState is FavoriteState.Loading -> {
                Box(
                    modifier = Modifier
                        .weight(1f)
                        .fillMaxWidth()
                        .background(Color(0xFFF0F4F8))
                        .windowInsetsPadding(WindowInsets.navigationBars),
                    contentAlignment = Alignment.Center
                ) {
                    CircularProgressIndicator(color = Color(0xFFFF6B35))
                }
            }
            favoriteState is FavoriteState.Error -> {
                Box(
                    modifier = Modifier
                        .weight(1f)
                        .fillMaxWidth()
                        .background(Color(0xFFF0F4F8))
                        .windowInsetsPadding(WindowInsets.navigationBars)
                        .padding(32.dp),
                    contentAlignment = Alignment.Center
                ) {
                    Column(
                        horizontalAlignment = Alignment.CenterHorizontally,
                        verticalArrangement = Arrangement.spacedBy(16.dp)
                    ) {
                        Text(
                            text = stringResource(R.string.favourites_error_loading),
                            style = MaterialTheme.typography.titleLarge,
                            color = Color(0xFFD32F2F),
                            fontWeight = FontWeight.Bold
                        )
                        Text(
                            text = (favoriteState as FavoriteState.Error).message,
                            style = MaterialTheme.typography.bodyMedium,
                            color = Color(0xFF666666),
                            textAlign = androidx.compose.ui.text.style.TextAlign.Center
                        )
                        Button(
                            onClick = { favoriteViewModel.loadFavoriteCourses() },
                            colors = ButtonDefaults.buttonColors(containerColor = Color(0xFFFF6B35))
                        ) {
                            Text(stringResource(R.string.favourites_retry), color = Color.White)
                        }
                    }
                }
            }
            favoriteCourses.isEmpty() -> {
                Box(
                    modifier = Modifier
                        .weight(1f)
                        .fillMaxWidth()
                        .background(Color(0xFFF0F4F8))
                        .windowInsetsPadding(WindowInsets.navigationBars)
                        .padding(32.dp),
                    contentAlignment = Alignment.Center
                ) {
                    Column(
                        horizontalAlignment = Alignment.CenterHorizontally,
                        verticalArrangement = Arrangement.spacedBy(16.dp)
                    ) {
                        Icon(
                            Icons.Filled.Favorite,
                            contentDescription = null,
                            modifier = Modifier.size(64.dp),
                            tint = Color(0xFF999999)
                        )
                        Text(
                            text = stringResource(R.string.favourites_no_courses),
                            style = MaterialTheme.typography.titleLarge,
                            color = Color(0xFF666666)
                        )
                        Text(
                            text = stringResource(R.string.favourites_no_courses_message),
                            style = MaterialTheme.typography.bodyMedium,
                            color = Color(0xFF999999),
                            textAlign = androidx.compose.ui.text.style.TextAlign.Center
                        )
                    }
                }
            }
            else -> {
                LazyColumn(
                    modifier = Modifier
                        .weight(1f)
                        .fillMaxWidth()
                        .background(Color(0xFFF0F4F8))
                        .windowInsetsPadding(WindowInsets.navigationBars),
                    contentPadding = PaddingValues(
                        start = 16.dp,
                        end = 16.dp,
                        top = 16.dp,
                        bottom = 8.dp
                    ),
                    verticalArrangement = Arrangement.spacedBy(12.dp)
                ) {
                    items(favoriteCourses.size) { index ->
                        val course = favoriteCourses[index]
                        FavouriteCourseCard(
                            course = course,
                            onClick = { onOpenCourse(course.id) },
                            onRemoveFavorite = { favoriteViewModel.removeFavorite(course.id) }
                        )
                    }
                }
            }
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
                onClick = { selectedTab = 0; onOpenHome() },
                icon = {
                    Icon(
                        painter = painterResource(id = R.drawable.ic_nav_for_you),
                        contentDescription = "For You",
                        tint = if (selectedTab == 0) Color(0xFF1A1A2E) else Color(0xFF999999),
                        modifier = Modifier.size(24.dp)
                    )
                },
                label = { Text(stringResource(R.string.nav_for_you), fontSize = 12.sp, color = if (selectedTab == 0) Color(0xFF1A1A2E) else Color(0xFF999999)) }
            )
            NavigationBarItem(
                selected = selectedTab == 1,
                onClick = { selectedTab = 1; onOpenCourses() },
                icon = {
                    Icon(
                        painter = painterResource(id = R.drawable.ic_nav_courses),
                        contentDescription = "Courses",
                        tint = if (selectedTab == 1) Color(0xFF1A1A2E) else Color(0xFF999999),
                        modifier = Modifier.size(24.dp)
                    )
                },
                label = { Text(stringResource(R.string.nav_courses), fontSize = 12.sp, color = if (selectedTab == 1) Color(0xFF1A1A2E) else Color(0xFF999999)) }
            )
            NavigationBarItem(
                selected = selectedTab == 2,
                onClick = { selectedTab = 2 },
                icon = {
                    Icon(
                        painter = painterResource(id = R.drawable.ic_nav_favorite),
                        contentDescription = "Favorite",
                        tint = if (selectedTab == 2) Color(0xFF1A1A2E) else Color(0xFF999999),
                        modifier = Modifier.size(24.dp)
                    )
                },
                label = { Text(stringResource(R.string.nav_favorite), fontSize = 12.sp, color = if (selectedTab == 2) Color(0xFF1A1A2E) else Color(0xFF999999)) }
            )
            NavigationBarItem(
                selected = selectedTab == 3,
                onClick = { selectedTab = 3; onOpenProfile() },
                icon = {
                    Icon(
                        painter = painterResource(id = R.drawable.ic_nav_profile),
                        contentDescription = "Profile",
                        tint = if (selectedTab == 3) Color(0xFF1A1A2E) else Color(0xFF999999),
                        modifier = Modifier.size(24.dp)
                    )
                },
                label = { Text(stringResource(R.string.nav_profile), fontSize = 12.sp, color = if (selectedTab == 3) Color(0xFF1A1A2E) else Color(0xFF999999)) }
            )
        }
    }
}

@Composable
private fun FavouriteCourseCard(
    course: Course,
    onClick: () -> Unit,
    onRemoveFavorite: () -> Unit
) {
    Card(
        modifier = Modifier
            .fillMaxWidth()
            .clickable(onClick = onClick),
        shape = RoundedCornerShape(16.dp),
        colors = CardDefaults.cardColors(containerColor = Color.White),
        elevation = CardDefaults.cardElevation(defaultElevation = 2.dp)
    ) {
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .padding(12.dp),
            horizontalArrangement = Arrangement.spacedBy(12.dp)
        ) {
            // Course Image
            Box(
                modifier = Modifier
                    .width(100.dp)
                    .height(100.dp)
                    .clip(RoundedCornerShape(12.dp))
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
                            android.util.Log.e("FavouritesScreen", "Error loading image: $coverImageUrl")
                        }
                    )
                } else {
                    Image(
                        painter = painterResource(id = R.drawable.ic_launcher_foreground),
                        contentDescription = course.title,
                        modifier = Modifier.fillMaxSize(),
                        contentScale = ContentScale.Crop
                    )
                }
            }
            
            // Course Content
            Column(
                modifier = Modifier
                    .weight(1f)
                    .fillMaxWidth(),
                verticalArrangement = Arrangement.spacedBy(4.dp)
            ) {
                // Favorite icon (top right) - filled red heart
                Box(modifier = Modifier.fillMaxWidth()) {
                    Column(modifier = Modifier.fillMaxWidth(0.85f)) {
                        // Category (orange)
                        Text(
                            text = course.category,
                            style = MaterialTheme.typography.bodySmall,
                            color = Color(0xFFFF6B35),
                            fontSize = 12.sp
                        )
                        
                        // Course Title (dark blue, bold)
                        Text(
                            text = course.title,
                            style = MaterialTheme.typography.titleMedium,
                            fontWeight = FontWeight.Bold,
                            color = Color(0xFF1A1A2E),
                            maxLines = 2,
                            overflow = TextOverflow.Ellipsis
                        )
                        
                        Spacer(modifier = Modifier.height(4.dp))
                        
                        // Price (orange) + EGP
                        Text(
                            text = "${course.price.toInt()} EGP",
                            style = MaterialTheme.typography.bodyLarge,
                            fontWeight = FontWeight.Bold,
                            color = Color(0xFFFF6B35),
                            fontSize = 16.sp
                        )
                        
                        Spacer(modifier = Modifier.height(4.dp))
                        
                        // Rating
                        if (course.rating > 0) {
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
                                    text = String.format(Locale.getDefault(), "%.1f", course.rating),
                                    style = MaterialTheme.typography.bodySmall,
                                    color = Color.Black,
                                    fontSize = 14.sp
                                )
                                if (course.enrolledStudents > 0) {
                                    Text(
                                        text = "| ${course.enrolledStudents} ${stringResource(R.string.courses_enrolled)}",
                                        style = MaterialTheme.typography.bodySmall,
                                        color = Color(0xFF666666),
                                        fontSize = 14.sp
                                    )
                                }
                            }
                        }
                    }
                    
                    // Filled red heart icon (top right)
                    IconButton(
                        onClick = onRemoveFavorite,
                        modifier = Modifier
                            .align(Alignment.TopEnd)
                            .size(24.dp)
                    ) {
                        Icon(
                            Icons.Filled.Favorite,
                            contentDescription = "Remove from Favourites",
                            tint = Color(0xFFFF0000),
                            modifier = Modifier.size(20.dp)
                        )
                    }
                }
            }
        }
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Preview(showBackground = true)
@Composable
private fun PreviewFavourites() {
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
                instructorId = "instructor2",
                instructorName = "Jane Smith",
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
                    text = "Favourites (${mockCourses.size})",
                    style = MaterialTheme.typography.titleLarge,
                    fontWeight = FontWeight.Bold,
                    color = Color(0xFF1A1A2E)
                )
            },
            colors = TopAppBarDefaults.topAppBarColors(containerColor = Color.White)
        )
        
        LazyColumn(
            modifier = Modifier
                .weight(1f)
                .fillMaxWidth()
                .background(Color(0xFFF0F4F8))
                .windowInsetsPadding(WindowInsets.navigationBars),
            contentPadding = PaddingValues(
                start = 16.dp,
                end = 16.dp,
                top = 16.dp,
                bottom = 8.dp
            ),
            verticalArrangement = Arrangement.spacedBy(12.dp)
        ) {
            items(mockCourses.size) { index ->
                val course = mockCourses[index]
                FavouriteCourseCard(
                    course = course,
                    onClick = { },
                    onRemoveFavorite = { }
                )
            }
        }
    }
}


