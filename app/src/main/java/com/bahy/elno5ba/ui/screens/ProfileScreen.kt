package com.bahy.elno5ba.ui.screens

import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.navigationBarsPadding
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.statusBarsPadding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.automirrored.filled.ArrowForward
import androidx.compose.material.icons.filled.Person
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.NavigationBar
import androidx.compose.material3.NavigationBarItem
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBar
import androidx.compose.material3.TopAppBarDefaults
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.layout.ContentScale
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.tooling.preview.Preview
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.lifecycle.viewmodel.compose.viewModel
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.rememberCoroutineScope
import coil.compose.AsyncImage
import com.bahy.elno5ba.R
import com.bahy.elno5ba.data.repository.CourseRepository
import com.bahy.elno5ba.data.repository.LanguageRepository
import com.bahy.elno5ba.data.repository.UserProfileRepository
import com.bahy.elno5ba.ui.utils.stringResource
import com.bahy.elno5ba.ui.viewmodel.ProfileViewModel
import com.google.firebase.auth.FirebaseAuth
import kotlinx.coroutines.launch

data class ProfileMenuItem(
    val id: String,
    val title: String,
    val iconRes: Int? = null,
    val iconVector: androidx.compose.ui.graphics.vector.ImageVector? = null,
    val rightText: String? = null,
    val onClick: () -> Unit
)

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun ProfileScreen(
    onBack: () -> Unit = {},
    onLanguage: () -> Unit = {},
    onLogout: () -> Unit = {},
    onOpenCourses: () -> Unit = {},
    onOpenFavourites: () -> Unit = {},
    onOpenHome: () -> Unit = {},
    onInstructorPortal: () -> Unit = {},
    onInstructorCourses: () -> Unit = {}
) {
    val context = LocalContext.current
    val languageRepository = remember { LanguageRepository(context) }
    val profileViewModel: ProfileViewModel = viewModel()
    val profileImageUrl by profileViewModel.profileImageUrl.collectAsState()
    val userProfileRepository = UserProfileRepository()
    val courseRepository = CourseRepository()
    val coroutineScope = rememberCoroutineScope()
    
    val currentUser = FirebaseAuth.getInstance().currentUser
    var userName by remember { mutableStateOf(currentUser?.displayName ?: currentUser?.email?.substringBefore("@") ?: "User") }
    var userEmail by remember { mutableStateOf(currentUser?.email ?: "No email") }
    
    // Dialog for instructor permission error
    var showInstructorErrorDialog by remember { mutableStateOf(false) }
    
    // Load profile data when screen becomes visible (including when returning from EditProfile)
    LaunchedEffect(Unit) {
        android.util.Log.d("ProfileScreen", "Loading profile data...")
        // Try to load from Firestore first, fallback to Firebase Auth
        val profileResult = userProfileRepository.getCurrentUserProfile()
        profileResult.fold(
            onSuccess = { profile ->
                profile?.let {
                    android.util.Log.d("ProfileScreen", "Profile loaded from Firestore: ${it.fullName}, ${it.email}")
                    userName = it.fullName.ifEmpty { 
                        currentUser?.displayName ?: currentUser?.email?.substringBefore("@") ?: "User"
                    }
                    userEmail = it.email.ifEmpty { 
                        currentUser?.email ?: "No email"
                    }
                } ?: run {
                    // No profile in Firestore, use Firebase Auth
                    android.util.Log.d("ProfileScreen", "No profile in Firestore, using Firebase Auth")
                    val updatedUser = FirebaseAuth.getInstance().currentUser
                    updatedUser?.let {
                        userName = it.displayName ?: it.email?.substringBefore("@") ?: "User"
                        userEmail = it.email ?: "No email"
                    }
                }
            },
            onFailure = { exception ->
                android.util.Log.e("ProfileScreen", "Error loading profile: ${exception.message}", exception)
                // Error loading from Firestore, use Firebase Auth
                val updatedUser = FirebaseAuth.getInstance().currentUser
                updatedUser?.let {
                    userName = it.displayName ?: it.email?.substringBefore("@") ?: "User"
                    userEmail = it.email ?: "No email"
                }
            }
        )
    }
    
    val selectedTab = 3 // Profile tab is selected
    
    Column(
        modifier = Modifier
            .fillMaxSize()
            .statusBarsPadding()
    ) {
        // Top App Bar
        TopAppBar(
            title = {
                Text(
                    text = "Profile",
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
        
        // Content
        LazyColumn(
            modifier = Modifier
                .weight(1f)
                .fillMaxWidth()
                .background(Color(0xFFF5F5F5)),
            contentPadding = PaddingValues(
                start = 16.dp,
                end = 16.dp,
                top = 16.dp,
                bottom = 8.dp
            ),
            verticalArrangement = Arrangement.spacedBy(16.dp)
        ) {
            // Profile Card
            item {
                Card(
                    modifier = Modifier.fillMaxWidth(),
                    shape = RoundedCornerShape(16.dp),
                    colors = CardDefaults.cardColors(containerColor = Color(0xFFF8F9FA)),
                    elevation = CardDefaults.cardElevation(defaultElevation = 2.dp)
                ) {
                    Column(
                        modifier = Modifier
                            .fillMaxWidth()
                            .padding(24.dp),
                        horizontalAlignment = Alignment.CenterHorizontally,
                        verticalArrangement = Arrangement.spacedBy(12.dp)
                    ) {
                        // Profile Picture Circle
                        Box(
                            modifier = Modifier
                                .size(100.dp)
                                .clip(CircleShape)
                                .background(Color(0xFFCCCCCC)),
                            contentAlignment = Alignment.Center
                        ) {
                            if (profileImageUrl != null) {
                                // Display profile image if available
                                AsyncImage(
                                    model = profileImageUrl,
                                    contentDescription = "Profile Picture",
                                    modifier = Modifier
                                        .fillMaxSize()
                                        .clip(CircleShape),
                                    contentScale = androidx.compose.ui.layout.ContentScale.Crop
                                )
                            } else {
                                // Display default icon if no image
                                Icon(
                                    Icons.Filled.Person,
                                    contentDescription = "Profile Picture",
                                    tint = Color(0xFF666666),
                                    modifier = Modifier.size(60.dp)
                                )
                            }
                        }
                        
                        // Name
                        Text(
                            text = userName,
                            style = MaterialTheme.typography.headlineSmall,
                            fontWeight = FontWeight.Bold,
                            color = Color(0xFF1A1A2E)
                        )
                        
                        // Email
                        Text(
                            text = userEmail,
                            style = MaterialTheme.typography.bodyMedium,
                            color = Color(0xFF1A1A2E)
                        )
                    }
                }
            }
            
            // Menu Items
            item {
                // Read language directly from repository to ensure it's always up-to-date
                // This will be re-evaluated on every recomposition
                val languageName = remember(languageRepository) {
                    languageRepository.getLanguageName(languageRepository.getSelectedLanguage())
                }
                
                val menuItems = listOf(
                    ProfileMenuItem(
                        id = "language",
                        title = stringResource(R.string.profile_language),
                        iconRes = R.drawable.ic_language,
                        rightText = languageName,
                        onClick = onLanguage
                    ),
                    ProfileMenuItem(
                        id = "instructor",
                        title = stringResource(R.string.profile_instructor_portal),
                        iconRes = R.drawable.ic_book, // Different icon for Instructor Portal
                        rightText = null,
                        onClick = {
                            // Check if user is instructor before opening portal
                            coroutineScope.launch {
                                val userId = currentUser?.uid
                                if (userId != null) {
                                    val userRole = courseRepository.getUserRole(userId)
                                    if (userRole?.role == "instructor") {
                                        onInstructorPortal()
                                    } else {
                                        showInstructorErrorDialog = true
                                    }
                                } else {
                                    showInstructorErrorDialog = true
                                }
                            }
                        }
                    ),
                    ProfileMenuItem(
                        id = "my_courses",
                        title = stringResource(R.string.profile_my_courses),
                        iconRes = R.drawable.ic_video, // Keep ic_video for My Courses
                        rightText = null,
                        onClick = onInstructorCourses
                    ),
                    ProfileMenuItem(
                        id = "logout",
                        title = stringResource(R.string.profile_logout),
                        iconRes = R.drawable.ic_logout,
                        onClick = onLogout
                    )
                )
                
                Column(
                    modifier = Modifier.fillMaxWidth(),
                    verticalArrangement = Arrangement.spacedBy(8.dp)
                ) {
                    menuItems.forEach { item ->
                        ProfileMenuItemCard(item = item)
                    }
                }
            }
        }
        
        // Bottom Navigation Bar
        NavigationBar(
            containerColor = Color.White,
            modifier = Modifier
                .fillMaxWidth()
                .navigationBarsPadding()
        ) {
            NavigationBarItem(
                selected = selectedTab == 0,
                onClick = onOpenHome,
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
                onClick = onOpenCourses,
                icon = {
                    Icon(
                        painter = painterResource(id = R.drawable.ic_nav_courses),
                        contentDescription = stringResource(R.string.nav_courses),
                        tint = if (selectedTab == 1) Color(0xFF1A1A2E) else Color(0xFF999999),
                        modifier = Modifier.size(24.dp)
                    )
                },
                label = { Text(stringResource(R.string.nav_courses), fontSize = 12.sp, color = if (selectedTab == 1) Color(0xFF1A1A2E) else Color(0xFF999999)) }
            )
            NavigationBarItem(
                selected = selectedTab == 2,
                onClick = onOpenFavourites,
                icon = {
                    Icon(
                        painter = painterResource(id = R.drawable.ic_nav_favorite),
                        contentDescription = stringResource(R.string.nav_favorite),
                        tint = if (selectedTab == 2) Color(0xFF1A1A2E) else Color(0xFF999999),
                        modifier = Modifier.size(24.dp)
                    )
                },
                label = { Text(stringResource(R.string.nav_favorite), fontSize = 12.sp, color = if (selectedTab == 2) Color(0xFF1A1A2E) else Color(0xFF999999)) }
            )
            NavigationBarItem(
                selected = selectedTab == 3,
                onClick = { },
                icon = {
                    Icon(
                        painter = painterResource(id = R.drawable.ic_nav_profile),
                        contentDescription = stringResource(R.string.nav_profile),
                        tint = if (selectedTab == 3) Color(0xFF1A1A2E) else Color(0xFF999999),
                        modifier = Modifier.size(24.dp)
                    )
                },
                label = { Text(stringResource(R.string.nav_profile), fontSize = 12.sp, color = if (selectedTab == 3) Color(0xFF1A1A2E) else Color(0xFF999999)) }
            )
        }
        
        // Instructor Permission Error Dialog
        if (showInstructorErrorDialog) {
            AlertDialog(
                onDismissRequest = { showInstructorErrorDialog = false },
                title = {
                    Text(
                        text = "Access Denied",
                        fontWeight = FontWeight.Bold,
                        color = Color(0xFFD32F2F)
                    )
                },
                text = {
                    Text(
                        text = "Only instructors can access the Instructor Portal. Please contact the admin to become an instructor."
                    )
                },
                confirmButton = {
                    TextButton(
                        onClick = { showInstructorErrorDialog = false }
                    ) {
                        Text("OK", color = Color(0xFFFF6B35))
                    }
                }
            )
        }
    }
}

@Composable
private fun ProfileMenuItemCard(item: ProfileMenuItem) {
    Card(
        modifier = Modifier
            .fillMaxWidth()
            .clickable(onClick = item.onClick),
        shape = RoundedCornerShape(12.dp),
        colors = CardDefaults.cardColors(containerColor = Color.White),
        elevation = CardDefaults.cardElevation(defaultElevation = 1.dp)
    ) {
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .padding(16.dp),
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.SpaceBetween
        ) {
            Row(
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.spacedBy(12.dp)
            ) {
                if (item.iconRes != null) {
                    Icon(
                        painter = painterResource(id = item.iconRes),
                        contentDescription = item.title,
                        tint = Color(0xFF1A1A2E),
                        modifier = Modifier.size(24.dp)
                    )
                } else if (item.iconVector != null) {
                    Icon(
                        imageVector = item.iconVector,
                        contentDescription = item.title,
                        tint = Color(0xFF1A1A2E),
                        modifier = Modifier.size(24.dp)
                    )
                }
                Text(
                    text = item.title,
                    style = MaterialTheme.typography.bodyLarge,
                    color = Color(0xFF1A1A2E),
                    fontWeight = FontWeight.Medium
                )
            }
            
            Row(
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.spacedBy(8.dp)
            ) {
                if (item.rightText != null) {
                    Text(
                        text = item.rightText,
                        style = MaterialTheme.typography.bodyMedium,
                        color = Color(0xFFFF6B35),
                        fontWeight = FontWeight.Medium
                    )
                }
                Icon(
                    Icons.AutoMirrored.Filled.ArrowForward,
                    contentDescription = null,
                    tint = Color(0xFF1A1A2E),
                    modifier = Modifier.size(20.dp)
                )
            }
        }
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Preview(showBackground = true)
@Composable
private fun PreviewProfile() {
    // Preview without Context - use mock data
    Column(
        modifier = Modifier
            .fillMaxSize()
            .statusBarsPadding()
    ) {
        // Top App Bar
        TopAppBar(
            title = {
                Text(
                    text = "Profile",
                    style = MaterialTheme.typography.titleLarge,
                    fontWeight = FontWeight.Bold,
                    color = Color(0xFF1A1A2E)
                )
            },
            colors = TopAppBarDefaults.topAppBarColors(
                containerColor = Color.White
            )
        )
        
        // Content
        LazyColumn(
            modifier = Modifier
                .weight(1f)
                .fillMaxWidth()
                .background(Color(0xFFF5F5F5)),
            contentPadding = PaddingValues(
                start = 16.dp,
                end = 16.dp,
                top = 16.dp,
                bottom = 8.dp
            ),
            verticalArrangement = Arrangement.spacedBy(16.dp)
        ) {
            // Profile Card
            item {
                Card(
                    modifier = Modifier.fillMaxWidth(),
                    shape = RoundedCornerShape(16.dp),
                    colors = CardDefaults.cardColors(containerColor = Color(0xFFF8F9FA)),
                    elevation = CardDefaults.cardElevation(defaultElevation = 2.dp)
                ) {
                    Column(
                        modifier = Modifier
                            .fillMaxWidth()
                            .padding(24.dp),
                        horizontalAlignment = Alignment.CenterHorizontally,
                        verticalArrangement = Arrangement.spacedBy(12.dp)
                    ) {
                        // Profile Picture Circle
                        Box(
                            modifier = Modifier
                                .size(100.dp)
                                .clip(CircleShape)
                                .background(Color(0xFFCCCCCC)),
                            contentAlignment = Alignment.Center
                        ) {
                            Icon(
                                Icons.Filled.Person,
                                contentDescription = "Profile Picture",
                                tint = Color(0xFF666666),
                                modifier = Modifier.size(60.dp)
                            )
                        }
                        
                        // Name
                        Text(
                            text = "John Doe",
                            style = MaterialTheme.typography.headlineSmall,
                            fontWeight = FontWeight.Bold,
                            color = Color(0xFF1A1A2E)
                        )
                        
                        // Email
                        Text(
                            text = "john.doe@example.com",
                            style = MaterialTheme.typography.bodyMedium,
                            color = Color(0xFF1A1A2E)
                        )
                    }
                }
            }
            
            // Menu Items
            item {
                val menuItems = listOf(
                    ProfileMenuItem(
                        id = "language",
                        title = stringResource(R.string.profile_language),
                        iconRes = R.drawable.ic_language,
                        rightText = stringResource(R.string.language_english),
                        onClick = { }
                    ),
                    ProfileMenuItem(
                        id = "instructor",
                        title = stringResource(R.string.profile_instructor_portal),
                        iconRes = R.drawable.ic_book,
                        onClick = { }
                    ),
                    ProfileMenuItem(
                        id = "my_courses",
                        title = stringResource(R.string.profile_my_courses),
                        iconRes = R.drawable.ic_video,
                        onClick = { }
                    ),
                    ProfileMenuItem(
                        id = "logout",
                        title = stringResource(R.string.profile_logout),
                        iconRes = R.drawable.ic_logout,
                        onClick = { }
                    )
                )
                
                Column(
                    modifier = Modifier.fillMaxWidth(),
                    verticalArrangement = Arrangement.spacedBy(8.dp)
                ) {
                    menuItems.forEach { item ->
                        ProfileMenuItemCard(item = item)
                    }
                }
            }
        }
    }
}


