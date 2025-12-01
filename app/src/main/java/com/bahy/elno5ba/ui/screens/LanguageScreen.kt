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
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.WindowInsets
import androidx.compose.foundation.layout.navigationBars
import androidx.compose.foundation.layout.statusBars
import androidx.compose.foundation.layout.windowInsetsPadding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.filled.Check
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
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.tooling.preview.Preview
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.ui.platform.LocalContext
import com.bahy.elno5ba.R
import com.bahy.elno5ba.data.repository.LanguageRepository
import com.bahy.elno5ba.ui.utils.stringResource

data class LanguageOption(
    val name: String,
    val code: String
)

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun LanguageScreen(
    onBack: () -> Unit = {},
    onOpenCourses: () -> Unit = {},
    onOpenFavourites: () -> Unit = {},
    onOpenProfile: () -> Unit = {},
    onOpenHome: () -> Unit = {}
) {
    val context = LocalContext.current
    val languageRepository = remember { LanguageRepository(context) }
    
    // Get language names using string resources
    val englishName = stringResource(R.string.language_english)
    val arabicName = stringResource(R.string.language_arabic)
    
    val languages = remember(englishName, arabicName) {
        listOf(
            LanguageOption(englishName, "en"),
            LanguageOption(arabicName, "ar")
        )
    }
    
    val initialLanguage = languageRepository.getSelectedLanguage()
    var selectedLanguage by remember { mutableStateOf(initialLanguage) }
    var shouldRecreate by remember { mutableStateOf(false) }
    
    // Save language when changed
    LaunchedEffect(selectedLanguage) {
        val currentSavedLanguage = languageRepository.getSelectedLanguage()
        if (selectedLanguage != currentSavedLanguage) {
            languageRepository.setSelectedLanguage(selectedLanguage)
            shouldRecreate = true
        }
    }
    
    // Restart activity to apply locale changes
    LaunchedEffect(shouldRecreate) {
        if (shouldRecreate) {
            kotlinx.coroutines.delay(200) // Small delay to ensure save is complete
            val activity = context as? android.app.Activity
            if (activity != null) {
                // Use recreate() which properly calls attachBaseContext
                activity.recreate()
            }
            shouldRecreate = false
        }
    }
    
    var selectedNavTab by remember { mutableIntStateOf(3) } // Profile tab
    
    Column(
        modifier = Modifier
            .fillMaxSize()
            .windowInsetsPadding(WindowInsets.statusBars)
    ) {
        // Top App Bar
        TopAppBar(
            title = {
                Text(
                    text = stringResource(R.string.language_title),
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
                .background(Color(0xFFF5F5F5))
                .windowInsetsPadding(WindowInsets.navigationBars),
            contentPadding = PaddingValues(
                start = 16.dp,
                end = 16.dp,
                top = 16.dp,
                bottom = 8.dp
            ),
            verticalArrangement = Arrangement.spacedBy(16.dp)
        ) {
            // Language Options Card
            item {
                Card(
                    modifier = Modifier.fillMaxWidth(),
                    shape = RoundedCornerShape(16.dp),
                    colors = CardDefaults.cardColors(containerColor = Color.White),
                    elevation = CardDefaults.cardElevation(defaultElevation = 2.dp)
                ) {
                    Column(
                        modifier = Modifier
                            .fillMaxWidth()
                            .padding(20.dp),
                        verticalArrangement = Arrangement.spacedBy(16.dp)
                    ) {
                        languages.forEach { language ->
                            LanguageItem(
                                language = language,
                                isSelected = selectedLanguage == language.code,
                                onClick = { selectedLanguage = language.code }
                            )
                        }
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
                selected = selectedNavTab == 0,
                onClick = { selectedNavTab = 0; onOpenHome() },
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
                onClick = { selectedNavTab = 1; onOpenCourses() },
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
                onClick = { selectedNavTab = 2; onOpenFavourites() },
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
                onClick = { selectedNavTab = 3; onOpenProfile() },
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

@Composable
private fun LanguageItem(
    language: LanguageOption,
    isSelected: Boolean,
    onClick: () -> Unit
) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .clickable(onClick = onClick),
        horizontalArrangement = Arrangement.SpaceBetween,
        verticalAlignment = Alignment.CenterVertically
    ) {
        Text(
            text = language.name,
            style = MaterialTheme.typography.bodyLarge,
            color = Color(0xFF1A1A2E),
            fontWeight = FontWeight.Medium
        )
        
        // Square Checkbox
        Box(
            modifier = Modifier
                .size(24.dp)
                .clip(RoundedCornerShape(4.dp))
                .background(
                    if (isSelected) Color(0xFFFF6B35) else Color(0xFFE0E0E0)
                ),
            contentAlignment = Alignment.Center
        ) {
            if (isSelected) {
                Icon(
                    Icons.Filled.Check,
                    contentDescription = "Selected",
                    tint = Color.White,
                    modifier = Modifier.size(16.dp)
                )
            }
        }
    }
}

@Preview(showBackground = true)
@Composable
private fun PreviewLanguage() {
    LanguageScreen(onBack = {})
}

