package com.bahy.elno5ba.ui.screens

import androidx.compose.foundation.Image
import androidx.compose.foundation.background
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
import androidx.compose.foundation.layout.WindowInsets
import androidx.compose.foundation.layout.navigationBars
import androidx.compose.foundation.layout.statusBars
import androidx.compose.foundation.layout.windowInsetsPadding
import androidx.compose.foundation.pager.HorizontalPager
import androidx.compose.foundation.pager.rememberPagerState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.ui.Alignment
import kotlinx.coroutines.launch
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.layout.ContentScale
import androidx.compose.ui.draw.clip
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.tooling.preview.Preview
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.bahy.elno5ba.R
import com.bahy.elno5ba.ui.utils.stringResource

data class OnboardingPage(
    val title: String,
    val description: String,
    val imagePlaceholder: String = ""
)

@Composable
fun OnboardingScreen(
    onGetStarted: () -> Unit,
    onSkip: () -> Unit = onGetStarted
) {
    // Get string resources (must be called outside remember)
    val title1 = stringResource(R.string.onboarding_title_1)
    val desc1 = stringResource(R.string.onboarding_description_1)
    val title2 = stringResource(R.string.onboarding_title_2)
    val desc2 = stringResource(R.string.onboarding_description_2)
    val title3 = stringResource(R.string.onboarding_title_3)
    val desc3 = stringResource(R.string.onboarding_description_3)
    
    val pages = remember(title1, desc1, title2, desc2, title3, desc3) {
        listOf(
            OnboardingPage(
                title = title1,
                description = desc1
            ),
            OnboardingPage(
                title = title2,
                description = desc2
            ),
            OnboardingPage(
                title = title3,
                description = desc3
            )
        )
    }
    val pagerState = rememberPagerState(pageCount = { pages.size })
    val scope = rememberCoroutineScope()
    
    Box(
        modifier = Modifier
            .fillMaxSize()
            .windowInsetsPadding(WindowInsets.statusBars)
    ) {
        // Skip button - visible on all pages
        TextButton(
            onClick = onSkip,
            modifier = Modifier
                .align(Alignment.TopStart)
                .padding(16.dp)
        ) {
            Text(stringResource(R.string.onboarding_skip), color = Color.White, fontSize = 14.sp)
        }
        
        Column(
            modifier = Modifier.fillMaxSize(),
            horizontalAlignment = Alignment.CenterHorizontally
        ) {
            // Image placeholder area
            Box(
                modifier = Modifier
                    .weight(1f)
                    .fillMaxWidth()
                    .padding(horizontal = 12.dp, vertical = 12.dp),
                contentAlignment = Alignment.Center
            ) {
                HorizontalPager(state = pagerState, modifier = Modifier.fillMaxWidth()) { page ->
                    val imageRes = when (page) {
                        0 -> R.drawable.onboarding1
                        1 -> R.drawable.onboarding2
                        else -> R.drawable.onboarding3
                    }
                    Image(
                        painter = painterResource(id = imageRes),
                        contentDescription = null,
                        contentScale = ContentScale.Crop,
                        modifier = Modifier
                            .fillMaxWidth()
                            .height(340.dp)
                            .clip(RoundedCornerShape(24.dp))
                    )
                }
            }
            
            // Bottom card
            Card(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(horizontal = 0.dp)
                    .windowInsetsPadding(WindowInsets.navigationBars),
                shape = RoundedCornerShape(topStart = 32.dp, topEnd = 32.dp),
                colors = CardDefaults.cardColors(containerColor = Color.White)
            ) {
                Column(
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(24.dp),
                    horizontalAlignment = Alignment.CenterHorizontally
                ) {
                    // Show current page content (not in pager to avoid nested pagers)
                    Column(
                        horizontalAlignment = Alignment.CenterHorizontally,
                        modifier = Modifier.fillMaxWidth()
                    ) {
                        Text(
                            text = pages[pagerState.currentPage].title,
                            style = MaterialTheme.typography.headlineSmall,
                            fontWeight = FontWeight.Bold,
                            textAlign = TextAlign.Center
                        )
                        Spacer(modifier = Modifier.height(8.dp))
                        Text(
                            text = pages[pagerState.currentPage].description,
                            style = MaterialTheme.typography.bodyMedium,
                            color = Color(0xFF666666),
                            textAlign = TextAlign.Center
                        )
                    }
                    
                    Spacer(modifier = Modifier.height(24.dp))
                    
                    // Dots indicator
                    DotsIndicator(
                        totalDots = pages.size,
                        selectedIndex = pagerState.currentPage
                    )
                    
                    Spacer(modifier = Modifier.height(32.dp))
                    
                    // Button
                    Button(
                        onClick = {
                            if (pagerState.currentPage < pages.size - 1) {
                                scope.launch {
                                    pagerState.animateScrollToPage(pagerState.currentPage + 1)
                                }
                            } else {
                                onGetStarted()
                            }
                        },
                        modifier = Modifier.fillMaxWidth(),
                        colors = ButtonDefaults.buttonColors(
                            containerColor = if (pagerState.currentPage < pages.size - 1) Color(0xFFBDBDBD) else Color(0xFFFFA600)
                        ),
                        shape = RoundedCornerShape(28.dp)
                    ) {
                        Text(
                            text = if (pagerState.currentPage < pages.size - 1) stringResource(R.string.onboarding_next) else stringResource(R.string.onboarding_get_started),
                            color = Color.White,
                            modifier = Modifier.padding(vertical = 10.dp)
                        )
                    }
                }
            }
        }
    }
}

@Composable
private fun DotsIndicator(totalDots: Int, selectedIndex: Int, modifier: Modifier = Modifier) {
    Row(modifier = modifier, horizontalArrangement = Arrangement.spacedBy(8.dp)) {
        repeat(totalDots) { index ->
            val isSelected = index == selectedIndex
            val size = if (isSelected) 10.dp else 8.dp
            val color = if (isSelected) Color(0xFF8B2635) else Color.Gray.copy(alpha = 0.5f)
            Box(
                modifier = Modifier
                    .size(size)
                    .background(color, CircleShape)
            )
        }
    }
}

@Preview(showBackground = true)
@Composable
private fun PreviewOnboarding() { OnboardingScreen(onGetStarted = {}) }


