package com.bahy.elno5ba.ui

import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.lifecycle.viewmodel.compose.viewModel
import androidx.navigation.NavType
import androidx.navigation.compose.NavHost
import androidx.navigation.compose.composable
import androidx.navigation.compose.rememberNavController
import androidx.navigation.navArgument
import com.bahy.elno5ba.ui.screens.AuthLoginScreen
import com.bahy.elno5ba.ui.screens.AuthSignUpScreen
import com.bahy.elno5ba.ui.screens.CourseDetailsScreen
import com.bahy.elno5ba.ui.screens.CoursesScreen
import com.bahy.elno5ba.ui.screens.FavouritesScreen
import com.bahy.elno5ba.ui.screens.HomeScreen
import com.bahy.elno5ba.ui.screens.LanguageScreen
import com.bahy.elno5ba.ui.screens.InstructorScreen
import com.bahy.elno5ba.ui.screens.InstructorCoursesScreen
import com.bahy.elno5ba.ui.screens.OnboardingScreen
import com.bahy.elno5ba.ui.screens.ProfileScreen
import com.bahy.elno5ba.ui.screens.SplashScreen
import com.bahy.elno5ba.ui.viewmodel.AuthViewModel


sealed class Screen(val route: String) {
    data object Splash : Screen("splash")
    data object Onboarding : Screen("onboarding")
    data object Login : Screen("login")
    data object SignUp : Screen("signup")
    data object Home : Screen("home")
    data object Courses : Screen("courses")
    data object CourseDetails : Screen("course_details/{courseId}") {
        fun createRoute(courseId: String) = "course_details/$courseId"
    }
    data object Favourites : Screen("favourites")
    data object Profile : Screen("profile")
    data object Language : Screen("language")
    data object Instructor : Screen("instructor")
    data object InstructorCourses : Screen("instructor_courses")
    data object EditCourse : Screen("edit_course/{courseId}") {
        fun createRoute(courseId: String) = "edit_course/$courseId"
    }
}

@Composable
fun Elno5baApp(modifier: Modifier = Modifier) {
    val navController = rememberNavController()
    Surface(modifier = modifier, color = MaterialTheme.colorScheme.background) {
        NavHost(navController = navController, startDestination = Screen.Splash.route) {
            composable(Screen.Splash.route) {
                SplashScreen(
                    onFinished = {
                        navController.navigate(Screen.Onboarding.route) {
                            popUpTo(Screen.Splash.route) { inclusive = true }
                        }
                    },
                    onNavigateToHome = {
                        navController.navigate(Screen.Home.route) {
                            popUpTo(Screen.Splash.route) { inclusive = true }
                        }
                    }
                )
            }
            composable(Screen.Onboarding.route) {
                OnboardingScreen(
                    onGetStarted = {
                        navController.navigate(Screen.Login.route) {
                            popUpTo(Screen.Onboarding.route) { inclusive = true }
                        }
                    },
                    onSkip = {
                        navController.navigate(Screen.Login.route) {
                            popUpTo(Screen.Onboarding.route) { inclusive = true }
                        }
                    }
                )
            }
            composable(Screen.Login.route) {
                AuthLoginScreen(
                    onLoginSuccess = {
                        navController.navigate(Screen.Home.route) {
                            popUpTo(Screen.Login.route) { inclusive = true }
                        }
                    },
                    onNavigateToSignUp = { navController.navigate(Screen.SignUp.route) }
                )
            }
            composable(Screen.SignUp.route) {
                AuthSignUpScreen(
                    onAccountCreated = {
                        navController.navigate(Screen.Home.route) {
                            popUpTo(Screen.SignUp.route) { inclusive = true }
                        }
                    },
                    onNavigateToLogin = { navController.navigate(Screen.Login.route) }
                )
            }
            composable(Screen.Home.route) {
                HomeScreen(
                    onOpenCourses = { navController.navigate(Screen.Courses.route) },
                    onOpenFavourites = { navController.navigate(Screen.Favourites.route) },
                    onOpenProfile = { navController.navigate(Screen.Profile.route) },
                    onOpenCourseDetails = { courseId ->
                        navController.navigate(Screen.CourseDetails.createRoute(courseId))
                    }
                )
            }
            composable(Screen.Courses.route) {
                CoursesScreen(
                    onOpenCourse = { courseId ->
                        navController.navigate(Screen.CourseDetails.createRoute(courseId))
                    },
                    onBack = { 
                        // Reload courses when going back
                        navController.popBackStack() 
                    },
                    onOpenFavourites = { navController.navigate(Screen.Favourites.route) },
                    onOpenProfile = { navController.navigate(Screen.Profile.route) },
                    onOpenHome = { navController.navigate(Screen.Home.route) }
                )
            }
            composable(
                route = Screen.CourseDetails.route,
                arguments = listOf(navArgument("courseId") { type = NavType.StringType })
            ) { backStackEntry ->
                val courseId = backStackEntry.arguments?.getString("courseId").orEmpty()
                CourseDetailsScreen(
                    courseId = courseId,
                    onBack = { navController.popBackStack() },
                    onPay = { }, // No longer used, kept for compatibility
                    onOpenVideo = { videoUrl, videoTitle ->
                        // Video will be opened in browser directly from CourseDetailsScreen
                    },
                    onOpenCourses = { navController.navigate(Screen.Courses.route) },
                    onOpenFavourites = { navController.navigate(Screen.Favourites.route) },
                    onOpenProfile = { navController.navigate(Screen.Profile.route) },
                    onOpenHome = { navController.navigate(Screen.Home.route) }
                )
            }
            composable(Screen.Favourites.route) {
                FavouritesScreen(
                    onBack = { navController.popBackStack() },
                    onOpenCourse = { courseId ->
                        navController.navigate(Screen.CourseDetails.createRoute(courseId))
                    },
                    onOpenCourses = { navController.navigate(Screen.Courses.route) },
                    onOpenProfile = { navController.navigate(Screen.Profile.route) },
                    onOpenHome = { navController.navigate(Screen.Home.route) }
                )
            }
            composable(Screen.Profile.route) {
                val authViewModel = viewModel<AuthViewModel>()
                ProfileScreen(
                    onBack = { navController.popBackStack() },
                    onLanguage = { navController.navigate(Screen.Language.route) },
                    onInstructorPortal = { navController.navigate(Screen.Instructor.route) },
                    onInstructorCourses = { navController.navigate(Screen.InstructorCourses.route) },
                    onLogout = {
                        authViewModel.signOut()
                        navController.navigate(Screen.Login.route) {
                            popUpTo(Screen.Profile.route) { inclusive = true }
                        }
                    },
                    onOpenCourses = { navController.navigate(Screen.Courses.route) },
                    onOpenFavourites = { navController.navigate(Screen.Favourites.route) },
                    onOpenHome = { navController.navigate(Screen.Home.route) }
                )
            }
            composable(Screen.Language.route) {
                LanguageScreen(
                    onBack = { 
                        navController.popBackStack()
                        // Force ProfileScreen to reload by navigating to it again
                        // This ensures the language is updated
                    },
                    onOpenCourses = { navController.navigate(Screen.Courses.route) },
                    onOpenFavourites = { navController.navigate(Screen.Favourites.route) },
                    onOpenProfile = { navController.navigate(Screen.Profile.route) },
                    onOpenHome = { navController.navigate(Screen.Home.route) }
                )
            }
            composable(Screen.Instructor.route) {
                InstructorScreen(
                    onBack = { navController.popBackStack() },
                    onSubmitSuccess = { 
                        // Stay on the same screen after creating a course
                        // User can navigate manually if needed
                    }
                )
            }
            composable(Screen.InstructorCourses.route) {
                InstructorCoursesScreen(
                    onBack = { navController.popBackStack() },
                    onEditCourse = { courseId ->
                        navController.navigate(Screen.EditCourse.createRoute(courseId))
                    }
                )
            }
            composable(
                route = Screen.EditCourse.route,
                arguments = listOf(navArgument("courseId") { type = NavType.StringType })
            ) { backStackEntry ->
                val courseId = backStackEntry.arguments?.getString("courseId").orEmpty()
                InstructorScreen(
                    courseId = courseId,
                    onBack = { navController.popBackStack() },
                    onSubmitSuccess = {
                        navController.navigate(Screen.InstructorCourses.route) {
                            popUpTo(Screen.EditCourse.route) { inclusive = true }
                        }
                    }
                )
            }
        }
    }
}


