package com.bahy.elno5ba.ui.screens

import androidx.compose.foundation.Image
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
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
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowForward
import androidx.compose.material.icons.filled.Email
import androidx.compose.material.icons.filled.Lock
import androidx.compose.material.icons.filled.Person
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.OutlinedTextFieldDefaults
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.text.input.VisualTransformation
import androidx.compose.ui.layout.ContentScale
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.tooling.preview.Preview
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.lifecycle.viewmodel.compose.viewModel
import com.bahy.elno5ba.R
import com.bahy.elno5ba.data.model.AuthState
import com.bahy.elno5ba.ui.utils.stringResource
import com.bahy.elno5ba.ui.viewmodel.AuthViewModel

@Composable
fun AuthSignUpScreen(
    onAccountCreated: () -> Unit,
    onNavigateToLogin: () -> Unit,
    viewModel: AuthViewModel = viewModel()
) {
    val name = remember { mutableStateOf("") }
    val email = remember { mutableStateOf("") }
    val password = remember { mutableStateOf("") }
    val confirm = remember { mutableStateOf("") }
    val passwordVisible = remember { mutableStateOf(false) }
    val confirmPasswordVisible = remember { mutableStateOf(false) }
    
    // Validation states - only show errors after trying to sign up
    var nameError by remember { mutableStateOf<String?>(null) }
    var emailError by remember { mutableStateOf<String?>(null) }
    var passwordError by remember { mutableStateOf<String?>(null) }
    var hasTriedToSignUp by remember { mutableStateOf(false) }
    
    val authState by viewModel.authState.collectAsState()
    val isLoading = authState is AuthState.Loading
    
    // Handle auth state changes
    LaunchedEffect(authState) {
        when (authState) {
            is AuthState.Success -> {
                onAccountCreated()
                viewModel.resetAuthState()
            }
            is AuthState.Error -> {
                // Error is shown in UI
            }
            else -> {}
        }
    }
    
    Column(
        modifier = Modifier
            .fillMaxSize()
            .windowInsetsPadding(WindowInsets.statusBars)
            .windowInsetsPadding(WindowInsets.navigationBars)
            .verticalScroll(rememberScrollState())
            .padding(24.dp),
        horizontalAlignment = Alignment.CenterHorizontally
    ) {
        Spacer(modifier = Modifier.height(32.dp))
        
        // Logo
        LogoSmall()
        
        Spacer(modifier = Modifier.height(48.dp))
        
        // Title
        Text(
            text = "Sign up",
            style = MaterialTheme.typography.headlineMedium,
            fontWeight = FontWeight.Bold,
            modifier = Modifier.fillMaxWidth()
        )
        
        Spacer(modifier = Modifier.height(32.dp))
        
        // Full Name field
        OutlinedTextField(
            value = name.value,
            onValueChange = { 
                name.value = it
                if (hasTriedToSignUp) {
                    if (it.trim().isEmpty()) {
                        nameError = "Full name is required"
                    } else if (it.trim().length < 6) {
                        nameError = "Full name must be at least 6 characters"
                    } else {
                        nameError = null
                    }
                }
            },
            modifier = Modifier.fillMaxWidth(),
            label = { Text(stringResource(R.string.signup_full_name)) },
            leadingIcon = {
                Icon(
                    Icons.Filled.Person,
                    contentDescription = null,
                    tint = Color(0xFFFFD700) // Yellow
                )
            },
            colors = OutlinedTextFieldDefaults.colors(
                focusedBorderColor = Color(0xFFFF6B35),
                unfocusedBorderColor = Color(0xFFE0E0E0)
            ),
            shape = RoundedCornerShape(12.dp)
        )
        
        Spacer(modifier = Modifier.height(16.dp))
        
        // Email field
        OutlinedTextField(
            value = email.value,
            onValueChange = { email.value = it },
            modifier = Modifier.fillMaxWidth(),
            label = { Text(stringResource(R.string.signup_email)) },
            leadingIcon = {
                Icon(
                    Icons.Filled.Email,
                    contentDescription = null,
                    tint = Color(0xFFFFD700) // Yellow
                )
            },
            colors = OutlinedTextFieldDefaults.colors(
                focusedBorderColor = Color(0xFFFF6B35),
                unfocusedBorderColor = Color(0xFFE0E0E0)
            ),
            shape = RoundedCornerShape(12.dp)
        )
        
        Spacer(modifier = Modifier.height(16.dp))
        
        // Password field
        OutlinedTextField(
            value = password.value,
            onValueChange = { password.value = it },
            modifier = Modifier.fillMaxWidth(),
            label = { Text(stringResource(R.string.signup_password)) },
            leadingIcon = {
                Icon(
                    Icons.Filled.Lock,
                    contentDescription = null,
                    tint = Color(0xFFFFD700) // Yellow
                )
            },
            trailingIcon = {
                IconButton(
                    onClick = { passwordVisible.value = !passwordVisible.value }
                ) {
                    Text(
                        text = if (passwordVisible.value) "👁️" else "👁️‍🗨️",
                        fontSize = 20.sp,
                        modifier = Modifier.padding(4.dp)
                    )
                }
            },
            visualTransformation = if (passwordVisible.value) VisualTransformation.None else PasswordVisualTransformation(),
            colors = OutlinedTextFieldDefaults.colors(
                focusedBorderColor = Color(0xFFFF6B35),
                unfocusedBorderColor = Color(0xFFE0E0E0)
            ),
            shape = RoundedCornerShape(12.dp)
        )
        
        Spacer(modifier = Modifier.height(16.dp))
        
        // Confirm Password field
        OutlinedTextField(
            value = confirm.value,
            onValueChange = { confirm.value = it },
            modifier = Modifier.fillMaxWidth(),
            label = { Text(stringResource(R.string.signup_confirm_password)) },
            leadingIcon = {
                Icon(
                    Icons.Filled.Lock,
                    contentDescription = null,
                    tint = Color(0xFFFFD700) // Yellow
                )
            },
            trailingIcon = {
                IconButton(
                    onClick = { confirmPasswordVisible.value = !confirmPasswordVisible.value }
                ) {
                    Text(
                        text = if (confirmPasswordVisible.value) "👁️" else "👁️‍🗨️",
                        fontSize = 20.sp,
                        modifier = Modifier.padding(4.dp)
                    )
                }
            },
            visualTransformation = if (confirmPasswordVisible.value) VisualTransformation.None else PasswordVisualTransformation(),
            colors = OutlinedTextFieldDefaults.colors(
                focusedBorderColor = Color(0xFFFF6B35),
                unfocusedBorderColor = Color(0xFFE0E0E0)
            ),
            shape = RoundedCornerShape(12.dp)
        )
        
        // Error message
        if (authState is AuthState.Error) {
            Text(
                text = (authState as AuthState.Error).message,
                color = Color(0xFFD32F2F),
                fontSize = 12.sp,
                modifier = Modifier.fillMaxWidth()
            )
        }
        
        // Password mismatch error
        val passwordMismatch = password.value.isNotEmpty() && 
                               confirm.value.isNotEmpty() && 
                               password.value != confirm.value
        
        if (passwordMismatch) {
            Text(
                text = "Passwords do not match",
                color = Color(0xFFD32F2F),
                fontSize = 12.sp,
                modifier = Modifier.fillMaxWidth()
            )
        }
        
        Spacer(modifier = Modifier.height(16.dp))
        
        // Sign up button
        Button(
            onClick = {
                hasTriedToSignUp = true
                
                // Validate all fields
                var isValid = true
                
                // Validate name
                if (name.value.trim().isEmpty()) {
                    nameError = "Full name is required"
                    isValid = false
                } else if (name.value.trim().length < 6) {
                    nameError = "Full name must be at least 6 characters"
                    isValid = false
                } else {
                    nameError = null
                }
                
                // Validate email (Gmail only)
                val emailTrimmed = email.value.trim().lowercase()
                if (emailTrimmed.isEmpty()) {
                    emailError = "Email is required"
                    isValid = false
                } else if (!emailTrimmed.endsWith("@gmail.com") || emailTrimmed.length <= "@gmail.com".length) {
                    emailError = "Email must be a Gmail address (example@gmail.com)"
                    isValid = false
                } else {
                    val parts = emailTrimmed.split("@")
                    if (parts.size != 2) {
                        emailError = "Please enter a valid Gmail address"
                        isValid = false
                    } else {
                        val username = parts[0]
                        val domain = parts[1]
                        if (domain != "gmail.com") {
                            emailError = "Email must be a Gmail address (example@gmail.com)"
                            isValid = false
                        } else if (username.isEmpty()) {
                            emailError = "Please enter a valid Gmail address"
                            isValid = false
                        } else {
                            val usernamePattern = Regex("^[a-z0-9._+-]+$")
                            if (!usernamePattern.matches(username)) {
                                emailError = "Please enter a valid Gmail address"
                                isValid = false
                            } else if (username.contains("gmail")) {
                                emailError = "Please enter a valid Gmail address"
                                isValid = false
                            } else if (!username[0].isLetterOrDigit() || !username.last().isLetterOrDigit()) {
                                emailError = "Please enter a valid Gmail address"
                                isValid = false
                            } else {
                                val exactPattern = Regex("^[a-z0-9._+-]+@gmail\\.com$")
                                if (!exactPattern.matches(emailTrimmed)) {
                                    emailError = "Please enter a valid Gmail address"
                                    isValid = false
                                } else {
                                    emailError = null
                                }
                            }
                        }
                    }
                }
                
                // Validate password
                if (password.value.isEmpty()) {
                    passwordError = "Password is required"
                    isValid = false
                } else if (password.value.length < 6) {
                    passwordError = "Password must be at least 6 characters"
                    isValid = false
                } else {
                    passwordError = null
                }
                
                // If all validations pass, proceed with sign up
                if (isValid && password.value == confirm.value) {
                    viewModel.signUpWithEmailAndPassword(
                        emailTrimmed,
                        password.value,
                        name.value.trim()
                    )
                }
            },
            modifier = Modifier.fillMaxWidth(),
            enabled = !isLoading,
            colors = ButtonDefaults.buttonColors(
                containerColor = Color(0xFFFF6B35) // Orange
            ),
            shape = RoundedCornerShape(12.dp)
        ) {
            if (isLoading) {
                CircularProgressIndicator(
                    modifier = Modifier.size(20.dp),
                    color = Color.White
                )
            } else {
                Text(stringResource(R.string.signup_button), modifier = Modifier.padding(vertical = 12.dp))
                Spacer(modifier = Modifier.size(8.dp))
                Icon(Icons.AutoMirrored.Filled.ArrowForward, contentDescription = null, modifier = Modifier.size(20.dp))
            }
        }
        
        Spacer(modifier = Modifier.weight(1f))
        
        // Login link
        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.Center
        ) {
            Text(stringResource(R.string.signup_have_account), color = Color(0xFF666666))
            Text(
                stringResource(R.string.signup_log_in),
                color = Color(0xFFFF6B35),
                fontWeight = FontWeight.Bold,
                modifier = Modifier.clickable { onNavigateToLogin() }
            )
        }
        
        Spacer(modifier = Modifier.height(16.dp))
    }
}

@Preview(showBackground = true)
@Composable
private fun PreviewSignUp() {
    // Create a preview version without ViewModel dependency
    PreviewSignUpContent()
}

@Composable
private fun PreviewSignUpContent() {
    val name = remember { mutableStateOf("") }
    val email = remember { mutableStateOf("") }
    val password = remember { mutableStateOf("") }
    val confirm = remember { mutableStateOf("") }
    val passwordVisible = remember { mutableStateOf(false) }
    val confirmPasswordVisible = remember { mutableStateOf(false) }
    
    Column(
        modifier = Modifier
            .fillMaxSize()
            .padding(24.dp),
        horizontalAlignment = Alignment.CenterHorizontally
    ) {
        Spacer(modifier = Modifier.height(32.dp))
        
        // Logo
        LogoSmall()
        
        Spacer(modifier = Modifier.height(48.dp))
        
        // Title
        Text(
            text = "Sign up",
            style = MaterialTheme.typography.headlineMedium,
            fontWeight = FontWeight.Bold,
            modifier = Modifier.fillMaxWidth()
        )
        
        Spacer(modifier = Modifier.height(32.dp))
        
        // Full Name field
        OutlinedTextField(
            value = name.value,
            onValueChange = { name.value = it },
            modifier = Modifier.fillMaxWidth(),
            label = { Text(stringResource(R.string.signup_full_name)) },
            leadingIcon = {
                Icon(
                    Icons.Filled.Person,
                    contentDescription = null,
                    tint = Color(0xFFFFD700) // Yellow
                )
            },
            colors = OutlinedTextFieldDefaults.colors(
                focusedBorderColor = Color(0xFFFF6B35),
                unfocusedBorderColor = Color(0xFFE0E0E0)
            ),
            shape = RoundedCornerShape(12.dp)
        )
        
        Spacer(modifier = Modifier.height(16.dp))
        
        // Email field
        OutlinedTextField(
            value = email.value,
            onValueChange = { email.value = it },
            modifier = Modifier.fillMaxWidth(),
            label = { Text(stringResource(R.string.signup_email)) },
            leadingIcon = {
                Icon(
                    Icons.Filled.Email,
                    contentDescription = null,
                    tint = Color(0xFFFFD700) // Yellow
                )
            },
            colors = OutlinedTextFieldDefaults.colors(
                focusedBorderColor = Color(0xFFFF6B35),
                unfocusedBorderColor = Color(0xFFE0E0E0)
            ),
            shape = RoundedCornerShape(12.dp)
        )
        
        Spacer(modifier = Modifier.height(16.dp))
        
        // Password field
        OutlinedTextField(
            value = password.value,
            onValueChange = { password.value = it },
            modifier = Modifier.fillMaxWidth(),
            label = { Text(stringResource(R.string.signup_password)) },
            leadingIcon = {
                Icon(
                    Icons.Filled.Lock,
                    contentDescription = null,
                    tint = Color(0xFFFFD700) // Yellow
                )
            },
            trailingIcon = {
                IconButton(
                    onClick = { passwordVisible.value = !passwordVisible.value }
                ) {
                    Text(
                        text = if (passwordVisible.value) "👁️" else "👁️‍🗨️",
                        fontSize = 20.sp,
                        modifier = Modifier.padding(4.dp)
                    )
                }
            },
            visualTransformation = if (passwordVisible.value) VisualTransformation.None else PasswordVisualTransformation(),
            colors = OutlinedTextFieldDefaults.colors(
                focusedBorderColor = Color(0xFFFF6B35),
                unfocusedBorderColor = Color(0xFFE0E0E0)
            ),
            shape = RoundedCornerShape(12.dp)
        )
        
        Spacer(modifier = Modifier.height(16.dp))
        
        // Confirm Password field
        OutlinedTextField(
            value = confirm.value,
            onValueChange = { confirm.value = it },
            modifier = Modifier.fillMaxWidth(),
            label = { Text(stringResource(R.string.signup_confirm_password)) },
            leadingIcon = {
                Icon(
                    Icons.Filled.Lock,
                    contentDescription = null,
                    tint = Color(0xFFFFD700) // Yellow
                )
            },
            trailingIcon = {
                IconButton(
                    onClick = { confirmPasswordVisible.value = !confirmPasswordVisible.value }
                ) {
                    Text(
                        text = if (confirmPasswordVisible.value) "👁️" else "👁️‍🗨️",
                        fontSize = 20.sp,
                        modifier = Modifier.padding(4.dp)
                    )
                }
            },
            visualTransformation = if (confirmPasswordVisible.value) VisualTransformation.None else PasswordVisualTransformation(),
            colors = OutlinedTextFieldDefaults.colors(
                focusedBorderColor = Color(0xFFFF6B35),
                unfocusedBorderColor = Color(0xFFE0E0E0)
            ),
            shape = RoundedCornerShape(12.dp)
        )
        
        Spacer(modifier = Modifier.height(32.dp))
        
        // Sign up button
        Button(
            onClick = { },
            modifier = Modifier.fillMaxWidth(),
            colors = ButtonDefaults.buttonColors(
                containerColor = Color(0xFFFF6B35) // Orange
            ),
            shape = RoundedCornerShape(12.dp)
        ) {
            Text("Sign up", modifier = Modifier.padding(vertical = 12.dp))
            Spacer(modifier = Modifier.size(8.dp))
            Icon(Icons.AutoMirrored.Filled.ArrowForward, contentDescription = null, modifier = Modifier.size(20.dp))
        }
        
        Spacer(modifier = Modifier.weight(1f))
        
        // Login link
        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.Center
        ) {
            Text(stringResource(R.string.signup_have_account), color = Color(0xFF666666))
            Text(
                stringResource(R.string.signup_log_in),
                color = Color(0xFFFF6B35),
                fontWeight = FontWeight.Bold,
                modifier = Modifier.clickable { }
            )
        }
        
        Spacer(modifier = Modifier.height(16.dp))
    }
}

@Composable
private fun LogoSmall() {
    Image(
        painter = painterResource(id = R.drawable.logo),
        contentDescription = "El Nokbha Logo",
        modifier = Modifier.size(120.dp),
        contentScale = ContentScale.Fit
    )
}


