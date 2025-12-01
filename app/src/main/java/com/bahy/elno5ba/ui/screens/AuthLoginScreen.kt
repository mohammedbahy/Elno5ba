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
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowForward
import androidx.compose.material.icons.filled.Lock
import androidx.compose.material.icons.filled.Person
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.OutlinedTextFieldDefaults
import androidx.compose.material3.IconButton
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import android.app.Activity
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.IntentSenderRequest
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.text.input.VisualTransformation
import androidx.compose.ui.layout.ContentScale
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.tooling.preview.Preview
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.lifecycle.viewmodel.compose.viewModel
import com.bahy.elno5ba.R
import com.bahy.elno5ba.data.model.AuthState
import com.bahy.elno5ba.ui.utils.stringResource
import com.bahy.elno5ba.ui.viewmodel.AuthViewModel
import com.google.android.gms.auth.api.identity.Identity
import com.google.android.gms.common.api.ApiException
import kotlinx.coroutines.launch
import kotlinx.coroutines.tasks.await
import androidx.compose.runtime.rememberCoroutineScope

@Composable
fun AuthLoginScreen(
    onLoginSuccess: () -> Unit,
    onNavigateToSignUp: () -> Unit,
    viewModel: AuthViewModel = viewModel()
) {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    val oneTapClient = remember { Identity.getSignInClient(context) }
    val email = remember { mutableStateOf("") }
    val password = remember { mutableStateOf("") }
    val passwordVisible = remember { mutableStateOf(false) }
    val showPasswordResetDialog = remember { mutableStateOf(false) }
    
    val authState by viewModel.authState.collectAsState()
    val currentUser by viewModel.currentUser.collectAsState()
    val isLoading = authState is AuthState.Loading
    
    // Google Sign-In launcher
    val googleSignInLauncher = rememberLauncherForActivityResult(
        contract = ActivityResultContracts.StartIntentSenderForResult()
    ) { result ->
        if (result.resultCode == Activity.RESULT_OK) {
            try {
                val credential = oneTapClient.getSignInCredentialFromIntent(result.data)
                viewModel.signInWithGoogle(credential)
            } catch (e: Exception) {
                // Handle error - show error message
                viewModel.resetAuthState()
            }
        }
    }
    
    // Handle auth state changes - only navigate to home if user is actually logged in
    LaunchedEffect(authState, currentUser) {
        when (authState) {
            is AuthState.Success -> {
                // Only navigate to home if user is actually logged in (not just password reset success)
                if (currentUser != null) {
                    onLoginSuccess()
                    viewModel.resetAuthState()
                }
                // If currentUser is null, it means it's a password reset success, not a login success
                // So we don't navigate, just show the success message in the dialog
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
            text = "Log in",
            style = MaterialTheme.typography.headlineMedium,
            fontWeight = FontWeight.Bold,
            modifier = Modifier.fillMaxWidth()
        )
        
        Spacer(modifier = Modifier.height(32.dp))
        
        // Email/Phone field
        OutlinedTextField(
            value = email.value,
            onValueChange = { email.value = it },
            modifier = Modifier.fillMaxWidth(),
            label = { Text(stringResource(R.string.login_email_phone)) },
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
        
        // Password field
        OutlinedTextField(
            value = password.value,
            onValueChange = { password.value = it },
            modifier = Modifier.fillMaxWidth(),
            label = { Text(stringResource(R.string.login_password)) },
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
        
        // Error message
        val errorState = authState as? AuthState.Error
        if (errorState != null) {
            Spacer(modifier = Modifier.height(8.dp))
            Text(
                text = errorState.message,
                color = Color(0xFFD32F2F),
                fontSize = 12.sp,
                modifier = Modifier.fillMaxWidth(),
                textAlign = TextAlign.Start
            )
            Spacer(modifier = Modifier.height(8.dp))
        }
        
        // Forget Password
        TextButton(
            onClick = { showPasswordResetDialog.value = true },
            modifier = Modifier.fillMaxWidth()
        ) {
            Text(
                stringResource(R.string.login_forget_password),
                color = Color(0xFF666666),
                fontSize = 14.sp,
                modifier = Modifier.fillMaxWidth(),
                textAlign = TextAlign.End
            )
        }
        
        Spacer(modifier = Modifier.height(8.dp))
        
        // Log In button
        Button(
            onClick = {
                if (email.value.isNotBlank() && password.value.isNotBlank()) {
                    viewModel.signInWithEmailAndPassword(email.value.trim(), password.value)
                }
            },
            modifier = Modifier.fillMaxWidth(),
            enabled = !isLoading && email.value.isNotBlank() && password.value.isNotBlank(),
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
                Text(stringResource(R.string.login_button), modifier = Modifier.padding(vertical = 12.dp))
                Spacer(modifier = Modifier.size(8.dp))
                Icon(Icons.AutoMirrored.Filled.ArrowForward, contentDescription = null, modifier = Modifier.size(20.dp))
            }
        }
        
        // Password Reset Dialog (Simple implementation)
        if (showPasswordResetDialog.value) {
            PasswordResetDialog(
                email = email.value,
                authState = authState,
                onDismiss = { 
                    showPasswordResetDialog.value = false
                    viewModel.resetAuthState()
                },
                onReset = { resetEmail ->
                    viewModel.sendPasswordResetEmail(resetEmail)
                }
            )
        }
        
        Spacer(modifier = Modifier.height(24.dp))
        
        // Divider with text
        Row(
            modifier = Modifier.fillMaxWidth(),
            verticalAlignment = Alignment.CenterVertically
        ) {
            Box(
                modifier = Modifier
                    .weight(1f)
                    .height(1.dp)
                    .background(Color(0xFFE0E0E0))
            )
            Text(
                stringResource(R.string.login_or_sign_in_with),
                modifier = Modifier.padding(horizontal = 16.dp),
                color = Color(0xFF666666),
                fontSize = 14.sp
            )
            Box(
                modifier = Modifier
                    .weight(1f)
                    .height(1.dp)
                    .background(Color(0xFFE0E0E0))
            )
        }
        
        Spacer(modifier = Modifier.height(24.dp))
        
        // Google Sign-In button
        Button(
            onClick = {
                scope.launch {
                    try {
                        val signInRequest = com.google.android.gms.auth.api.identity.BeginSignInRequest.builder()
                            .setPasswordRequestOptions(
                                com.google.android.gms.auth.api.identity.BeginSignInRequest.PasswordRequestOptions.builder()
                                    .setSupported(true)
                                    .build()
                            )
                            .setGoogleIdTokenRequestOptions(
                                com.google.android.gms.auth.api.identity.BeginSignInRequest.GoogleIdTokenRequestOptions.builder()
                                    .setSupported(true)
                                    .setFilterByAuthorizedAccounts(false)
                                    .setServerClientId(context.getString(R.string.default_web_client_id))
                                    .build()
                            )
                            .build()
                        
                        val signInResult = oneTapClient.beginSignIn(signInRequest).await()
                        
                        googleSignInLauncher.launch(
                            IntentSenderRequest.Builder(signInResult.pendingIntent.intentSender).build()
                        )
                    } catch (e: Exception) {
                        // Handle error - One Tap might not be available
                        // Fallback to regular Google Sign-In if needed
                        viewModel.resetAuthState()
                    }
                }
            },
            modifier = Modifier.fillMaxWidth(),
            enabled = !isLoading,
            colors = ButtonDefaults.buttonColors(
                containerColor = Color(0xFF4285F4) // Google Blue
            ),
            shape = RoundedCornerShape(12.dp)
        ) {
            if (isLoading) {
                CircularProgressIndicator(
                    modifier = Modifier.size(20.dp),
                    color = Color.White
                )
            } else {
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.Center,
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Box(
                        modifier = Modifier
                            .size(24.dp)
                            .background(Color.White, CircleShape),
                        contentAlignment = Alignment.Center
                    ) {
                        Text(
                            text = "G",
                            color = Color(0xFF4285F4),
                            fontWeight = FontWeight.Bold,
                            fontSize = 16.sp
                        )
                    }
                    Spacer(modifier = Modifier.size(12.dp))
                    Text(
                        text = "Continue with Google",
                        color = Color.White,
                        fontWeight = FontWeight.Medium,
                        modifier = Modifier.padding(vertical = 12.dp)
                    )
                }
            }
        }
        
        Spacer(modifier = Modifier.height(24.dp))
        
        // Sign up link
        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.Center
        ) {
            Text(stringResource(R.string.login_no_account), color = Color(0xFF666666))
            Text(
                stringResource(R.string.login_sign_up),
                color = Color(0xFFFF6B35),
                fontWeight = FontWeight.Bold,
                modifier = Modifier.clickable { onNavigateToSignUp() }
            )
        }
        
        Spacer(modifier = Modifier.height(16.dp))
    }
}

@Composable
private fun LogoSmall() {
    Image(
        painter = painterResource(id = R.drawable.logo),
        contentDescription = "Elno5ba Logo",
        modifier = Modifier.size(120.dp),
        contentScale = ContentScale.Fit
    )
}

@Composable
private fun SocialLoginButton(text: String, color: Color, onClick: () -> Unit) {
    Box(
        modifier = Modifier
            .size(56.dp)
            .background(color, CircleShape)
            .clickable(onClick = onClick),
        contentAlignment = Alignment.Center
    ) {
        Text(
            text = text,
            color = Color.White,
            fontWeight = FontWeight.Bold,
            fontSize = 18.sp
        )
    }
}

@Composable
private fun PasswordResetDialog(
    email: String,
    authState: AuthState,
    onDismiss: () -> Unit,
    onReset: (String) -> Unit
) {
    val resetEmail = remember { mutableStateOf(email) }
    val isLoading = authState is AuthState.Loading
    val isSuccess = authState is AuthState.Success
    val errorMessage = if (authState is AuthState.Error) authState.message else null
    
    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text("Reset Password") },
        text = {
            Column {
                if (isSuccess) {
                    val successState = authState as AuthState.Success
                    Text(
                        text = successState.message ?: "Password reset email sent successfully!",
                        color = Color(0xFF4CAF50),
                        fontWeight = FontWeight.Bold
                    )
                    Spacer(modifier = Modifier.height(8.dp))
                    Text(
                        text = "Please check your email inbox (and spam folder) for the password reset link.",
                        fontSize = 12.sp,
                        color = Color(0xFF666666)
                    )
                } else {
                    Text(stringResource(R.string.password_reset_message))
                    Spacer(modifier = Modifier.height(16.dp))
                    OutlinedTextField(
                        value = resetEmail.value,
                        onValueChange = { resetEmail.value = it },
                        label = { Text(stringResource(R.string.password_reset_email)) },
                        modifier = Modifier.fillMaxWidth(),
                        singleLine = true,
                        enabled = !isLoading,
                        isError = errorMessage != null
                    )
                    if (errorMessage != null) {
                        Spacer(modifier = Modifier.height(8.dp))
                        Text(
                            text = errorMessage,
                            color = Color(0xFFD32F2F),
                            fontSize = 12.sp
                        )
                    }
                    if (isLoading) {
                        Spacer(modifier = Modifier.height(8.dp))
                        CircularProgressIndicator(
                            modifier = Modifier.size(20.dp)
                        )
                    }
                }
            }
        },
        confirmButton = {
            if (isSuccess) {
                TextButton(onClick = onDismiss) {
                    Text(stringResource(R.string.common_ok))
                }
            } else {
                TextButton(
                    onClick = { onReset(resetEmail.value.trim()) },
                    enabled = !isLoading && resetEmail.value.isNotBlank()
                ) {
                    Text(stringResource(R.string.password_reset_send))
                }
            }
        },
        dismissButton = {
            if (!isSuccess) {
                TextButton(onClick = onDismiss) {
                    Text(stringResource(R.string.password_reset_cancel))
                }
            }
        }
    )
}

@Preview(showBackground = true)
@Composable
private fun PreviewLogin() {
    // Create a preview version without ViewModel dependency
    PreviewLoginContent()
}

@Composable
private fun PreviewLoginContent() {
    val email = remember { mutableStateOf("") }
    val password = remember { mutableStateOf("") }
    val passwordVisible = remember { mutableStateOf(false) }
    
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
            text = "Log in",
            style = MaterialTheme.typography.headlineMedium,
            fontWeight = FontWeight.Bold,
            modifier = Modifier.fillMaxWidth()
        )
        
        Spacer(modifier = Modifier.height(32.dp))
        
        // Email/Phone field
        OutlinedTextField(
            value = email.value,
            onValueChange = { email.value = it },
            modifier = Modifier.fillMaxWidth(),
            label = { Text(stringResource(R.string.login_email_phone)) },
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
        
        // Password field
        OutlinedTextField(
            value = password.value,
            onValueChange = { password.value = it },
            modifier = Modifier.fillMaxWidth(),
            label = { Text(stringResource(R.string.login_password)) },
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
        
        // Forget Password
        TextButton(
            onClick = { },
            modifier = Modifier.fillMaxWidth()
        ) {
            Text(
                stringResource(R.string.login_forget_password),
                color = Color(0xFF666666),
                fontSize = 14.sp,
                modifier = Modifier.fillMaxWidth(),
                textAlign = TextAlign.End
            )
        }
        
        Spacer(modifier = Modifier.height(8.dp))
        
        // Log In button
        Button(
            onClick = { },
            modifier = Modifier.fillMaxWidth(),
            colors = ButtonDefaults.buttonColors(
                containerColor = Color(0xFFFF6B35) // Orange
            ),
            shape = RoundedCornerShape(12.dp)
        ) {
            Text("Log In", modifier = Modifier.padding(vertical = 12.dp))
            Spacer(modifier = Modifier.size(8.dp))
            Icon(Icons.AutoMirrored.Filled.ArrowForward, contentDescription = null, modifier = Modifier.size(20.dp))
        }
        
        Spacer(modifier = Modifier.height(24.dp))
        
        // Divider with text
        Row(
            modifier = Modifier.fillMaxWidth(),
            verticalAlignment = Alignment.CenterVertically
        ) {
            Box(
                modifier = Modifier
                    .weight(1f)
                    .height(1.dp)
                    .background(Color(0xFFE0E0E0))
            )
            Text(
                stringResource(R.string.login_or_sign_in_with),
                modifier = Modifier.padding(horizontal = 16.dp),
                color = Color(0xFF666666),
                fontSize = 14.sp
            )
            Box(
                modifier = Modifier
                    .weight(1f)
                    .height(1.dp)
                    .background(Color(0xFFE0E0E0))
            )
        }
        
        Spacer(modifier = Modifier.height(24.dp))
        
        // Social login buttons
        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.SpaceEvenly
        ) {
            SocialLoginButton("G", Color(0xFF4285F4)) { /* Google */ }
            SocialLoginButton("f", Color(0xFF1877F2)) { /* Facebook */ }
            SocialLoginButton("X", Color(0xFF000000)) { /* X/Twitter */ }
            SocialLoginButton("in", Color(0xFF0077B5)) { /* LinkedIn */ }
        }
        
        Spacer(modifier = Modifier.weight(1f))
        
        // Sign up link
        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.Center
        ) {
            Text(stringResource(R.string.login_no_account), color = Color(0xFF666666))
            Text(
                stringResource(R.string.login_sign_up),
                color = Color(0xFFFF6B35),
                fontWeight = FontWeight.Bold,
                modifier = Modifier.clickable { }
            )
        }
        
        Spacer(modifier = Modifier.height(16.dp))
    }
}


