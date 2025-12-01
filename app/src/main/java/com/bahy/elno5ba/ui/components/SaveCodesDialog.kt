package com.bahy.elno5ba.ui.components

import android.net.Uri
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.remember
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.bahy.elno5ba.data.repository.FileService

@Composable
fun SaveCodesDialog(
    courseTitle: String,
    codes: List<String>,
    onDismiss: () -> Unit,
    onSaveComplete: () -> Unit,
    onSaveError: (String) -> Unit
) {
    val context = LocalContext.current
    
    val saveFileLauncher = rememberLauncherForActivityResult(
        contract = ActivityResultContracts.CreateDocument("text/plain")
    ) { uri: Uri? ->
        if (uri != null) {
            try {
                context.contentResolver.openOutputStream(uri)?.use { outputStream ->
                    val result = FileService.saveCodesToFile(outputStream, courseTitle, codes)
                    result.fold(
                        onSuccess = {
                            onSaveComplete()
                        },
                        onFailure = { error ->
                            onSaveError(error.message ?: "Failed to save file")
                        }
                    )
                } ?: run {
                    onSaveError("Failed to open file for writing")
                }
            } catch (e: Exception) {
                onSaveError(e.message ?: "Error saving file")
            }
        } else {
            // User cancelled
            onDismiss()
        }
    }
    
    AlertDialog(
        onDismissRequest = onDismiss,
        title = {
            Text(
                text = "Save Enrollment Codes",
                fontWeight = FontWeight.Bold,
                fontSize = 20.sp
            )
        },
        text = {
            Column(
                modifier = Modifier.fillMaxWidth(),
                verticalArrangement = Arrangement.spacedBy(12.dp)
            ) {
                Text(
                    text = "Choose where to save the enrollment codes file.",
                    fontSize = 14.sp,
                    color = Color(0xFF666666)
                )
                Text(
                    text = "The file will be saved as a .txt file that you can open anytime.",
                    fontSize = 12.sp,
                    color = Color(0xFF666666)
                )
                Text(
                    text = "Total codes: ${codes.size}",
                    fontSize = 12.sp,
                    fontWeight = FontWeight.Bold,
                    color = Color(0xFF1A1A2E)
                )
            }
        },
        confirmButton = {
            Button(
                onClick = {
                    val fileName = "enrollment_codes_${courseTitle.replace(" ", "_")}_${System.currentTimeMillis()}.txt"
                    saveFileLauncher.launch(fileName)
                },
                colors = ButtonDefaults.buttonColors(
                    containerColor = Color(0xFFFF6B35)
                )
            ) {
                Text("Choose Location")
            }
        },
        dismissButton = {
            TextButton(onClick = onDismiss) {
                Text("Cancel", color = Color(0xFF666666))
            }
        }
    )
}

