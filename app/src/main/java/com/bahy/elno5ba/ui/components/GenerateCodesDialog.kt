package com.bahy.elno5ba.ui.components

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp

@Composable
fun GenerateCodesDialog(
    onDismiss: () -> Unit,
    onConfirm: (Int) -> Unit,
    isLoading: Boolean = false
) {
    var codeCount by remember { mutableStateOf("") }
    
    AlertDialog(
        onDismissRequest = onDismiss,
        title = {
            Text(
                text = "Generate Enrollment Codes",
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
                    text = "How many enrollment codes would you like to generate?",
                    fontSize = 14.sp,
                    color = Color(0xFF666666)
                )
                
                OutlinedTextField(
                    value = codeCount,
                    onValueChange = { 
                        if (it.all { char -> char.isDigit() }) {
                            codeCount = it.take(3) // Max 3 digits (999 codes)
                        }
                    },
                    label = { Text("Number of Codes") },
                    placeholder = { Text("e.g., 10") },
                    modifier = Modifier.fillMaxWidth(),
                    keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Number),
                    enabled = !isLoading
                )
                
                Text(
                    text = "Codes will be sent to your email address",
                    fontSize = 12.sp,
                    color = Color(0xFF666666)
                )
            }
        },
        confirmButton = {
            Button(
                onClick = { 
                    val count = codeCount.toIntOrNull() ?: 0
                    if (count > 0 && count <= 999) {
                        onConfirm(count)
                    }
                },
                enabled = codeCount.toIntOrNull()?.let { it > 0 && it <= 999 } == true && !isLoading,
                colors = ButtonDefaults.buttonColors(
                    containerColor = Color(0xFFFF6B35)
                )
            ) {
                Text(if (isLoading) "Generating..." else "Generate Codes")
            }
        },
        dismissButton = {
            TextButton(onClick = onDismiss, enabled = !isLoading) {
                Text("Skip", color = Color(0xFF666666))
            }
        }
    )
}

