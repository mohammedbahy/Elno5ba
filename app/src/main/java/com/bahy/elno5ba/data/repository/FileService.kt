package com.bahy.elno5ba.data.repository

import android.content.ContentResolver
import android.net.Uri
import android.util.Log
import java.io.OutputStream

object FileService {
    /**
     * Save enrollment codes to a text file
     * Writes the codes to the provided OutputStream (from Storage Access Framework)
     */
    fun saveCodesToFile(outputStream: OutputStream, courseTitle: String, codes: List<String>): Result<Unit> {
        return try {
            val content = buildString {
                appendLine("Enrollment Codes for Course: $courseTitle")
                appendLine("=".repeat(50))
                appendLine()
                appendLine("Generated on: ${java.text.SimpleDateFormat("yyyy-MM-dd HH:mm:ss", java.util.Locale.getDefault()).format(java.util.Date())}")
                appendLine()
                appendLine("Codes:")
                appendLine("-".repeat(50))
                codes.forEachIndexed { index, code ->
                    appendLine("${index + 1}. $code")
                }
                appendLine("-".repeat(50))
                appendLine()
                appendLine("Total codes: ${codes.size}")
                appendLine()
                appendLine("You can share these codes with your students to enroll them in the course.")
                appendLine()
                appendLine("Best regards,")
                appendLine("Elno5ba Team")
            }
            
            outputStream.use { stream ->
                stream.write(content.toByteArray(Charsets.UTF_8))
            }
            
            Log.d("FileService", "Codes saved to file successfully")
            Result.success(Unit)
        } catch (e: Exception) {
            Log.e("FileService", "Error saving codes to file: ${e.message}", e)
            Result.failure(e)
        }
    }
}

