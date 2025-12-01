package com.bahy.elno5ba

import android.content.Context
import android.content.res.Configuration
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.ui.Modifier
import androidx.core.view.WindowCompat
import com.bahy.elno5ba.data.repository.LanguageRepository
import com.bahy.elno5ba.ui.Elno5baApp
import com.bahy.elno5ba.utils.LocaleHelper
import java.util.Locale

class MainActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        
        // Enable edge-to-edge and set status bar icons to dark (for light backgrounds)
        WindowCompat.setDecorFitsSystemWindows(window, false)
        window.statusBarColor = android.graphics.Color.TRANSPARENT
        val insetsController = WindowCompat.getInsetsController(window, window.decorView)
        insetsController?.isAppearanceLightStatusBars = true // Dark icons for light background
        
        setContent {
            MaterialTheme {
                Surface(
                    modifier = Modifier.fillMaxSize(),
                    color = MaterialTheme.colorScheme.background
                ) {
                    Elno5baApp()
                }
            }
        }
    }
    
    override fun attachBaseContext(newBase: Context?) {
        if (newBase == null) {
            super.attachBaseContext(null)
            return
        }
        val languageRepository = LanguageRepository(newBase)
        val languageCode = languageRepository.getSelectedLanguage()
        val wrappedContext = LocaleHelper.wrap(newBase, languageCode)
        super.attachBaseContext(wrappedContext)
    }
}