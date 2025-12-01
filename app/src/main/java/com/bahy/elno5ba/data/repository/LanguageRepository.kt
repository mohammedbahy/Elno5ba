package com.bahy.elno5ba.data.repository

import android.content.Context
import android.content.SharedPreferences
import java.util.Locale

class LanguageRepository(
    private val context: Context
) {
    private val prefs: SharedPreferences = context.getSharedPreferences("app_prefs", Context.MODE_PRIVATE)
    private val LANGUAGE_KEY = "selected_language"
    
    fun getSelectedLanguage(): String {
        return prefs.getString(LANGUAGE_KEY, "en") ?: "en"
    }
    
    fun setSelectedLanguage(languageCode: String) {
        prefs.edit().putString(LANGUAGE_KEY, languageCode).commit()
    }
    
    fun getLanguageName(languageCode: String): String {
        return when (languageCode) {
            "ar" -> "العربية"
            "en" -> "English"
            else -> "English"
        }
    }
    
    fun getCurrentLocale(): Locale {
        val languageCode = getSelectedLanguage()
        return Locale(languageCode)
    }
}

