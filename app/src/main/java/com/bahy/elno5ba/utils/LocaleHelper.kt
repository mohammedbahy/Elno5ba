package com.bahy.elno5ba.utils

import android.content.Context
import android.content.ContextWrapper
import android.content.res.Configuration
import android.content.res.Resources
import java.util.Locale

class LocaleHelper(base: Context) : ContextWrapper(base) {
    companion object {
        fun wrap(context: Context, languageCode: String): ContextWrapper {
            val config = Configuration(context.resources.configuration)
            val locale = Locale(languageCode)
            Locale.setDefault(locale)
            config.setLocale(locale)
            val wrappedContext = context.createConfigurationContext(config)
            return LocaleHelper(wrappedContext)
        }
    }
}

