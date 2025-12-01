package com.bahy.elno5ba.ui.utils

import androidx.compose.runtime.Composable
import androidx.compose.ui.platform.LocalContext
import com.bahy.elno5ba.R

@Composable
fun stringResource(id: Int): String {
    return LocalContext.current.getString(id)
}

@Composable
fun stringResource(id: Int, vararg formatArgs: Any): String {
    return LocalContext.current.getString(id, *formatArgs)
}

