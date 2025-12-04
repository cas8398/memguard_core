package com.flagodna.memguard

import android.util.Log
import com.flagodna.memguard.BuildConfig

object debugPrint {

    private const val MAX_LOG_SIZE = 1000

    private fun log(tag: String, message: String, level: LogLevel, throwable: Throwable?) {
        if (!BuildConfig.DEBUG) return  // Never log in release

        var start = 0
        val length = message.length
        while (start < length) {
            val end = (start + MAX_LOG_SIZE).coerceAtMost(length)
            val chunk = message.substring(start, end)
            when (level) {
                LogLevel.DEBUG -> if (throwable != null) Log.d(tag, chunk, throwable) else Log.d(tag, chunk)
                LogLevel.INFO  -> if (throwable != null) Log.i(tag, chunk, throwable) else Log.i(tag, chunk)
                LogLevel.WARN  -> if (throwable != null) Log.w(tag, chunk, throwable) else Log.w(tag, chunk)
                LogLevel.ERROR -> if (throwable != null) Log.e(tag, chunk, throwable) else Log.e(tag, chunk)
            }
            start = end
        }
    }

    fun d(tag: String, message: String, throwable: Throwable? = null) = log(tag, message, LogLevel.DEBUG, throwable)
    fun i(tag: String, message: String, throwable: Throwable? = null) = log(tag, message, LogLevel.INFO, throwable)
    fun w(tag: String, message: String, throwable: Throwable? = null) = log(tag, message, LogLevel.WARN, throwable)
    fun e(tag: String, message: String, throwable: Throwable? = null) = log(tag, message, LogLevel.ERROR, throwable)

    private enum class LogLevel { DEBUG, INFO, WARN, ERROR }
}
