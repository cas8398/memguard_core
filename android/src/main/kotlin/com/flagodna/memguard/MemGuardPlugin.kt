package com.flagodna.memguard

import com.flagodna.memguard.debugPrint
import android.content.Context
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.security.keystore.StrongBoxUnavailableException
import android.util.Base64  
import io.flutter.embedding.engine.plugins.FlutterPlugin
import io.flutter.plugin.common.MethodCall
import io.flutter.plugin.common.MethodChannel
import io.flutter.plugin.common.MethodChannel.MethodCallHandler
import io.flutter.plugin.common.MethodChannel.Result
import java.io.File  
import java.nio.charset.StandardCharsets
import java.security.KeyStore
import java.security.MessageDigest  
import java.security.InvalidKeyException   
import java.util.concurrent.ConcurrentHashMap
import org.json.JSONObject 
import androidx.annotation.RequiresApi
import android.os.Build
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec
import java.util.Collections
import java.util.WeakHashMap
import java.security.SecureRandom
import javax.crypto.AEADBadTagException


class MemGuardPlugin : FlutterPlugin, MethodCallHandler {
    private lateinit var channel: MethodChannel
    private lateinit var context: Context
    private val tag = "MemGuardPlugin"
    
    // Encryption settings
    private val encryptionAlgorithm = "AES/GCM/NoPadding" 
    private val keyLength = 256 
    private val gcmTagLengthBits = 128 // GCM tag length in bits

    // Rate limiting for direct retrievals
    private val rateLimitMap = Collections.synchronizedMap(WeakHashMap<String, MutableList<Long>>())
    private val RATE_LIMIT_MAX_CALLS = 5        // max calls
    private val RATE_LIMIT_WINDOW_MS = 60_000L  // 1 minute
    
    // Android KeyStore
    private val keyStoreAlias = "memguard_secure_key"
    private val keyStoreProvider = "AndroidKeyStore"
    
    // Rust FFI instance
    private lateinit var rustFFI: RustFFI

    companion object {
        const val CHANNEL_NAME = "com.memguard/storage"
        const val STORAGE_DIR = "memguard_secure" 
        const val RUST_NOT_READY = "rust_not_ready"

        // SHA-256 hash of "memguard_stats" to use as key in Rust storage
        const val STATS_KEY_HASH = "db3b1c9812e7edc529fa4dbd05c3f793db5743dbefdb5b4be1f2f0c0bb0d9ec1"
    }

    // Rust FFI wrapper with safe calls
    inner class RustFFI { 
        // Fixed initialization block
        init {
            try {
                System.loadLibrary("memguard_ffi")
                debugPrint.i(tag, "Rust FFI library loaded (not yet initialized)")
            } catch (e: UnsatisfiedLinkError) {
                debugPrint.w(tag, "Rust FFI library not available: ${e.message}")
            } catch (e: Exception) {
                debugPrint.e(tag, "Failed to load Rust FFI: ${e.message}")
            }
        } 

        external fun memguard_store(key: String, value: String): Int
        external fun memguard_retrieve(key: String): String?
        external fun memguard_delete(key: String): Int
        external fun memguard_contains(key: String): Int
        external fun memguard_cleanup_memory(): Unit
        external fun memguard_cleanup_all(): Unit     
        external fun memguard_is_initialized(): Int
        external fun memguard_get_memory_usage(): Int

        
        val isRustReady: Boolean
            get() = try {
                memguard_is_initialized() == 1  // Rust returns 1 for initialized
            } catch (e: UnsatisfiedLinkError) {
                false
            }

        fun storeSafe(key: String, value: String): Boolean {
            return try {
                val result = memguard_store(key, value)
                result == 0  // 0 means success in Rust
            } catch (e: UnsatisfiedLinkError) {
                debugPrint.d(tag, "Rust FFI not available for store operation")
                false
            } catch (e: Exception) {
                debugPrint.e(tag, "Rust store error: ${e.message}")
                false
            }
        }

        fun retrieveSafe(key: String): String? {
            return try {
                memguard_retrieve(key)
            } catch (e: UnsatisfiedLinkError) {
                debugPrint.d(tag, "Rust FFI not available for retrieve operation")
                null
            } catch (e: Exception) {
                debugPrint.e(tag, "Rust retrieve error: ${e.message}")
                null
            }
        }

        fun deleteSafe(key: String): Boolean {
            return try {
                val result = memguard_delete(key)
                result == 0
            } catch (e: UnsatisfiedLinkError) {
                debugPrint.d(tag, "Rust FFI not available for delete operation")
                false
            } catch (e: Exception) {
                debugPrint.e(tag, "Rust delete error: ${e.message}")
                false
            }
        }

        fun containsSafe(key: String): Boolean {
            return try {
                val result = memguard_contains(key)
                result == 1  // Rust returns 1 if key exists
            } catch (e: UnsatisfiedLinkError) {
                debugPrint.d(tag, "Rust FFI not available for contains operation")
                false
            } catch (e: Exception) {
                debugPrint.e(tag, "Rust contains error: ${e.message}")
                false
            }
        }

        fun cleanupMemorySafe() {
            try {
                memguard_cleanup_memory()
            } catch (e: UnsatisfiedLinkError) {
                debugPrint.d(tag, "Rust FFI not available for cleanup")
            } catch (e: Exception) {
                debugPrint.e(tag, "Rust cleanup error: ${e.message}")
            }
        }

        fun cleanupAllSafe() {
            try {
                memguard_cleanup_all()
            } catch (e: UnsatisfiedLinkError) {
                debugPrint.d(tag, "Rust FFI not available for cleanup")
            } catch (e: Exception) {
                debugPrint.e(tag, "Rust cleanup error: ${e.message}")
            }
        }
    }

    override fun onAttachedToEngine(flutterPluginBinding: FlutterPlugin.FlutterPluginBinding) {
        context = flutterPluginBinding.applicationContext
        channel = MethodChannel(flutterPluginBinding.binaryMessenger, CHANNEL_NAME)
        channel.setMethodCallHandler(this)
        
        rustFFI = RustFFI() 
            
        debugPrint.i(tag, "MemGuardPlugin attached to engine")
    }

    override fun onMethodCall(call: MethodCall, result: Result) {
        debugPrint.d(tag, "Method call: ${call.method}")
        
        try {
            when (call.method) {
                "store" -> handleStore(call, result)
                "retrieve" -> handleRetrieve(call, result)
                "retrieveDirect" -> handleRetrieveDirect(call, result)
                "delete" -> handleDelete(call, result)
                "contains" -> handleContains(call, result)
                "getStats" -> handleGetStats(call, result)
                "cleanupAll" -> handleCleanupAll(call, result)
                else -> result.notImplemented()
            }
        } catch (e: Exception) {
            result.error("MEMGUARD_ERROR", e.message, null)
        }
    }

    override fun onDetachedFromEngine(binding: FlutterPlugin.FlutterPluginBinding) {
        channel.setMethodCallHandler(null)
    }

    /**
     * SECURE STORAGE PROTOCOL - DART/KOTLIN CONTRACT
     * ==============================================
     * 
     * PLATFORM CHANNEL RESTRICTIONS:
     *   • Kotlin → Dart: ONLY null, rust_not_ready, true, or false allowed 
     *   • NEVER plaintext values over platform channel
     *   • Dart pulls actual data from Rust FFI when indicated
     * 
     * RETURN VALUE SEMANTICS:
     *   • true  = "Go fetch from Rust via FFI" (success + data in Rust)
     *   • false  = "Negative/Doesn't exist" (context-dependent)
     *   • rust_not_ready = "Rust not initialized" (only in retrieve/contains)
     *   • null = "Not found" (only in retrieve)
     *   • Error = Operation failed
     * 
     * DART RESPONSIBILITIES:
     *   1. Initialize Rust storage before any operations
     *   2. When Kotlin returns true → call Rust FFI for actual data
     *   3. Handle hot reload by re-initializing Rust
     * 
     * SECURITY BOUNDARIES:
     *   ┌─────────────────┐ true/false/null/rust_not_ready ┌─────────────────┐
     *   │    Kotlin       ├──────────────────────────────►│      Dart       │
     *   │  (KeyStore)     │                              │                 │
     *   └────────┬────────┘                             └────────┬────────┘
     *            │                                              │
     *            │ Rust FFI (encrypted)                        │ Rust FFI (direct)
     *            ▼                                            ▼
     *   ┌─────────────────┐                         ┌─────────────────┐
     *   │   Rust Native   │◄───────────────────────┤  Rust via Dart  │
     *   │ (Memory Cache)  │   plaintext*          │                 │
     *   └─────────────────┘                       └─────────────────┘
     *   *plaintext only during initial store; immediately encrypted
     */


    private fun handleStore(call: MethodCall, result: Result) {
        val key = call.argument<String>("key")
        val value = call.argument<String>("value")

        if (key.isNullOrEmpty() || value.isNullOrEmpty()) {
            result.error("INVALID_ARGUMENTS", "Non-empty key and value required", null)
            return
        }

        try {
            // PRIMARY: Always store to hardware-backed encryption
            val encryptedOnDisk = encrypt(value, key)
            saveToFile(key, encryptedOnDisk)

            // SECONDARY: Cache in Rust if available (performance only)
            if (rustFFI.isRustReady) {
                rustFFI.storeSafe(key, value)
                debugPrint.d(tag, "Key cached in Rust: $key")
            } else {
                debugPrint.w(tag, "Rust not ready - key stored in KeyStore only: $key")
                // This is OK! Value is safely stored in KeyStore
            }

            // Success: Value stored securely
            result.success(true)
        } catch (e: SecurityException) {
            debugPrint.e(tag, "Hardware security failure for key: $key", e)
            result.error("SECURITY_ERROR", "KeyStore operation failed", null)
        } catch (e: Exception) {
            debugPrint.e(tag, "Store failed for key: $key", e)
            result.error("STORE_FAILED", e.message ?: "Unknown encryption error", null)
        }
    }

    private fun handleRetrieve(call: MethodCall, result: Result) {
        val key = call.argument<String>("key")
            ?: return result.error("INVALID_ARGUMENTS", "Missing key", null)

        try {
            // IMPORTANT DESIGN DECISION: If Rust isn't ready, we CANNOT return false
            if (!rustFFI.isRustReady) {
                return result.success(RUST_NOT_READY)  
            }

            // Rust is ready - use tiered strategy
            if (rustFFI.containsSafe(key)) {
                result.success(true)  // Fast path: in Rust cache
                return
            }

            // Check disk
            val encryptedOnDisk = readFromFile(key)
            if (encryptedOnDisk != null) { 
                // Decrypt and cache in Rust
                val plaintext = decrypt(encryptedOnDisk, key)
                rustFFI.storeSafe(key, plaintext)
                result.success(true)  // Now in Rust cache
            } else {
                result.success(null)  // Not found
            }
        } catch (e: InvalidKeyException) {
            debugPrint.e(tag, "Key integrity violation for: $key", e)
            result.error("KEY_INVALID", "Decryption key unavailable or invalid", null)
        } catch (e: Exception) {
            debugPrint.e(tag, "Retrieve failed for key: $key", e)
            result.error("RETRIEVE_FAILED", e.message ?: "Decryption failed", null)
        }
    }

    /**
     * Emergency direct retrieval — bypasses the normal secure protocol.
     *
     * This method intentionally breaks the "no plaintext over MethodChannel" rule
     * and returns the decrypted value directly.
     *
     * Use ONLY in controlled recovery scenarios:
     *   • During app startup / cold start when Rust FFI is not yet initialized
     *   • After hot restart in debug mode
     *   • When migrating from old storage or recovering from corrupted Rust state
     *
     * Why this is acceptable:
     *   • The alternative is silent data loss (unacceptable for secure storage)
     *   • The channel is still within the app process (not exposed to other apps)
     *   • All encryption is hardware-backed — no keys leave the secure enclave
     *   • This is a well-known, documented exception used by top-tier secure storage libs
     *
     * In production, Dart code should:
     *   1. Call this only once per key during initialization
     *   2. Immediately re-store via normal `store()` to populate Rust cache
     *   3. Never use this in regular read/write flow
     */

    private fun isRateLimited(key: String): Boolean {
        val now = System.currentTimeMillis()
        val timestamps = rateLimitMap.computeIfAbsent(key) { mutableListOf() }

        synchronized(timestamps) {
            // Remove timestamps outside the window
            timestamps.removeAll { it < now - RATE_LIMIT_WINDOW_MS }

            return if (timestamps.size >= RATE_LIMIT_MAX_CALLS) {
                true  // Limit exceeded, do NOT add timestamp
            } else {
                timestamps.add(now)  // Only add when allowed
                false
            }
        }
    }


    private fun handleRetrieveDirect(call: MethodCall, result: Result) {
        val key = call.argument<String>("key")
            ?: return result.error("INVALID_ARGUMENTS", "Missing key", null)

        if (isRateLimited(key)) {
            debugPrint.w(tag, "Rate limit exceeded for key: $key")
            return result.error("RATE_LIMIT_EXCEEDED", "Too many requests for key: $key", null)
        }

        try {
            val encryptedOnDisk = readFromFile(key)
            if (encryptedOnDisk != null) {
                val plaintext = decrypt(encryptedOnDisk, key)
                
                if (rustFFI.isRustReady) {
                    rustFFI.storeSafe(key, plaintext)
                    debugPrint.d(tag, "Direct retrieve: hydrated Rust cache for key '$key'")
                }
                
                result.success(plaintext)
            } else {
                result.success(null)
            }
        } catch (e: InvalidKeyException) {
            debugPrint.e(tag, "Direct retrieve failed — key permanently invalidated for: $key", e)
            result.error("KEY_INVALID", "Encryption key was reset. Data unrecoverable.", null)
        } catch (e: Exception) {
            debugPrint.e(tag, "Direct retrieve failed for key: $key", e)
            result.error("RETRIEVE_FAILED", "Decryption failed: ${e.message}", null)
        }
    }

    private fun handleContains(call: MethodCall, result: Result) {
        val key = call.argument<String>("key")
            ?: return result.error("INVALID_ARGUMENTS", "Missing key", null)

        try {
            // IMPORTANT DESIGN DECISION: If Rust isn't ready, we CANNOT return false
            // because Dart would have no way to get the value. 
            if (!rustFFI.isRustReady) {
                return result.success(RUST_NOT_READY)  
            }
            
            // Check Rust cache first if available
            if (rustFFI.containsSafe(key)) {
                result.success(true)
                return
            }

            // Fallback to disk check
            val existsOnDisk = fileExists(key)
            
            result.success(if (existsOnDisk) true else false)
        } catch (e: Exception) {
            result.error("CONTAINS_FAILED", e.message, null)
        }
    }

    private fun handleDelete(call: MethodCall, result: Result) {
        val key = call.argument<String>("key")
            ?: return result.error("INVALID_ARGUMENTS", "Missing key", null)

        try {
            // Always delete from persistent storage
            deleteFile(key)
            
            // Delete from Rust cache if available
            if (rustFFI.isRustReady) { 
                rustFFI.deleteSafe(key)
            }

            result.success(true)
        } catch (e: Exception) {
            result.error("DELETE_FAILED", e.message, null)
        }
    }

    private fun handleGetStats(call: MethodCall, result: Result) {
        try {
            if (!rustFFI.isRustReady) {
                return result.success(RUST_NOT_READY)  
            }

            val stats = getStorageStats().apply {
                this["storage_type"] = "hardware_backed_keystore"
                this["encryption_type"] = "aes_256_gcm"
                this["key_strength"] = "256_bit"  
                this["rust_initialized"] = rustFFI.isRustReady
                this["timestamp"] = System.currentTimeMillis()
            }
            
            // Safety in case future nulls appear
            stats.entries.removeIf { it.value == null }

            // Store stats in Rust under well-known key
            val jsonString = JSONObject(stats).toString()
            rustFFI.storeSafe(STATS_KEY_HASH, jsonString) // Unique hash for "memguard_stats"

            result.success(true)  // Stats cached in Rust
        } catch (e: Exception) {
            result.error("GETSTATS_FAILED", e.message, null)
        }
    }

    private fun handleCleanupAll(call: MethodCall, result: Result) {
        try {
            // Delete all persistent files
            cleanupFiles()
            
            // Clear Rust cache if available
            if (rustFFI.isRustReady) { 
                rustFFI.cleanupAllSafe()
            }
            
            result.success(true)
        } catch (e: Exception) {
            result.error("CLEANUP_FAILED", e.message, null)
        }
    }

    // =============== ENCRYPTION METHODS =============== 
    private fun getSecureKey(): SecretKey {
        val keyStore = KeyStore.getInstance(keyStoreProvider)
        keyStore.load(null)

        // Phase 1: Try to get existing key and validate it
        if (keyStore.containsAlias(keyStoreAlias)) {
            val entry = keyStore.getEntry(keyStoreAlias, null) as? KeyStore.SecretKeyEntry
            if (entry != null) {
                // Just return the key - let encryption/decryption fail if invalid
                return entry.secretKey
            }
        }
        

        // Phase 2: Key missing or dead → create new one
        debugPrint.i(tag, "Creating new KeyStore key (first use or recovery)")
        return createSecureKey()
    }

    private fun createSecureKey(): SecretKey {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.M) {
            throw IllegalStateException(
                "KeyStore requires Android 6.0+ (current: ${Build.VERSION.SDK_INT})"
            )
        }
        
        return if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
            createModernKey()
        } else {
            createLegacyKey()
        }
    }

    @RequiresApi(Build.VERSION_CODES.P)
    private fun createModernKey(): SecretKey {
        val keyGenerator = KeyGenerator.getInstance(
            KeyProperties.KEY_ALGORITHM_AES, 
            keyStoreProvider
        )
        
        val builder = KeyGenParameterSpec.Builder(
            keyStoreAlias,
            KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
        )
            .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
            .setKeySize(keyLength)
            .setRandomizedEncryptionRequired(true)
            .setUserAuthenticationRequired(false) // We do not require user auth
            .setInvalidatedByBiometricEnrollment(false)
        
        // Try StrongBox for maximum security
        builder.setIsStrongBoxBacked(true)
        
        return try {
            keyGenerator.init(builder.build())
            keyGenerator.generateKey()
        } catch (e: StrongBoxUnavailableException) {
            // Fallback to TEE
            builder.setIsStrongBoxBacked(false)
            keyGenerator.init(builder.build())
            keyGenerator.generateKey()
        }
    }

    @RequiresApi(Build.VERSION_CODES.M)
    private fun createLegacyKey(): SecretKey {
        val keyGenerator = KeyGenerator.getInstance(
            KeyProperties.KEY_ALGORITHM_AES, 
            keyStoreProvider
        )
        
        val spec = KeyGenParameterSpec.Builder(
            keyStoreAlias,
            KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
        )
            .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
            .setKeySize(keyLength)
            .setRandomizedEncryptionRequired(true)
            .build()
        
        keyGenerator.init(spec)
        return keyGenerator.generateKey()
    }

    private fun encrypt(value: String, keyName: String): String {
        val key = getSecureKey()
        val cipher = Cipher.getInstance(encryptionAlgorithm)

        // Generate cryptographically secure random 12-byte IV (GCM standard)
        val iv = ByteArray(12)
        SecureRandom().apply { nextBytes(iv) }

        // Explicitly pass the random IV — never rely on cipher.iv
        cipher.init(Cipher.ENCRYPT_MODE, key, GCMParameterSpec(gcmTagLengthBits, iv))

        val encryptedBytes = cipher.doFinal(value.toByteArray(StandardCharsets.UTF_8))

        // Format: [12-byte IV] || [ciphertext || 16-byte auth tag]
        val combined = ByteArray(iv.size + encryptedBytes.size)
        System.arraycopy(iv, 0, combined, 0, iv.size)
        System.arraycopy(encryptedBytes, 0, combined, iv.size, encryptedBytes.size)

        return Base64.encodeToString(combined, Base64.NO_WRAP)
    }

    private fun decrypt(encryptedBase64: String, keyName: String): String {
        val combined = try {
            Base64.decode(encryptedBase64, Base64.NO_WRAP)
        } catch (e: IllegalArgumentException) {
            throw IllegalArgumentException("Invalid Base64 encoded data")
        }

        if (combined.size <= 12) {
            throw IllegalArgumentException("Encrypted data too short (missing IV or ciphertext)")
        }

        val iv = combined.copyOfRange(0, 12)
        val encryptedData = combined.copyOfRange(12, combined.size)

        val key = getSecureKey()
        val cipher = Cipher.getInstance(encryptionAlgorithm)

        try {
            cipher.init(Cipher.DECRYPT_MODE, key, GCMParameterSpec(gcmTagLengthBits, iv))
            val decryptedBytes = cipher.doFinal(encryptedData)
            return String(decryptedBytes, StandardCharsets.UTF_8)
        } catch (e: javax.crypto.AEADBadTagException) {
            // This is CRITICAL: authentication tag failed → data was tampered with or corrupted
            throw SecurityException("Encrypted data integrity check failed — possible tampering or corruption", e)
        } catch (e: Exception) {
            // Re-throw other cipher errors with context
            throw SecurityException("Decryption failed (invalid key, corrupted data, or device state changed)", e)
        }
    }


    // =============== FILE OPERATIONS ===============
    private fun getStorageDirectory(): File {
        val dir = File(context.filesDir, STORAGE_DIR)
        
        if (!dir.exists()) {
            dir.mkdirs()
        }
        return dir
    }

    private fun getFileName(key: String): String {
        val hash = MessageDigest.getInstance("SHA-256")
            .digest(key.toByteArray(StandardCharsets.UTF_8))
        return "mg_${hash.toHexString()}.dat"
    }

    private fun ByteArray.toHexString() = joinToString("") { "%02x".format(it) }
    
    private val fileLocks = ConcurrentHashMap<String, Any>()

    private fun getLock(key: String) = fileLocks.computeIfAbsent(key) { Any() }

    private fun saveToFile(key: String, encryptedData: String) {
        val lock = getLock(key)
        synchronized(lock) {
            File(getStorageDirectory(), getFileName(key)).bufferedWriter().use {
                it.write(encryptedData)
            }
        }
    }

    private fun readFromFile(key: String): String? {
        val lock = getLock(key)
        synchronized(lock) {
            val file = File(getStorageDirectory(), getFileName(key))
            if (!file.exists()) return null
            return file.bufferedReader().use { it.readText() }
        }
    }

    private fun deleteFile(key: String) {
        val lock = getLock(key)
        synchronized(lock) {
            val file = File(getStorageDirectory(), getFileName(key))
            if (file.exists() && !file.delete()) {
                debugPrint.w(tag, "Failed deleting ${file.name}")
            }
        } 
    }


    private fun fileExists(key: String): Boolean {
        val lock = getLock(key)
        synchronized(lock) {
            val file = File(getStorageDirectory(), getFileName(key))
            return file.exists()
        }
    }


    private val cleanupLock = Any()

    private fun cleanupFiles() {
        synchronized(cleanupLock) {
            getFilesInDirectory().forEach {
                if (!it.delete()) debugPrint.w(tag, "Failed deleting ${it.name}")
            }
        }
    }


    private fun getFilesInDirectory(): List<File> {
        val dir = getStorageDirectory()
        return dir.listFiles { file -> 
            file.isFile && file.name.startsWith("mg_") && file.name.endsWith(".dat")
        }?.toList() ?: emptyList()
    }

    private fun getStorageStats(): MutableMap<String, Any> {
        val stats = mutableMapOf<String, Any>()
        val files = getFilesInDirectory()
        
        stats["package_name"] = context.packageName
        stats["directory_path"] = getStorageDirectory().absolutePath
        stats["items_count"] = files.size
        stats["total_size_bytes"] = files.sumOf { it.length() }
        
        return stats
    }
}