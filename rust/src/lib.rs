use std::collections::HashMap;
use std::ffi::{CStr, CString};
use std::os::raw::{c_char, c_uchar};
use std::ptr;
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};
use chacha20poly1305::{ChaCha20Poly1305, Key, KeyInit};
use chacha20poly1305::aead::{Aead, OsRng};
use hex;
use log::{error, info};
use once_cell::sync::OnceCell;
use rand_core::RngCore;
use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

// =============== CONFIG ===============
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemGuardConfig {
    pub enable_encryption: bool,
    pub auto_cleanup: bool,
    pub cleanup_interval_ms: u64,
}

impl Default for MemGuardConfig {
    fn default() -> Self {
        Self {
            enable_encryption: false,
            auto_cleanup: true,
            cleanup_interval_ms: 600_000, // 10 minutes default
        }
    }
}

// =============== SECURE DATA ===============
#[allow(dead_code)]
#[derive(Clone)]
struct SecureEntry {
    ciphertext: Vec<u8>,
    nonce: [u8; 12],
    key_id: String,
    created_at: u64,
    last_accessed: u64,
    access_count: u64,
    size: usize,
}

impl Zeroize for SecureEntry {
    fn zeroize(&mut self) {
        self.ciphertext.zeroize();
        self.nonce.zeroize();
        self.key_id.zeroize();
    }
}

impl Drop for SecureEntry {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl SecureEntry {
    fn new(plaintext: &str, master_key: &[u8]) -> Result<Self> {
        let mut nonce = [0u8; 12];
        OsRng.fill_bytes(&mut nonce);
        
        let data_key = Self::derive_key(master_key, &nonce)?;
        let cipher = ChaCha20Poly1305::new(&data_key);
        
        let ciphertext = cipher
            .encrypt(&nonce.into(), plaintext.as_bytes())
            .map_err(|e| anyhow::anyhow!("Encryption failed: {:?}", e))?;
        
        let now = current_timestamp();
        
        Ok(Self {
            ciphertext,
            nonce,
            key_id: hex::encode(&nonce[..8]),
            created_at: now,
            last_accessed: now,
            access_count: 0,
            size: plaintext.as_bytes().len(),
        })
    }
    
    fn new_unencrypted(plaintext: &str) -> Self {
        let now = current_timestamp();
        
        Self {
            ciphertext: plaintext.as_bytes().to_vec(),
            nonce: [0u8; 12],
            key_id: String::new(),
            created_at: now,
            last_accessed: now,
            access_count: 0,
            size: plaintext.as_bytes().len(),
        }
    }
    
    fn decrypt(&mut self, master_key: &[u8]) -> Result<String> {
        let data_key = Self::derive_key(master_key, &self.nonce)?;
        let cipher = ChaCha20Poly1305::new(&data_key);
        
        let plaintext_bytes = cipher
            .decrypt(&self.nonce.into(), self.ciphertext.as_ref())
            .map_err(|e| anyhow::anyhow!("Decryption failed: {:?}", e))?;
        
        self.last_accessed = current_timestamp();
        self.access_count += 1;
        
        String::from_utf8(plaintext_bytes).context("Invalid UTF-8")
    }
    
    fn get_plaintext(&mut self) -> Result<String> {
        let plaintext = String::from_utf8(self.ciphertext.clone())
            .context("Invalid UTF-8")?;
        
        self.last_accessed = current_timestamp();
        self.access_count += 1;
        
        Ok(plaintext)
    }
    
    fn derive_key(master_key: &[u8], nonce: &[u8; 12]) -> Result<Key> {
        // Use BLAKE3 for fast key derivation
        let mut hasher = blake3::Hasher::new();
        hasher.update(master_key);
        hasher.update(nonce);
        
        let hash = hasher.finalize();
        let key_bytes: [u8; 32] = hash.as_bytes()[..32].try_into().unwrap();
        
        Ok(Key::clone_from_slice(&key_bytes))
    }
    
    fn is_expired(&self, max_age_ms: u64) -> bool {
        if max_age_ms == 0 {
            return false;
        }
        
        let now = current_timestamp();
        let max_age_secs = max_age_ms / 1000;
        
        (now - self.last_accessed) > max_age_secs
    }
}

// =============== MEMORY STORAGE ENGINE ===============
struct MemGuardStorage {
    config: MemGuardConfig,
    master_key: [u8; 32],
    
    // Thread-safe storage
    data: Arc<RwLock<HashMap<String, SecureEntry>>>,
    
    // Statistics
    stats: Arc<Mutex<StorageStats>>,
    
    // Background cleanup
    last_cleanup: Arc<Mutex<Instant>>,
}

#[derive(Debug, Default, Serialize)]
struct StorageStats {
    total_stores: u64,
    total_retrieves: u64,
    total_deletes: u64,
    total_cleanups: u64,
    memory_usage_bytes: u64,
    items_count: usize,
    last_cleanup_time: u64,
}

impl MemGuardStorage {
    fn new(config: MemGuardConfig) -> Result<Self> {
        let mut master_key = [0u8; 32];
        if config.enable_encryption {
            OsRng.fill_bytes(&mut master_key);
        }
        
        Ok(Self {
            config,
            master_key,
            data: Arc::new(RwLock::new(HashMap::new())),
            stats: Arc::new(Mutex::new(StorageStats::default())),
            last_cleanup: Arc::new(Mutex::new(Instant::now())),
        })
    }
    
    fn store(&self, key: &str, value: &str) -> Result<()> {
        let entry = if self.config.enable_encryption {
            SecureEntry::new(value, &self.master_key)?
        } else {
            SecureEntry::new_unencrypted(value)
        };
        
        let size = entry.size;
        
        {
            let mut data = self.data.write().unwrap();
            data.insert(key.to_string(), entry);
        }
        
        {
            let mut stats = self.stats.lock().unwrap();
            stats.total_stores += 1;
            stats.memory_usage_bytes += size as u64;
            stats.items_count = self.data.read().unwrap().len();
        }
        
        // Auto cleanup if enabled
        if self.config.auto_cleanup {
            self.try_cleanup();
        }
        
        info!("Stored: {} ({} bytes)", key, size);
        Ok(())
    }
    
    fn retrieve(&self, key: &str) -> Result<Option<String>> {
        let result = {
            let mut data = self.data.write().unwrap();
            
            if let Some(entry) = data.get_mut(key) {
                if self.config.enable_encryption {
                    entry.decrypt(&self.master_key).map(Some)
                } else {
                    entry.get_plaintext().map(Some)
                }
            } else {
                Ok(None)
            }
        };
        
        if let Ok(Some(_)) = result {
            let mut stats = self.stats.lock().unwrap();
            stats.total_retrieves += 1;
        }
        
        result
    }
    
    fn delete(&self, key: &str) -> Result<bool> {
        let removed = {
            let mut data = self.data.write().unwrap();
            data.remove(key).is_some()
        };
        
        if removed {
            let mut stats = self.stats.lock().unwrap();
            stats.total_deletes += 1;
            stats.items_count = self.data.read().unwrap().len();
            info!("Deleted: {}", key);
        }
        
        Ok(removed)
    }
    
    fn contains(&self, key: &str) -> bool {
        let data = self.data.read().unwrap();
        data.contains_key(key)
    }
    
    fn _get_keys(&self) -> Vec<String> {
        let data = self.data.read().unwrap();
        data.keys().cloned().collect()
    }
    
    fn get_buffer(&self, key: &str) -> Result<Option<(Vec<u8>, usize)>> {
        let value = self.retrieve(key)?;
        
        if let Some(value) = value {
            let bytes = value.into_bytes();
            let len = bytes.len();
            Ok(Some((bytes, len)))
        } else {
            Ok(None)
        }
    }
    
    fn try_cleanup(&self) {
        if !self.config.auto_cleanup || self.config.cleanup_interval_ms == 0 {
            return;
        }
        
        let last_cleanup = self.last_cleanup.lock().unwrap();
        if last_cleanup.elapsed() < Duration::from_millis(self.config.cleanup_interval_ms) {
            return;
        }
        
        drop(last_cleanup);
        
        let cutoff_ms = self.config.cleanup_interval_ms;
        let _items_before = {
            let data = self.data.read().unwrap();
            data.len()
        };
        
        let mut expired_count = 0;
        let mut total_size_reclaimed = 0;
        
        {
            let mut data = self.data.write().unwrap();
            data.retain(|_key, entry| {
                if entry.is_expired(cutoff_ms) {
                    expired_count += 1;
                    total_size_reclaimed += entry.size;
                    false
                } else {
                    true
                }
            });
            
            // Shrink capacity if needed
            if data.capacity() > data.len() * 2 {
                data.shrink_to_fit();
            }
        }
        
        if expired_count > 0 {
            let mut stats = self.stats.lock().unwrap();
            stats.total_cleanups += 1;
            stats.memory_usage_bytes = stats.memory_usage_bytes.saturating_sub(total_size_reclaimed as u64);
            stats.items_count = self.data.read().unwrap().len();
            stats.last_cleanup_time = current_timestamp();
            
            info!("Cleanup removed {} items ({} bytes reclaimed)", expired_count, total_size_reclaimed);
        }
        
        *self.last_cleanup.lock().unwrap() = Instant::now();
    }
    
    fn force_cleanup(&self) {
        let _items_before = {
            let data = self.data.read().unwrap();
            data.len()
        };
        
        {
            let mut data = self.data.write().unwrap();
            let old_size: usize = data.values().map(|e| e.size).sum();
            data.clear();
            data.shrink_to_fit();
            
            let mut stats = self.stats.lock().unwrap();
            stats.total_cleanups += 1;
            stats.memory_usage_bytes = stats.memory_usage_bytes.saturating_sub(old_size as u64);
            stats.items_count = 0;
            stats.last_cleanup_time = current_timestamp();
            
            info!("Force cleanup removed all items ({} bytes)", old_size);
        }
        
        *self.last_cleanup.lock().unwrap() = Instant::now();
    }
    
    fn get_stats(&self) -> StorageStats {
        let stats = self.stats.lock().unwrap();
        let data = self.data.read().unwrap();
        
        StorageStats {
            items_count: data.len(),
            ..*stats
        }
    }
    
    fn get_memory_usage(&self) -> usize {
        let data = self.data.read().unwrap();
        data.values().map(|e| e.size).sum()
    }
}

// Helper function
fn current_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

// =============== GLOBAL INSTANCE ===============
static STORAGE_INSTANCE: OnceCell<Arc<MemGuardStorage>> = OnceCell::new();

fn init_storage(config: MemGuardConfig) -> Result<()> {
    let storage = MemGuardStorage::new(config)?;
    STORAGE_INSTANCE.set(Arc::new(storage))
        .map_err(|_| anyhow::anyhow!("Storage already initialized"))
}

fn get_storage() -> Result<Arc<MemGuardStorage>> {
    STORAGE_INSTANCE.get()
        .cloned()
        .ok_or_else(|| anyhow::anyhow!("Storage not initialized"))
}

// =============== FFI EXPORTS ===============

// ===== C-COMPATIBLE FUNCTIONS (For Dart FFI) =====

#[no_mangle]
pub extern "C" fn memguard_init(
    enable_encryption: bool,
    auto_cleanup: bool,
    cleanup_interval_ms: u64,
) -> i32 {
    std::panic::catch_unwind(|| {
        let _ = env_logger::try_init();
        
        let config = MemGuardConfig {
            enable_encryption,
            auto_cleanup,
            cleanup_interval_ms,
        };
        
        match init_storage(config) {
            Ok(_) => {
                info!("MemGuard initialized successfully");
                0
            }
            Err(e) => {
                error!("Failed to initialize: {}", e);
                -1
            }
        }
    }).unwrap_or(-2)
}

#[no_mangle]
pub extern "C" fn memguard_init_with_config(config_json: *const c_char) -> i32 {
    if config_json.is_null() {
        return -3;
    }
    
    std::panic::catch_unwind(|| {
        let _ = env_logger::try_init();
        
        let config_str = unsafe { CStr::from_ptr(config_json).to_string_lossy() };
        
        match serde_json::from_str::<MemGuardConfig>(&config_str) {
            Ok(config) => {
                // Check if already initialized
                if STORAGE_INSTANCE.get().is_some() {
                    info!("MemGuard already initialized (hot restart)");
                    return 0;
                }
                
                match init_storage(config) {
                    Ok(_) => {
                        info!("MemGuard initialized with config");
                        0
                    }
                    Err(e) => {
                        error!("Init failed: {}", e);
                        -1
                    }
                }
            }
            Err(e) => {
                error!("Invalid config JSON: {}", e);
                -2
            }
        }
    }).unwrap_or(-4)
}

#[no_mangle]
pub extern "C" fn memguard_store(key: *const c_char, value: *const c_char) -> i32 {
    if key.is_null() || value.is_null() {
        return -1;
    }
    
    std::panic::catch_unwind(|| {
        let key_str = unsafe { CStr::from_ptr(key).to_string_lossy() };
        let value_str = unsafe { CStr::from_ptr(value).to_string_lossy() };
        
        match get_storage() {
            Ok(storage) => {
                match storage.store(&key_str, &value_str) {
                    Ok(_) => 0,
                    Err(e) => {
                        error!("Store failed: {}", e);
                        -2
                    }
                }
            }
            Err(_) => {
                error!("Storage not initialized");
                -3
            }
        }
    }).unwrap_or(-4)
}

#[no_mangle]
pub extern "C" fn memguard_retrieve(key: *const c_char) -> *mut c_char {
    if key.is_null() {
        return ptr::null_mut();
    }
    
    std::panic::catch_unwind(|| {
        let key_str = unsafe { CStr::from_ptr(key).to_string_lossy() };
        
        match get_storage() {
            Ok(storage) => {
                match storage.retrieve(&key_str) {
                    Ok(Some(value)) => {
                        match CString::new(value) {
                            Ok(cstring) => cstring.into_raw(),
                            Err(_) => ptr::null_mut(),
                        }
                    }
                    Ok(None) => ptr::null_mut(),
                    Err(e) => {
                        error!("Retrieve failed: {}", e);
                        ptr::null_mut()
                    }
                }
            }
            Err(_) => {
                error!("Storage not initialized");
                ptr::null_mut()
            }
        }
    }).unwrap_or(ptr::null_mut())
}

#[no_mangle]
pub extern "C" fn memguard_get_buffer(
    key: *const c_char,
    length_out: *mut i64,
) -> *const c_uchar {
    if key.is_null() || length_out.is_null() {
        return ptr::null();
    }
    
    std::panic::catch_unwind(|| {
        let key_str = unsafe { CStr::from_ptr(key).to_string_lossy() };
        
        match get_storage() {
            Ok(storage) => {
                match storage.get_buffer(&key_str) {
                    Ok(Some((buffer, length))) => {
                        unsafe {
                            *length_out = length as i64;
                        }
                        let ptr = buffer.as_ptr();
                        std::mem::forget(buffer);
                        ptr as *const c_uchar
                    }
                    Ok(None) => {
                        unsafe {
                            *length_out = 0;
                        }
                        ptr::null()
                    }
                    Err(e) => {
                        error!("Get buffer failed: {}", e);
                        unsafe {
                            *length_out = 0;
                        }
                        ptr::null()
                    }
                }
            }
            Err(_) => {
                error!("Storage not initialized");
                unsafe {
                    *length_out = 0;
                }
                ptr::null()
            }
        }
    }).unwrap_or(ptr::null())
}

#[no_mangle]
pub extern "C" fn memguard_zeroize_buffer(ptr: *mut c_uchar, length: i64) {
    if ptr.is_null() || length <= 0 {
        return;
    }
    
    unsafe {
        let slice = std::slice::from_raw_parts_mut(ptr, length as usize);
        slice.zeroize();
        
        let _ = Vec::from_raw_parts(ptr, length as usize, length as usize);
    }
    
    info!("Buffer zeroized: {} bytes", length);
}

#[no_mangle]
pub extern "C" fn memguard_delete(key: *const c_char) -> i32 {
    if key.is_null() {
        return -1;
    }
    
    std::panic::catch_unwind(|| {
        let key_str = unsafe { CStr::from_ptr(key).to_string_lossy() };
        
        match get_storage() {
            Ok(storage) => {
                match storage.delete(&key_str) {
                    Ok(true) => 0,
                    Ok(false) => 1,
                    Err(e) => {
                        error!("Delete failed: {}", e);
                        -2
                    }
                }
            }
            Err(_) => {
                error!("Storage not initialized");
                -3
            }
        }
    }).unwrap_or(-4)
}

#[no_mangle]
pub extern "C" fn memguard_contains(key: *const c_char) -> i32 {
    if key.is_null() {
        return 0;
    }
    
    std::panic::catch_unwind(|| {
        let key_str = unsafe { CStr::from_ptr(key).to_string_lossy() };
        
        match get_storage() {
            Ok(storage) => {
                if storage.contains(&key_str) {
                    1
                } else {
                    0
                }
            }
            Err(_) => {
                -1
            }
        }
    }).unwrap_or(-2)
}

#[no_mangle]
pub extern "C" fn memguard_cleanup() {
    std::panic::catch_unwind(|| {
        if let Ok(storage) = get_storage() {
            storage.try_cleanup();
        }
    }).ok();
}

#[no_mangle]
pub extern "C" fn memguard_cleanup_all() {
    std::panic::catch_unwind(|| {
        if let Ok(storage) = get_storage() {
            storage.force_cleanup();
        }
    }).ok();
}

#[no_mangle]
pub extern "C" fn memguard_get_stats() -> *mut c_char {
    std::panic::catch_unwind(|| {
        match get_storage() {
            Ok(storage) => {
                let stats = storage.get_stats();
                match serde_json::to_string(&stats) {
                    Ok(json) => {
                        match CString::new(json) {
                            Ok(cstring) => cstring.into_raw(),
                            Err(_) => ptr::null_mut(),
                        }
                    }
                    Err(e) => {
                        error!("Stats serialization failed: {}", e);
                        ptr::null_mut()
                    }
                }
            }
            Err(_) => {
                ptr::null_mut()
            }
        }
    }).unwrap_or(ptr::null_mut())
}

#[no_mangle]
pub extern "C" fn memguard_get_memory_usage() -> usize {
    std::panic::catch_unwind(|| {
        match get_storage() {
            Ok(storage) => storage.get_memory_usage(),
            Err(_) => 0,
        }
    }).unwrap_or(0)
}

#[no_mangle]
pub extern "C" fn memguard_clear_all() -> i32 {
    std::panic::catch_unwind(|| {
        match get_storage() {
            Ok(storage) => {
                storage.force_cleanup();
                0
            }
            Err(_) => -1,
        }
    }).unwrap_or(-2)
}

#[no_mangle]
pub extern "C" fn memguard_is_initialized() -> i32 {
    if STORAGE_INSTANCE.get().is_some() {
        1
    } else {
        0
    }
}

#[repr(C)]
pub struct MemGuardConfigC {
    pub enable_encryption: bool,
    pub auto_cleanup: bool,
    pub cleanup_interval_ms: u64,
}

#[no_mangle]
pub extern "C" fn memguard_init_c(config: MemGuardConfigC) -> i32 {
    let rust_config = MemGuardConfig {
        enable_encryption: config.enable_encryption,
        auto_cleanup: config.auto_cleanup,
        cleanup_interval_ms: config.cleanup_interval_ms,
    };
    
    memguard_init(
        rust_config.enable_encryption,
        rust_config.auto_cleanup,
        rust_config.cleanup_interval_ms,
    )
}

// ===== JNI-COMPATIBLE FUNCTIONS (For Kotlin) =====
// Note: These use JNI naming convention: Java_package_class_method

use jni::{
    JNIEnv,
    objects::{JClass, JString},
    sys::{jint, jstring},
};

// Helper to convert JNI strings to Rust strings
fn jstring_to_string(env: &mut JNIEnv, jstr: JString) -> Result<String, jni::errors::Error> {
    let java_str = env.get_string(&jstr)?;
    Ok(java_str.to_string_lossy().into_owned())
}

// Helper to create JNI string from Rust string
fn string_to_jstring(env: &mut JNIEnv, string: &str) -> Result<jstring, jni::errors::Error> {
    let jstring = env.new_string(string)?;
    Ok(jstring.into_raw())
}

// JNI function for initialization with config
#[no_mangle]
#[allow(non_snake_case)]
pub extern "system" fn Java_com_flagodna_memguard_MemGuardPlugin_00024RustFFI_memguard_1init_1with_1config(
    mut env: JNIEnv,
    _class: JClass,
    config_json: JString,
) -> jint {
    match jstring_to_string(&mut env, config_json) {
        Ok(config_str) => {
            match serde_json::from_str::<MemGuardConfig>(&config_str) {
                Ok(config) => {
                    if STORAGE_INSTANCE.get().is_some() {
                        0 // Already initialized, return success
                    } else {
                        match init_storage(config) {
                            Ok(_) => 0,
                            Err(_) => -1,
                        }
                    }
                }
                Err(_) => -2,
            }
        }
        Err(_) => -3,
    }
}

// JNI function for store
#[no_mangle]
#[allow(non_snake_case)]
pub extern "system" fn Java_com_flagodna_memguard_MemGuardPlugin_00024RustFFI_memguard_1store(
    mut env: JNIEnv,
    _class: JClass,
    key: JString,
    value: JString,
) -> jint {
    match (jstring_to_string(&mut env, key), jstring_to_string(&mut env, value)) {
        (Ok(key_str), Ok(value_str)) => {
            match get_storage() {
                Ok(storage) => {
                    match storage.store(&key_str, &value_str) {
                        Ok(_) => 0,
                        Err(_) => -2,
                    }
                }
                Err(_) => -3,
            }
        }
        _ => -1,
    }
}

// JNI function for retrieve
#[no_mangle]
#[allow(non_snake_case)]
pub extern "system" fn Java_com_flagodna_memguard_MemGuardPlugin_00024RustFFI_memguard_1retrieve(
    mut env: JNIEnv,
    _class: JClass,
    key: JString,
) -> jstring {
    match jstring_to_string(&mut env, key) {
        Ok(key_str) => {
            match get_storage() {
                Ok(storage) => {
                    match storage.retrieve(&key_str) {
                        Ok(Some(value)) => {
                            match string_to_jstring(&mut env, &value) {
                                Ok(jstr) => jstr,
                                Err(_) => std::ptr::null_mut(),
                            }
                        }
                        _ => std::ptr::null_mut(),
                    }
                }
                Err(_) => std::ptr::null_mut(),
            }
        }
        Err(_) => std::ptr::null_mut(),
    }
}

// JNI function for delete
#[no_mangle]
#[allow(non_snake_case)]
pub extern "system" fn Java_com_flagodna_memguard_MemGuardPlugin_00024RustFFI_memguard_1delete(
    mut env: JNIEnv,
    _class: JClass,
    key: JString,
) -> jint {
    match jstring_to_string(&mut env, key) {
        Ok(key_str) => {
            match get_storage() {
                Ok(storage) => {
                    match storage.delete(&key_str) {
                        Ok(true) => 0,
                        Ok(false) => 1,
                        Err(_) => -2,
                    }
                }
                Err(_) => -3,
            }
        }
        Err(_) => -1,
    }
}

// JNI function for contains
#[no_mangle]
#[allow(non_snake_case)]
pub extern "system" fn Java_com_flagodna_memguard_MemGuardPlugin_00024RustFFI_memguard_1contains(
    mut env: JNIEnv,
    _class: JClass,
    key: JString,
) -> jint {
    match jstring_to_string(&mut env, key) {
        Ok(key_str) => {
            match get_storage() {
                Ok(storage) => {
                    if storage.contains(&key_str) {
                        1
                    } else {
                        0
                    }
                }
                Err(_) => -1,
            }
        }
        Err(_) => -1,
    }
}

// JNI function for cleanup memory
#[no_mangle]
#[allow(non_snake_case)]
pub extern "system" fn Java_com_flagodna_memguard_MemGuardPlugin_00024RustFFI_memguard_1cleanup_1memory(
    _env: JNIEnv,
    _class: JClass,
) {
    if let Ok(storage) = get_storage() {
        storage.try_cleanup();
    }
}

// JNI function for cleanup all
#[no_mangle]
#[allow(non_snake_case)]
pub extern "system" fn Java_com_flagodna_memguard_MemGuardPlugin_00024RustFFI_memguard_1cleanup_1all(
    _env: JNIEnv,
    _class: JClass,
) {
    if let Ok(storage) = get_storage() {
        storage.force_cleanup();
    }
}

// JNI function for get stats
#[no_mangle]
#[allow(non_snake_case)]
pub extern "system" fn Java_com_flagodna_memguard_MemGuardPlugin_00024RustFFI_memguard_1get_1stats(
    mut env: JNIEnv,
    _class: JClass,
) -> jstring {
    match get_storage() {
        Ok(storage) => {
            let stats = storage.get_stats();
            match serde_json::to_string(&stats) {
                Ok(json) => {
                    match string_to_jstring(&mut env, &json) {
                        Ok(jstr) => jstr,
                        Err(_) => std::ptr::null_mut(),
                    }
                }
                Err(_) => std::ptr::null_mut(),
            }
        }
        Err(_) => std::ptr::null_mut(),
    }
}

// JNI function for is initialized
#[no_mangle]
#[allow(non_snake_case)]
pub extern "system" fn Java_com_flagodna_memguard_MemGuardPlugin_00024RustFFI_memguard_1is_1initialized(
    _env: JNIEnv,
    _class: JClass,
) -> jint {
    if STORAGE_INSTANCE.get().is_some() {
        1
    } else {
        0
    }
}

// JNI function for get memory usage
#[no_mangle]
#[allow(non_snake_case)]
pub extern "system" fn Java_com_flagodna_memguard_MemGuardPlugin_00024RustFFI_memguard_1get_1memory_1usage(
    _env: JNIEnv,
    _class: JClass,
) -> jint {
    match get_storage() {
        Ok(storage) => storage.get_memory_usage() as jint,
        Err(_) => 0,
    }
}

// JNI function for clear all
#[no_mangle]
#[allow(non_snake_case)]
pub extern "system" fn Java_com_flagodna_memguard_MemGuardPlugin_00024RustFFI_memguard_1clear_1all(
    _env: JNIEnv,
    _class: JClass,
) -> jint {
    match get_storage() {
        Ok(storage) => {
            storage.force_cleanup();
            0
        }
        Err(_) => -1,
    }
}