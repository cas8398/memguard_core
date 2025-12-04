use jni::{
    objects::{JClass, JObject, JString, JValue},
    JNIEnv, JavaVM,
};
use anyhow::{Context, Result};
use std::ffi::{CStr, CString};
use std::ptr;
use log::{error, info};

#[cfg(target_os = "android")]
pub mod android {
    use super::*;
    use ndk_context::AndroidContext;
    
    /// Direct Android secure storage via JNI (NO plugin needed)
    pub struct AndroidSecureStorage {
        jvm: JavaVM,
    }
    
    impl AndroidSecureStorage {
        /// Create instance with existing JVM (from Flutter)
        pub unsafe fn from_existing_jvm() -> Result<Self> {
            // Get JVM from Android context
            let android_context: AndroidContext = ndk_context::android_context();
            let jvm_ptr = android_context.vm().as_ptr() as *mut _;
            
            let jvm = JavaVM::from_raw(jvm_ptr)
                .context("Failed to create JavaVM from raw pointer")?;
            
            Ok(Self { jvm })
        }
        
        /// Store to Android's EncryptedSharedPreferences
        pub fn store(&self, key: &str, value: &str) -> Result<()> {
            let mut env = self.jvm.attach_current_thread()
                .context("Failed to attach JNI thread")?;
            
            // Find Android Context (from Flutter's JNI)
            let context = self.get_android_context(&mut env)?;
            
            // Call Android's EncryptedSharedPreferences directly
            let master_key = self.create_master_key(&mut env, &context)?;
            let prefs = self.create_encrypted_prefs(&mut env, &context, &master_key)?;
            
            // Store the value
            let edit = env.call_method(
                &prefs, 
                "edit", 
                "()Landroid/content/SharedPreferences$Editor;", 
                &[]
            )?;
            let edit = edit.l()?;
            
            let jkey = env.new_string(key)?;
            let jvalue = env.new_string(value)?;
            
            env.call_method(
                &edit, 
                "putString", 
                "(Ljava/lang/String;Ljava/lang/String;)Landroid/content/SharedPreferences$Editor;",
                &[
                    JValue::from(&jkey),
                    JValue::from(&jvalue)
                ]
            )?;
            
            env.call_method(&edit, "apply", "()V", &[])?;
            
            info!("Stored to Android secure storage: {}", key);
            Ok(())
        }
        
        /// Retrieve from Android's secure storage
        pub fn retrieve(&self, key: &str) -> Result<Option<String>> {
            let mut env = self.jvm.attach_current_thread()
                .context("Failed to attach JNI thread")?;
            
            let context = self.get_android_context(&mut env)?;
            let master_key = self.create_master_key(&mut env, &context)?;
            let prefs = self.create_encrypted_prefs(&mut env, &context, &master_key)?;
            
            let jkey = env.new_string(key)?;
            
            let result = env.call_method(
                &prefs,
                "getString",
                "(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;",
                &[
                    JValue::from(&jkey),
                    JValue::Null
                ]
            )?;
            
            match result {
                JValue::Object(obj) if !obj.is_null() => {
                    let jstr = JString::from(obj);
                    let rust_str = env.get_string(&jstr)?.into();
                    Ok(Some(rust_str))
                }
                _ => Ok(None),
            }
        }
        
        // =============== HELPER METHODS ===============
        
        /// Get Android Application Context from Flutter
        fn get_android_context<'a>(&self, env: &'a mut JNIEnv) -> Result<JObject<'a>> {
            // Try to get context from FlutterJNI
            match env.find_class("io/flutter/embedding/engine/FlutterJNI") {
                Ok(flutter_loader) => {
                    let context = env.call_static_method(
                        flutter_loader,
                        "getContext",
                        "()Landroid/content/Context;",
                        &[],
                    )?.l()?;
                    Ok(context)
                }
                Err(_) => {
                    // Fallback: get context from current activity
                    let activity_class = env.find_class("android/app/ActivityThread")?;
                    let activity = env.call_static_method(
                        activity_class,
                        "currentActivity",
                        "()Landroid/app/Activity;",
                        &[],
                    )?.l()?;
                    Ok(activity)
                }
            }
        }
        
        /// Create MasterKey for EncryptedSharedPreferences
        fn create_master_key<'a>(
            &self,
            env: &'a mut JNIEnv,
            context: &JObject,
        ) -> Result<JObject<'a>> {
            let master_key_class = env.find_class(
                "androidx/security/crypto/MasterKey"
            )?;
            
            let master_key_builder = env.new_object(
                master_key_class,
                "(Landroid/content/Context;)V",
                &[JValue::from(context)],
            )?;
            
            let key_scheme = self.get_enum_value(env, "androidx/security/crypto/MasterKey$KeyScheme", "AES256_GCM")?;
            
            env.call_method(
                &master_key_builder,
                "setKeyScheme",
                "(Landroidx/security/crypto/MasterKey$KeyScheme;)Landroidx/security/crypto/MasterKey$Builder;",
                &[JValue::from(&key_scheme)]
            )?;
            
            let master_key = env.call_method(
                &master_key_builder,
                "build",
                "()Landroidx/security/crypto/MasterKey;",
                &[],
            )?.l()?;
            
            Ok(master_key)
        }
        
        /// Create EncryptedSharedPreferences instance
        fn create_encrypted_prefs<'a>(
            &self,
            env: &'a mut JNIEnv,
            context: &JObject,
            master_key: &JObject,
        ) -> Result<JObject<'a>> {
            let encrypted_prefs_class = env.find_class(
                "androidx/security/crypto/EncryptedSharedPreferences"
            )?;
            
            let prefs_name = env.new_string("memguard_secure_prefs")?;
            
            let key_scheme = self.get_enum_value(
                env, 
                "androidx/security/crypto/EncryptedSharedPreferences$PrefKeyEncryptionScheme", 
                "AES256_SIV"
            )?;
            
            let value_scheme = self.get_enum_value(
                env, 
                "androidx/security/crypto/EncryptedSharedPreferences$PrefValueEncryptionScheme", 
                "AES256_GCM"
            )?;
            
            let prefs = env.call_static_method(
                encrypted_prefs_class,
                "create",
                "(Landroid/content/Context;Ljava/lang/String;Landroidx/security/crypto/MasterKey;Landroidx/security/crypto/EncryptedSharedPreferences$PrefKeyEncryptionScheme;Landroidx/security/crypto/EncryptedSharedPreferences$PrefValueEncryptionScheme;)Landroid/content/SharedPreferences;",
                &[
                    JValue::from(context),
                    JValue::from(&prefs_name),
                    JValue::from(master_key),
                    JValue::from(&key_scheme),
                    JValue::from(&value_scheme),
                ],
            )?.l()?;
            
            Ok(prefs)
        }
        
        /// Get enum value by name
        fn get_enum_value<'a>(
            &self,
            env: &'a mut JNIEnv,
            class_name: &str,
            value_name: &str,
        ) -> Result<JObject<'a>> {
            let enum_class = env.find_class(class_name)?;
            let value = env.get_static_field(enum_class, value_name, format!("L{};", class_name))?;
            Ok(value.l()?)
        }
        
        /// Use Android KeyStore directly (alternative)
        pub fn store_to_keystore(&self, alias: &str, _data: &[u8]) -> Result<()> {
            let mut env = self.jvm.attach_current_thread()?;
            
            let key_store_class = env.find_class("java/security/KeyStore")?;
            
            // Get KeyStore instance
            let key_store_type = env.new_string("AndroidKeyStore")?;
            let key_store = env.call_static_method(
                key_store_class,
                "getInstance",
                "(Ljava/lang/String;)Ljava/security/KeyStore;",
                &[JValue::from(&key_store_type)],
            )?.l()?;
            
            env.call_method(
                &key_store, 
                "load", 
                "(Ljava/security/KeyStore$LoadStoreParameter;)V", 
                &[JValue::Null]
            )?;
            
            // Generate key
            let key_gen_class = env.find_class("javax/crypto/KeyGenerator")?;
            let algo = env.new_string("AES")?;
            let provider = env.new_string("AndroidKeyStore")?;
            
            let key_gen = env.call_static_method(
                key_gen_class,
                "getInstance",
                "(Ljava/lang/String;Ljava/lang/String;)Ljavax/crypto/KeyGenerator;",
                &[
                    JValue::from(&algo),
                    JValue::from(&provider),
                ],
            )?.l()?;
            
            let builder_class = env.find_class("android/security/keystore/KeyGenParameterSpec$Builder")?;
            let alias_str = env.new_string(alias)?;
            
            let builder = env.new_object(
                builder_class,
                "(Ljava/lang/String;I)V",
                &[
                    JValue::from(&alias_str),
                    JValue::Int(3), // PURPOSE_ENCRYPT | PURPOSE_DECRYPT
                ],
            )?;
            
            // Configure key - create arrays
            let block_mode_class = env.find_class("java/lang/String")?;
            let block_modes = env.new_object_array(1, block_mode_class, env.new_string("GCM")?)?;
            
            env.call_method(
                &builder,
                "setBlockModes",
                "([Ljava/lang/String;)Landroid/security/keystore/KeyGenParameterSpec$Builder;",
                &[JValue::from(&block_modes)],
            )?;
            
            let paddings = env.new_object_array(1, block_mode_class, env.new_string("NoPadding")?)?;
            
            env.call_method(
                &builder,
                "setEncryptionPaddings",
                "([Ljava/lang/String;)Landroid/security/keystore/KeyGenParameterSpec$Builder;",
                &[JValue::from(&paddings)],
            )?;
            
            env.call_method(
                &builder, 
                "setKeySize", 
                "(I)Landroid/security/keystore/KeyGenParameterSpec$Builder;", 
                &[JValue::Int(256)]
            )?;
            
            let spec = env.call_method(
                &builder, 
                "build", 
                "()Landroid/security/keystore/KeyGenParameterSpec;", 
                &[]
            )?.l()?;
            
            env.call_method(
                &key_gen, 
                "init", 
                "(Ljava/security/spec/AlgorithmParameterSpec;)V", 
                &[JValue::from(&spec)]
            )?;
            
            env.call_method(&key_gen, "generateKey", "()Ljavax/crypto/SecretKey;", &[])?;
            
            info!("Generated KeyStore key: {}", alias);
            Ok(())
        }
    }
    
    // =============== FFI EXPORTS ===============
    
    /// Global Android storage instance
    static mut ANDROID_STORAGE: Option<AndroidSecureStorage> = None;
    
    /// Initialize Android storage (called from Rust init)
    #[no_mangle]
    pub unsafe extern "C" fn android_storage_init() -> i32 {
        match AndroidSecureStorage::from_existing_jvm() {
            Ok(storage) => {
                ANDROID_STORAGE = Some(storage);
                0 // Success
            }
            Err(e) => {
                error!("Failed to init Android storage: {}", e);
                -1 // Failed
            }
        }
    }
    
    /// Store to Android secure storage
    #[no_mangle]
    pub unsafe extern "C" fn android_storage_store(
        key: *const c_char,
        value: *const c_char,
    ) -> i32 {
        if key.is_null() || value.is_null() || ANDROID_STORAGE.is_none() {
            return -1;
        }
        
        let key_str = CStr::from_ptr(key).to_string_lossy();
        let value_str = CStr::from_ptr(value).to_string_lossy();
        
        match ANDROID_STORAGE.as_ref().unwrap().store(&key_str, &value_str) {
            Ok(_) => 0,
            Err(e) => {
                error!("Android store failed: {}", e);
                -2
            }
        }
    }
    
    /// Retrieve from Android secure storage
    #[no_mangle]
    pub unsafe extern "C" fn android_storage_retrieve(
        key: *const c_char,
    ) -> *mut c_char {
        if key.is_null() || ANDROID_STORAGE.is_none() {
            return ptr::null_mut();
        }
        
        let key_str = CStr::from_ptr(key).to_string_lossy();
        
        match ANDROID_STORAGE.as_ref().unwrap().retrieve(&key_str) {
            Ok(Some(value)) => {
                match CString::new(value) {
                    Ok(cstring) => cstring.into_raw(),
                    Err(_) => ptr::null_mut(),
                }
            }
            Ok(None) => ptr::null_mut(),
            Err(e) => {
                error!("Android retrieve failed: {}", e);
                ptr::null_mut()
            }
        }
    }
    
    /// Free string returned by Android
    #[no_mangle]
    pub unsafe extern "C" fn android_storage_free_string(ptr: *mut c_char) {
        if !ptr.is_null() {
            let _ = CString::from_raw(ptr);
        }
    }
}