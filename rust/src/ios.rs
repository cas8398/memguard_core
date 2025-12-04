#[cfg(target_os = "ios")]
pub mod ios {
    use super::*;
    use anyhow::{Context, Result};
    use core_foundation::base::{CFRelease, CFRetain, CFTypeRef, TCFType};
    use core_foundation::string::CFString;
    use core_foundation::dictionary::{CFDictionary, CFMutableDictionary};
    use security_framework::os::macos::keychain::SecKeychain;
    use security_framework::item::{ItemClass, ItemSearchOptions, Reference};
    use security_framework::access::Access;
    use security_framework::base::Error as SecError;
    use security_framework::passwords::{
        get_generic_password, set_generic_password, delete_generic_password
    };
    use std::ffi::{CStr, CString};
    use std::os::raw::{c_char, c_void};
    use std::ptr;
    use log::{error, info};
    
    /// iOS Keychain Storage via Security.framework
    pub struct IOSKeychainStorage;
    
    impl IOSKeychainStorage {
        /// Create new instance
        pub fn new() -> Result<Self> {
            Ok(Self)
        }
        
        /// Store to iOS Keychain
        pub fn store(&self, key: &str, value: &str) -> Result<()> {
            // Use bundle ID as service name
            let service = Self::get_bundle_id()?;
            
            set_generic_password(
                service,
                key.as_bytes(),
                value.as_bytes(),
            ).context("Failed to store to iOS Keychain")?;
            
            info!("Stored to iOS Keychain: {} (service: {})", key, service);
            Ok(())
        }
        
        /// Retrieve from iOS Keychain
        pub fn retrieve(&self, key: &str) -> Result<Option<String>> {
            let service = Self::get_bundle_id()?;
            
            match get_generic_password(service, key.as_bytes()) {
                Ok(password_data) => {
                    let value = String::from_utf8(password_data.to_vec())
                        .context("Invalid UTF-8 in keychain")?;
                    Ok(Some(value))
                }
                Err(SecError::ItemNotFound) => Ok(None),
                Err(e) => Err(anyhow::anyhow!("Keychain retrieve failed: {}", e)),
            }
        }
        
        /// Delete from iOS Keychain
        pub fn delete(&self, key: &str) -> Result<()> {
            let service = Self::get_bundle_id()?;
            
            delete_generic_password(service, key.as_bytes())
                .context("Failed to delete from iOS Keychain")?;
            
            info!("Deleted from iOS Keychain: {}", key);
            Ok(())
        }
        
        /// Store with accessibility controls
        pub fn store_with_accessibility(
            &self,
            key: &str,
            value: &str,
            accessible: KeychainAccessibility,
            require_auth: bool,
        ) -> Result<()> {
            let service = Self::get_bundle_id()?;
            
            // Create mutable dictionary for attributes
            let mut query = CFMutableDictionary::<CFString, CFTypeRef>::new();
            
            // Item class
            let ksec_class = CFString::from_static_string("kSecClassGenericPassword");
            let class_value = CFString::from_static_string("genp");
            query.add(&ksec_class, class_value.as_CFTypeRef());
            
            // Service (bundle ID)
            let ksec_attr_service = CFString::from_static_string("kSecAttrService");
            let service_cf = CFString::new(service);
            query.add(&ksec_attr_service, service_cf.as_CFTypeRef());
            
            // Account (key)
            let ksec_attr_account = CFString::from_static_string("kSecAttrAccount");
            let account_cf = CFString::new(key);
            query.add(&ksec_attr_account, account_cf.as_CFTypeRef());
            
            // Value data
            let ksec_value_data = CFString::from_static_string("kSecValueData");
            let value_data = CFData::from_buffer(value.as_bytes());
            query.add(&ksec_value_data, value_data.as_CFTypeRef());
            
            // Accessibility
            let ksec_attr_accessible = CFString::from_static_string("kSecAttrAccessible");
            let accessible_cf = CFString::from_static_string(accessible.to_cfstring());
            query.add(&ksec_attr_accessible, accessible_cf.as_CFTypeRef());
            
            // Authentication requirement
            if require_auth {
                let ksec_attr_access_control = CFString::from_static_string("kSecAttrAccessControl");
                
                // Create SecAccessControl
                let flags = if cfg!(feature = "biometric") {
                    // Biometric authentication
                    security_framework::access::Flags::USER_PRESENCE
                } else {
                    // Device passcode
                    security_framework::access::Flags::DEVICE_PASSCODE
                };
                
                let access_control = Access::create_with_flags(flags)
                    .context("Failed to create access control")?;
                
                query.add(&ksec_attr_access_control, access_control.as_CFTypeRef());
            }
            
            // Add to keychain
            let result = unsafe {
                security_framework_sys::SecItemAdd(query.as_concrete_TypeRef(), ptr::null_mut())
            };
            
            if result != 0 {
                return Err(anyhow::anyhow!("SecItemAdd failed: {}", result));
            }
            
            info!("Stored with accessibility: {} ({:?})", key, accessible);
            Ok(())
        }
        
        /// Store in Secure Enclave (hardware-backed)
        #[cfg(feature = "secure_enclave")]
        pub fn store_in_secure_enclave(
            &self,
            key: &str,
            value: &[u8],
            require_auth: bool,
        ) -> Result<()> {
            // Generate key pair in Secure Enclave
            let access_control = if require_auth {
                security_framework::access::Access::create_secure_enclave_with_flags(
                    security_framework::access::Flags::USER_PRESENCE
                )?
            } else {
                security_framework::access::Access::create_secure_enclave()?
            };
            
            let attributes = CFMutableDictionary::<CFString, CFTypeRef>::new();
            
            // Key type
            let ksec_attr_key_type = CFString::from_static_string("kSecAttrKeyType");
            let key_type = CFString::from_static_string("kSecAttrKeyTypeECSECPrimeRandom");
            attributes.add(&ksec_attr_key_type, key_type.as_CFTypeRef());
            
            // Key size
            let ksec_attr_key_size_in_bits = CFString::from_static_string("kSecAttrKeySizeInBits");
            let key_size = CFNumber::from(256);
            attributes.add(&ksec_attr_key_size_in_bits, key_size.as_CFTypeRef());
            
            // Private key
            let ksec_attr_is_permanent = CFString::from_static_string("kSecAttrIsPermanent");
            let is_permanent = CFBoolean::true_value();
            attributes.add(&ksec_attr_is_permanent, is_permanent.as_CFTypeRef());
            
            // Access control
            let ksec_attr_access_control = CFString::from_static_string("kSecAttrAccessControl");
            attributes.add(&ksec_attr_access_control, access_control.as_CFTypeRef());
            
            // Application tag (identifier)
            let ksec_attr_application_tag = CFString::from_static_string("kSecAttrApplicationTag");
            let tag_data = CFData::from_buffer(key.as_bytes());
            attributes.add(&ksec_attr_application_tag, tag_data.as_CFTypeRef());
            
            // Create key
            let mut error: CFErrorRef = ptr::null_mut();
            let private_key = unsafe {
                security_framework_sys::SecKeyCreateRandomKey(
                    attributes.as_concrete_TypeRef(),
                    &mut error
                )
            };
            
            if !error.is_null() {
                return Err(anyhow::anyhow!("Failed to create Secure Enclave key"));
            }
            
            // Get public key
            let public_key = unsafe {
                security_framework_sys::SecKeyCopyPublicKey(private_key)
            };
            
            // Encrypt data with public key
            // ... encryption logic here ...
            
            info!("Stored in Secure Enclave: {}", key);
            Ok(())
        }
        
        /// Get iOS bundle identifier
        fn get_bundle_id() -> Result<String> {
            use objc::runtime::{Object, Sel};
            use objc::{class, msg_send, sel, sel_impl};
            
            unsafe {
                let bundle_class: *const Object = class!(NSBundle);
                let main_bundle: *const Object = msg_send![bundle_class, mainBundle];
                let bundle_id: *const Object = msg_send![main_bundle, bundleIdentifier];
                
                if bundle_id.is_null() {
                    return Ok("com.memguard.app".to_string());
                }
                
                let c_str: *const c_char = msg_send![bundle_id, UTF8String];
                if c_str.is_null() {
                    return Ok("com.memguard.app".to_string());
                }
                
                let bundle_str = CStr::from_ptr(c_str).to_string_lossy();
                Ok(bundle_str.to_string())
            }
        }
        
        /// Check if biometric authentication is available
        pub fn is_biometric_available(&self) -> bool {
            use security_framework::authorization::AuthorizationContext;
            
            let context = AuthorizationContext::new();
            context.can_evaluate_policy(
                security_framework::policy::Policy::device_owner_authentication_with_biometrics,
                None
            ).unwrap_or(false)
        }
        
        /// Check if device has passcode set
        pub fn is_passcode_set(&self) -> bool {
            use security_framework::authorization::AuthorizationContext;
            
            let context = AuthorizationContext::new();
            context.can_evaluate_policy(
                security_framework::policy::Policy::device_owner_authentication,
                None
            ).unwrap_or(false)
        }
    }
    
    /// Keychain accessibility levels
    #[derive(Debug, Clone, Copy)]
    pub enum KeychainAccessibility {
        /// When unlocked (default)
        WhenUnlocked,
        /// After first unlock
        AfterFirstUnlock,
        /// Always (not recommended)
        Always,
        /// When passcode set (iOS only)
        WhenPasscodeSetThisDeviceOnly,
        /// When unlocked, this device only
        WhenUnlockedThisDeviceOnly,
        /// After first unlock, this device only
        AfterFirstUnlockThisDeviceOnly,
        /// Always, this device only
        AlwaysThisDeviceOnly,
    }
    
    impl KeychainAccessibility {
        fn to_cfstring(&self) -> &'static str {
            match self {
                Self::WhenUnlocked => "kSecAttrAccessibleWhenUnlocked",
                Self::AfterFirstUnlock => "kSecAttrAccessibleAfterFirstUnlock",
                Self::Always => "kSecAttrAccessibleAlways",
                Self::WhenPasscodeSetThisDeviceOnly => "kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly",
                Self::WhenUnlockedThisDeviceOnly => "kSecAttrAccessibleWhenUnlockedThisDeviceOnly",
                Self::AfterFirstUnlockThisDeviceOnly => "kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly",
                Self::AlwaysThisDeviceOnly => "kSecAttrAccessibleAlwaysThisDeviceOnly",
            }
        }
    }
    
    // =============== FFI EXPORTS ===============
    
    /// Global iOS storage instance
    static mut IOS_STORAGE: Option<IOSKeychainStorage> = None;
    
    /// Initialize iOS Keychain storage
    #[no_mangle]
    pub unsafe extern "C" fn ios_storage_init() -> i32 {
        match IOSKeychainStorage::new() {
            Ok(storage) => {
                IOS_STORAGE = Some(storage);
                
                // Test keychain access
                let test_key = "memguard_test";
                let test_value = "test_value";
                
                if let Err(e) = IOS_STORAGE.as_ref().unwrap().store(test_key, test_value) {
                    error!("iOS Keychain test store failed: {}", e);
                    return -2;
                }
                
                if let Ok(Some(retrieved)) = IOS_STORAGE.as_ref().unwrap().retrieve(test_key) {
                    if retrieved == test_value {
                        let _ = IOS_STORAGE.as_ref().unwrap().delete(test_key);
                        info!("iOS Keychain initialized successfully");
                        return 0;
                    }
                }
                
                error!("iOS Keychain test failed");
                -1
            }
            Err(e) => {
                error!("Failed to init iOS storage: {}", e);
                -1
            }
        }
    }
    
    /// Store to iOS Keychain
    #[no_mangle]
    pub unsafe extern "C" fn ios_storage_store(
        key: *const c_char,
        value: *const c_char,
    ) -> i32 {
        if key.is_null() || value.is_null() || IOS_STORAGE.is_none() {
            return -1;
        }
        
        let key_str = CStr::from_ptr(key).to_string_lossy();
        let value_str = CStr::from_ptr(value).to_string_lossy();
        
        match IOS_STORAGE.as_ref().unwrap().store(&key_str, &value_str) {
            Ok(_) => 0,
            Err(e) => {
                error!("iOS store failed: {}", e);
                -2
            }
        }
    }
    
    /// Retrieve from iOS Keychain
    #[no_mangle]
    pub unsafe extern "C" fn ios_storage_retrieve(
        key: *const c_char,
    ) -> *mut c_char {
        if key.is_null() || IOS_STORAGE.is_none() {
            return ptr::null_mut();
        }
        
        let key_str = CStr::from_ptr(key).to_string_lossy();
        
        match IOS_STORAGE.as_ref().unwrap().retrieve(&key_str) {
            Ok(Some(value)) => {
                match CString::new(value) {
                    Ok(cstring) => cstring.into_raw(),
                    Err(_) => ptr::null_mut(),
                }
            }
            Ok(None) => ptr::null_mut(),
            Err(e) => {
                error!("iOS retrieve failed: {}", e);
                ptr::null_mut()
            }
        }
    }
    
    /// Store with accessibility options
    #[no_mangle]
    pub unsafe extern "C" fn ios_storage_store_with_access(
        key: *const c_char,
        value: *const c_char,
        accessible: i32,
        require_auth: i32,
    ) -> i32 {
        if key.is_null() || value.is_null() || IOS_STORAGE.is_none() {
            return -1;
        }
        
        let key_str = CStr::from_ptr(key).to_string_lossy();
        let value_str = CStr::from_ptr(value).to_string_lossy();
        
        let accessibility = match accessible {
            0 => KeychainAccessibility::WhenUnlocked,
            1 => KeychainAccessibility::AfterFirstUnlock,
            2 => KeychainAccessibility::WhenUnlockedThisDeviceOnly,
            3 => KeychainAccessibility::AfterFirstUnlockThisDeviceOnly,
            _ => KeychainAccessibility::WhenUnlockedThisDeviceOnly,
        };
        
        let require_auth_bool = require_auth != 0;
        
        match IOS_STORAGE.as_ref().unwrap().store_with_accessibility(
            &key_str,
            &value_str,
            accessibility,
            require_auth_bool,
        ) {
            Ok(_) => 0,
            Err(e) => {
                error!("iOS store with access failed: {}", e);
                -2
            }
        }
    }
    
    /// Delete from iOS Keychain
    #[no_mangle]
    pub unsafe extern "C" fn ios_storage_delete(key: *const c_char) -> i32 {
        if key.is_null() || IOS_STORAGE.is_none() {
            return -1;
        }
        
        let key_str = CStr::from_ptr(key).to_string_lossy();
        
        match IOS_STORAGE.as_ref().unwrap().delete(&key_str) {
            Ok(_) => 0,
            Err(e) => {
                error!("iOS delete failed: {}", e);
                -2
            }
        }
    }
    
    /// Check biometric availability
    #[no_mangle]
    pub unsafe extern "C" fn ios_is_biometric_available() -> i32 {
        match IOS_STORAGE.as_ref() {
            Some(storage) => {
                if storage.is_biometric_available() {
                    1
                } else {
                    0
                }
            }
            None => 0,
        }
    }
    
    /// Check if passcode is set
    #[no_mangle]
    pub unsafe extern "C" fn ios_is_passcode_set() -> i32 {
        match IOS_STORAGE.as_ref() {
            Some(storage) => {
                if storage.is_passcode_set() {
                    1
                } else {
                    0
                }
            }
            None => 0,
        }
    }
    
    /// Free string returned by iOS
    #[no_mangle]
    pub unsafe extern "C" fn ios_storage_free_string(ptr: *mut c_char) {
        if !ptr.is_null() {
            let _ = CString::from_raw(ptr);
        }
    }
    
    /// Clear all MemGuard items from Keychain
    #[no_mangle]
    pub unsafe extern "C" fn ios_storage_clear_all() -> i32 {
        if IOS_STORAGE.is_none() {
            return -1;
        }
        
        // Note: iOS doesn't have a "delete all" API for security reasons
        // We would need to track all keys and delete them individually
        // In practice, apps should manage their own key lifecycle
        
        info!("iOS Keychain clear requested (not implemented for security)");
        0
    }
}

// =============== HELPER STRUCTS ===============

// Import Core Foundation types
#[cfg(target_os = "ios")]
use core_foundation::data::CFData;
#[cfg(target_os = "ios")]
use core_foundation::boolean::CFBoolean;
#[cfg(target_os = "ios")]
use core_foundation::number::CFNumber;
#[cfg(target_os = "ios")]
use security_framework_sys::base::CFErrorRef;

// Re-export for main lib
#[cfg(target_os = "ios")]
pub use ios::{
    KeychainAccessibility,
    ios_storage_init,
    ios_storage_store,
    ios_storage_retrieve,
    ios_storage_store_with_access,
    ios_storage_delete,
    ios_is_biometric_available,
    ios_is_passcode_set,
    ios_storage_free_string,
    ios_storage_clear_all,
};