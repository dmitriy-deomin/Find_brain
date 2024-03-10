use std::ffi::{CString};
use libloading::{Library, Symbol};
use std::os::raw::{c_char};

pub struct IceLibrary {
    ice: Library,
}

impl IceLibrary {
    pub fn new() -> Self {
        let ice = unsafe { Library::new("ice_secp256k1.dll") }.expect("Failed to load library");
        IceLibrary { ice }
    }

    pub(crate) fn init_secp256_lib(&self) {
        let init_secp256_lib: Symbol<unsafe extern "C" fn() -> ()> = unsafe { self.ice.get(b"init_secp256_lib") }.expect("Failed init");
        unsafe { init_secp256_lib() };
    }

    pub fn privatekey_to_publickey(&self, hex: &Vec<u8>) -> [u8; 65] {
        let privatekey_to_publickey: Symbol<unsafe extern "C" fn(*const c_char,  *mut u8) -> ()> =
            unsafe { self.ice.get(b"scalar_multiplication") }.unwrap();

        let private_key = CString::new(hex::encode(hex)).expect("Failed to create CString");
        let mut res = [0u8; 65];

        unsafe { privatekey_to_publickey(private_key.as_ptr(), res.as_mut_ptr()) };

        res
    }
    pub fn publickey_uncompres_to_compres(&self, pub_hex: &[u8; 65]) -> [u8; 33] {
        let mut result = [0u8; 33];

        if pub_hex[64] % 2 == 0 {
            result[0] = 2;
        } else {
            result[0] = 3;
        }
        result[1..33].copy_from_slice(&pub_hex[1..33]);
        result
    }
}