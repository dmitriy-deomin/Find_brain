use std::ffi::{CStr, CString};
use libloading::{Library, Symbol};
use std::os::raw::{c_char, c_int};
use base58::FromBase58;

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

    pub fn publickey_to_address(&self, addr_type: c_int, is_compressed: bool, pubkey: &[u8]) -> String {
        let pubkey_to_address: Symbol<unsafe extern "C" fn(c_int, bool, *const u8) -> *mut c_char> =
            unsafe { self.ice.get(b"pubkey_to_address") }.unwrap();

        unsafe {
            let result_ptr = pubkey_to_address(addr_type, is_compressed, pubkey.as_ptr());
            let address = CString::from_raw(result_ptr).into_string().expect("Failed to convert C string to Rust string");
            address
        }
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

    #[allow(invalid_value)]
    pub fn privatekey_to_h160_uncopress(&self, hexx: &str) -> [u8; 20] {
        let privatekey_to_h160: Symbol<unsafe extern "C" fn(i32, bool, *const c_char, *mut u8) -> ()> =
            unsafe { self.ice.get(b"privatekey_to_h160").unwrap() };
        let mut res: [u8; 20] = unsafe { std::mem::MaybeUninit::uninit().assume_init() };

        let private_key = CString::new(hexx).expect("Не удалось создать CString");

        unsafe { privatekey_to_h160(0, false, private_key.as_ptr(), res.as_mut_ptr()) };
        res
    }

    pub fn privatekey_to_address(&self, hex: &str) -> String {
        let privatekey_to_address: Symbol<unsafe extern "C" fn(i32, bool, *const i8) -> *mut i8> = unsafe { self.ice.get(b"privatekey_to_address") }.unwrap();
        let private_key = CString::new(hex).expect("Failed to create CString");
        let result = unsafe { privatekey_to_address(0, true, private_key.as_ptr()) };
        let result_str = unsafe { CStr::from_ptr(result) }.to_str().expect("Failed to convert C string to str");
        unsafe { libc::free(result as *mut libc::c_void) }; // Освобождаем память, выделенную внешней библиотекой
        result_str.to_owned() // Возвращаем владеющую строку
    }

    #[allow(invalid_value)]
    pub fn bech32_address_decode(&self, coin_type: i32, b32_addr: &str) -> String {
        let bech32_address_decode: Symbol<unsafe extern "C" fn(i32, *const c_char, *mut u8) -> ()> =
            unsafe { self.ice.get(b"bech32_address_decode").unwrap() };
        let mut h160: [u8; 20] = unsafe { std::mem::MaybeUninit::uninit().assume_init() };

        let address = CString::new(b32_addr).expect("Не удалось создать CString");

        unsafe { bech32_address_decode(coin_type,address.as_ptr(), h160.as_mut_ptr()) };
        h160.iter().map(|b| format!("{:02x}", b)).collect()
    }

    pub fn address_to_h160(&self, address: &str) -> String {
        let binding = address.from_base58().unwrap();
        let a = &binding.as_slice()[1..binding.len()-4];
        hex::encode(a)
    }

}