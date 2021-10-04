mod credential;

use std::ffi::{c_void, CStr, CString};
use windows::IntoParam;

use bindings::Windows::Win32::{
    Foundation::*,
    Security::Credentials::*,
    System::SystemInformation::*,
};

const NO_FLAGS: u32 = 0;
const GENERIC_CREDENTIAL: u32 = 1;

pub fn read_credential<'a>(target: impl IntoParam<'a, PWSTR>) -> Option<credential::Credential> {
    let cred: *mut *mut CREDENTIALW = std::ptr::null_mut();
    let result = unsafe { CredReadW(target, GENERIC_CREDENTIAL, NO_FLAGS, cred) };
    if result == false {
        None
    } else {
        let credential = credential::Credential{
            secret: unsafe { CStr::from_ptr((**cred).CredentialBlob as *const i8).to_str().unwrap().to_string() },
        };
        unsafe { CredFree(cred as *const c_void) };

        Some(credential)
    }
}

pub fn write_credential(target: &str, val: credential::Credential) {
    let filetime = Box::new(FILETIME {
        dwLowDateTime: 0,
        dwHighDateTime: 0,
    });
    let filetime: *mut FILETIME = Box::into_raw(filetime);
    unsafe { GetSystemTimeAsFileTime(filetime) };

    let secret_len = val.secret.len();

    let target_cstr = CString::new(target).unwrap();
    let secret_cstr = CString::new(val.secret).unwrap();

    let target_ptr = target_cstr.as_ptr();
    let secret_ptr = secret_cstr.as_ptr();

    let cred = CREDENTIALW{
        Flags: CRED_FLAGS(0),
        Type: CRED_TYPE(0),
        TargetName: PWSTR(target_ptr as *mut u16),
        Comment: PWSTR(std::ptr::null_mut() as *mut u16),
        LastWritten: unsafe { *filetime },
        CredentialBlobSize: secret_len as u32,
        CredentialBlob: secret_ptr as *mut u8,
        Persist: CRED_PERSIST(1),
        AttributeCount: 0,
        Attributes: std::ptr::null_mut(),
        TargetAlias: PWSTR(std::ptr::null_mut() as *mut u16),
        UserName: PWSTR(std::ptr::null_mut() as *mut u16),
    };

    unsafe { CredWriteW(&cred, NO_FLAGS) };
    unsafe { drop(Box::from_raw(filetime)) }
}

pub fn delete_credential<'a>(target: impl IntoParam<'a, PWSTR>) {
    unsafe { CredDeleteW(target, GENERIC_CREDENTIAL, NO_FLAGS) };
}
