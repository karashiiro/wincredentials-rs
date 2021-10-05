mod credential;

use std::ffi::c_void;
use windows::*;
use widestring::{U16CString, U16String};

use bindings::Windows::Win32::{
    Foundation::*,
    Security::Credentials::*,
    System::SystemInformation::*,
};

const NO_FLAGS: u32 = 0;
const GENERIC_CREDENTIAL: u32 = 1;

pub fn read_credential(target: &str) -> Result<credential::Credential> {
    let target_cstr = U16CString::from_str(target).unwrap();
    let target_ptr = target_cstr.as_ptr();

    let mut cred: *mut CREDENTIALW = std::ptr::null_mut();
    let cred_ptr: *mut *mut CREDENTIALW = &mut cred;
    unsafe { CredReadW(PWSTR(target_ptr as *mut u16), GENERIC_CREDENTIAL, NO_FLAGS, cred_ptr).ok()? };

    let credential = credential::Credential{
        secret: unsafe { U16String::from_ptr((*cred).CredentialBlob as *const u16, (*cred).CredentialBlobSize as usize / 2).to_string_lossy() },
    };
    unsafe { CredFree(cred as *const c_void) };

    Ok(credential)
}

pub fn write_credential(target: &str, val: credential::Credential) -> Result<()> {
    let filetime = Box::new(FILETIME {
        dwLowDateTime: 0,
        dwHighDateTime: 0,
    });
    let filetime: *mut FILETIME = Box::into_raw(filetime);
    unsafe { GetSystemTimeAsFileTime(filetime) };

    let secret_len = val.secret.len();

    let target_cstr = U16CString::from_str(target).unwrap();
    let secret_cstr = U16CString::from_str(val.secret).unwrap();
    let user_cstr = U16CString::from_str("").unwrap();

    let target_ptr = target_cstr.as_ptr();
    let secret_ptr = secret_cstr.as_ptr();
    let user_ptr = user_cstr.as_ptr();

    let cred = CREDENTIALW{
        Flags: CRED_FLAGS(NO_FLAGS),
        Type: CRED_TYPE(GENERIC_CREDENTIAL),
        TargetName: PWSTR(target_ptr as *mut u16),
        Comment: PWSTR(std::ptr::null_mut() as *mut u16),
        LastWritten: unsafe { *filetime },
        CredentialBlobSize: secret_len as u32 * 2,
        CredentialBlob: secret_ptr as *mut u8,
        Persist: CRED_PERSIST(1),
        AttributeCount: 0,
        Attributes: std::ptr::null_mut(),
        TargetAlias: PWSTR(std::ptr::null_mut() as *mut u16),
        UserName: PWSTR(user_ptr as *mut u16),
    };

    unsafe { CredWriteW(&cred, NO_FLAGS).ok()? };
    unsafe { drop(Box::from_raw(filetime)) }

    Ok(())
}

pub fn delete_credential(target: &str) -> Result<()> {
    let target_cstr = U16CString::from_str(target).unwrap();
    let target_ptr = target_cstr.as_ptr();
    unsafe { CredDeleteW(PWSTR(target_ptr as *mut u16), GENERIC_CREDENTIAL, NO_FLAGS).ok()? };

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn write_credential_is_ok_when_unset() {
        let target = "WINCREDENTIALS_RS_TEST_1";
        let secret = "testy";

        let _ = delete_credential(target);

        let res = write_credential(target, credential::Credential{
            secret: secret.to_owned(),
        });
        assert!(res.is_ok(), "{}", res.err().unwrap().to_string());
    }

    #[test]
    fn write_credential_is_ok_when_set() {
        let target = "WINCREDENTIALS_RS_TEST_2";
        let secret = "testy";

        let _ = delete_credential(target);
        let _ = write_credential(target, credential::Credential{
            secret: secret.to_owned(),
        });

        let res = write_credential(target, credential::Credential{
            secret: secret.to_owned(),
        });
        assert!(res.is_ok(), "{}", res.err().unwrap().to_string());
    }

    #[test]
    fn read_credential_is_err_when_unset() {
        let target = "WINCREDENTIALS_RS_TEST_3";

        let _ = delete_credential(target);

        let res = read_credential(target);
        assert!(res.is_err())
    }

    #[test]
    fn read_credential_is_ok_when_set() {
        let target = "WINCREDENTIALS_RS_TEST_4";
        let secret = "testy";

        let _ = delete_credential(target);

        let res = write_credential(target, credential::Credential{
            secret: secret.to_owned(),
        });
        assert!(res.is_ok(), "{}", res.err().unwrap().to_string());

        let res = read_credential(target);
        assert!(res.is_ok(), "{}", res.err().unwrap().to_string());

        assert_eq!(res.unwrap().secret, secret);
    }

    #[test]
    fn delete_credential_is_err_when_unset() {
        let target = "WINCREDENTIALS_RS_TEST_5";

        let _ = delete_credential(target);
        let res = delete_credential(target);
        assert!(res.is_err())
    }

    #[test]
    fn delete_credential_is_ok_when_set() {
        let target = "WINCREDENTIALS_RS_TEST_6";
        let secret = "testy";

        let _ = delete_credential(target);

        let res = write_credential(target, credential::Credential{
            secret: secret.to_owned(),
        });
        assert!(res.is_ok(), "{}", res.err().unwrap().to_string());

        let res = delete_credential(target);
        assert!(res.is_ok(), "{}", res.err().unwrap().to_string());
    }
}
