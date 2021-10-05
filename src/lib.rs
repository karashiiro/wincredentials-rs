pub mod credential;

use std::ffi::c_void;
use widestring::{U16CString, U16String};
use windows::*;

use wincredentials_bindings::Windows::Win32::{
    Foundation::*, Security::Credentials::*, System::SystemInformation::*,
};

const NO_FLAGS: u32 = 0;
const GENERIC_CREDENTIAL: u32 = 1;

// Reads the credential with the specified target name. If the operation
// fails for any reason, including no credential existing, the result
// will resolve to an error.
pub fn read_credential(target: &str) -> Result<credential::Credential> {
    // Convert the target to UTF16
    let target_cstr = U16CString::from_str(target).unwrap();
    let target_ptr = target_cstr.as_ptr();

    // Allocate a pointer for the credential and read it
    let mut cred: *mut CREDENTIALW = std::ptr::null_mut();
    let cred_ptr: *mut *mut CREDENTIALW = &mut cred;
    unsafe {
        CredReadW(
            PWSTR(target_ptr as *mut u16),
            GENERIC_CREDENTIAL,
            NO_FLAGS,
            cred_ptr,
        )
        .ok()?
    };

    // Read from the credential and convert it into something rustier
    let credential = credential::Credential {
        // U16String takes the number of elements, not the number of bytes
        //
        // hence the division
        secret: unsafe {
            U16String::from_ptr(
                (*cred).CredentialBlob as *const u16,
                (*cred).CredentialBlobSize as usize / 2,
            )
            .to_string_lossy()
        },
    };

    // Free the credential we read
    unsafe { CredFree(cred as *const c_void) };

    Ok(credential)
}

// Writes out the credential with the specified target name. If the operation
// fails for any reason, the result will resolve to an error.
pub fn write_credential(target: &str, val: credential::Credential) -> Result<()> {
    // Get the current time as a Windows file time
    let filetime = Box::new(FILETIME {
        dwLowDateTime: 0,
        dwHighDateTime: 0,
    });
    let filetime: *mut FILETIME = Box::into_raw(filetime);
    unsafe { GetSystemTimeAsFileTime(filetime) };

    // Convert all the things into UTF16
    let secret_len = val.secret.len();

    let target_cstr = U16CString::from_str(target).unwrap();
    let secret_cstr = U16CString::from_str(val.secret).unwrap();
    let user_cstr = U16CString::from_str("").unwrap();

    let target_ptr = target_cstr.as_ptr();
    let secret_ptr = secret_cstr.as_ptr();
    let user_ptr = user_cstr.as_ptr();

    // Build our credential object
    let cred = CREDENTIALW {
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

    // Write the credential out
    unsafe { CredWriteW(&cred, NO_FLAGS).ok()? };

    // Free the file time object we got
    unsafe { drop(Box::from_raw(filetime)) }

    Ok(())
}

// Deletes the credential with the specified target name. If the operation
// fails for any reason, the result will resolve to an error.
pub fn delete_credential(target: &str) -> Result<()> {
    // Convert the target to UTF16
    let target_cstr = U16CString::from_str(target).unwrap();
    let target_ptr = target_cstr.as_ptr();

    // Delete the credential
    unsafe { CredDeleteW(PWSTR(target_ptr as *mut u16), GENERIC_CREDENTIAL, NO_FLAGS).ok()? };

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    // We use different target names in each test to allow them to run in parallel
    // without interfering with each other.

    // The secret is deliberately chosen to have an odd number of elements because we
    // divide its length at some point.

    #[test]
    fn write_credential_is_ok_when_unset() {
        let target = "WINCREDENTIALS_RS_TEST_1";
        let secret = "testy";

        let _ = delete_credential(target);

        let res = write_credential(
            target,
            credential::Credential {
                secret: secret.to_owned(),
            },
        );
        assert!(res.is_ok(), "{}", res.err().unwrap().to_string());
    }

    #[test]
    fn write_credential_is_ok_when_set() {
        let target = "WINCREDENTIALS_RS_TEST_2";
        let secret = "testy";

        let _ = delete_credential(target);
        let _ = write_credential(
            target,
            credential::Credential {
                secret: secret.to_owned(),
            },
        );

        let res = write_credential(
            target,
            credential::Credential {
                secret: secret.to_owned(),
            },
        );
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

        let res = write_credential(
            target,
            credential::Credential {
                secret: secret.to_owned(),
            },
        );
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

        let res = write_credential(
            target,
            credential::Credential {
                secret: secret.to_owned(),
            },
        );
        assert!(res.is_ok(), "{}", res.err().unwrap().to_string());

        let res = delete_credential(target);
        assert!(res.is_ok(), "{}", res.err().unwrap().to_string());
    }
}
