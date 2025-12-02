pub mod credential;
mod tests;

use std::ffi::c_void;
use widestring::{U16CString, U16String};
use windows::Win32::Security::Credentials::{
    CRED_FLAGS, CRED_PERSIST, CRED_TYPE, CREDENTIALW, CredDeleteW, CredFree, CredReadW, CredWriteW,
};
use windows::Win32::System::SystemInformation::GetSystemTimeAsFileTime;
use windows::core::PWSTR;

const NO_FLAGS: CRED_FLAGS = CRED_FLAGS(0);
const GENERIC_CREDENTIAL: CRED_TYPE = CRED_TYPE(1);

/// Reads the credential with the specified target name. If the operation
/// fails for any reason, including no credential existing, the result
/// will resolve to an error.
pub fn read_credential(target: &str) -> Result<credential::Credential, Box<dyn std::error::Error>> {
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
            None,
            cred_ptr,
        )?
    };

    // Read from the credential and convert it into something rustier
    let credential = unsafe {
        credential::Credential {
            username: U16CString::from_ptr_str((*cred).UserName.0 as *const u16).to_string_lossy(),
            // U16String takes the number of elements, not the number of bytes
            //
            // hence the division
            secret: U16String::from_ptr(
                (*cred).CredentialBlob as *const u16,
                (*cred).CredentialBlobSize as usize / 2,
            )
            .to_string_lossy(),
        }
    };

    // Free the credential we read
    unsafe { CredFree(cred as *const c_void) };

    Ok(credential)
}

/// Writes out the credential with the specified target name. If the operation
/// fails for any reason, the result will resolve to an error.
pub fn write_credential(
    target: &str,
    val: credential::Credential,
) -> Result<(), Box<dyn std::error::Error>> {
    unsafe {
        // Get the current time as a Windows file time
        let filetime = GetSystemTimeAsFileTime();

        // Convert all the things into UTF16
        let secret_len = val.secret.len();

        let target_cstr = U16CString::from_str(target).unwrap();
        let secret_cstr = U16CString::from_str(val.secret).unwrap();
        let user_cstr = U16CString::from_str(val.username).unwrap();

        let target_ptr = target_cstr.as_ptr();
        let secret_ptr = secret_cstr.as_ptr();
        let user_ptr = user_cstr.as_ptr();

        // Build our credential object
        let cred = CREDENTIALW {
            Flags: NO_FLAGS,
            Type: GENERIC_CREDENTIAL,
            TargetName: PWSTR(target_ptr as *mut u16),
            Comment: PWSTR(std::ptr::null_mut() as *mut u16),
            LastWritten: filetime,
            CredentialBlobSize: secret_len as u32 * 2,
            CredentialBlob: secret_ptr as *mut u8,
            Persist: CRED_PERSIST(1),
            AttributeCount: 0,
            Attributes: std::ptr::null_mut(),
            TargetAlias: PWSTR(std::ptr::null_mut() as *mut u16),
            UserName: PWSTR(user_ptr as *mut u16),
        };

        // Write the credential out
        CredWriteW(&cred, NO_FLAGS.0)?
    };

    // Free the file time object we got
    //unsafe { drop(Box::from_raw(filetime)) }
    Ok(())
}

/// Deletes the credential with the specified target name. If the operation
/// fails for any reason, the result will resolve to an error.
pub fn delete_credential(target: &str) -> Result<(), Box<dyn std::error::Error>> {
    // Convert the target to UTF16
    let target_cstr = U16CString::from_str(target).unwrap();
    let target_ptr = target_cstr.as_ptr();

    // Delete the credential
    unsafe { CredDeleteW(PWSTR(target_ptr as *mut u16), GENERIC_CREDENTIAL, None)? };

    Ok(())
}
