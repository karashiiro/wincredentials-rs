fn main() {
    windows::build! {
        Windows::Win32::Foundation::{BOOL, PWSTR, FILETIME},
        Windows::Win32::Security::Credentials::{CredReadW, CredWriteW, CredDeleteW, CredFree, CREDENTIALW, CRED_FLAGS, CRED_TYPE, CRED_PERSIST},
        Windows::Win32::System::SystemInformation::GetSystemTimeAsFileTime,
    };
}