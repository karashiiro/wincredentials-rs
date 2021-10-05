# wincredentials-rs
A wrapper around the Win32 API credential management functions. Currently only supports generic credentials.

## Example
```rs
using wincredentials::*;

fn main() {
  let _ = write_credential("test_target", credential::Credential{
    secret: "test".to_owned(),
  });
  
  let cred = read_credential("test_target");
  println!(cred.unwrap().secret);
  
  let _ = delete_credential("test_target");
}
```
