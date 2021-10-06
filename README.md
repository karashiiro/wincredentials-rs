[![Crates.io](https://img.shields.io/crates/v/wincredentials)](https://crates.io/crates/wincredentials)
[![docs.rs](https://img.shields.io/docsrs/wincredentials)](https://docs.rs/wincredentials)

# wincredentials-rs
A wrapper around the Win32 API credential management functions. Currently only supports generic credentials.

## Example
```rs
use wincredentials::*;

fn main() {
  let _ = write_credential("test_target", credential::Credential{
    username: "username".to_owned(),
    secret: "test".to_owned(),
  });
  
  let cred = read_credential("test_target").unwrap();
  println!(cred.username);
  println!(cred.secret);
  
  let _ = delete_credential("test_target");
}
```
