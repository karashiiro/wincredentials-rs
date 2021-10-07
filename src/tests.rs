#![cfg(test)]

use super::*;

// We use different target names in each test to allow them to run in parallel
// without interfering with each other.

// The secret is deliberately chosen to have an odd number of elements because we
// divide its length at some point.

#[test]
fn write_credential_is_ok_when_unset() {
    let target = "WINCREDENTIALS_RS_TEST_1";
    let username = "testuser";
    let secret = "testy";

    let _ = delete_credential(target);

    let res = write_credential(
        target,
        credential::Credential {
            username: username.to_owned(),
            secret: secret.to_owned(),
        },
    );
    assert!(res.is_ok(), "{}", res.err().unwrap().to_string());

    let _ = delete_credential(target);
}

#[test]
fn write_credential_is_ok_when_set() {
    let target = "WINCREDENTIALS_RS_TEST_2";
    let username = "testuser";
    let secret = "testy";

    let _ = delete_credential(target);
    let _ = write_credential(
        target,
        credential::Credential {
            username: username.to_owned(),
            secret: secret.to_owned(),
        },
    );

    let res = write_credential(
        target,
        credential::Credential {
            username: username.to_owned(),
            secret: secret.to_owned(),
        },
    );
    assert!(res.is_ok(), "{}", res.err().unwrap().to_string());

    let _ = delete_credential(target);
}

#[test]
fn read_credential_is_err_when_unset() {
    let target = "WINCREDENTIALS_RS_TEST_3";

    let _ = delete_credential(target);

    let res = read_credential(target);
    assert!(res.is_err());

    let _ = delete_credential(target);
}

#[test]
fn read_credential_is_ok_when_set() {
    let target = "WINCREDENTIALS_RS_TEST_4";
    let username = "testuser";
    let secret = "testy";

    let _ = delete_credential(target);

    let res = write_credential(
        target,
        credential::Credential {
            username: username.to_owned(),
            secret: secret.to_owned(),
        },
    );
    assert!(res.is_ok(), "{}", res.err().unwrap().to_string());

    let res = read_credential(target);
    assert!(res.is_ok(), "{}", res.err().unwrap().to_string());

    let res = res.unwrap();
    assert_eq!(res.username, username);
    assert_eq!(res.secret, secret);

    let _ = delete_credential(target);
}

#[test]
fn delete_credential_is_err_when_unset() {
    let target = "WINCREDENTIALS_RS_TEST_5";

    let _ = delete_credential(target);
    let res = delete_credential(target);
    assert!(res.is_err());

    let _ = delete_credential(target);
}

#[test]
fn delete_credential_is_ok_when_set() {
    let target = "WINCREDENTIALS_RS_TEST_6";
    let username = "testuser";
    let secret = "testy";

    let _ = delete_credential(target);

    let res = write_credential(
        target,
        credential::Credential {
            username: username.to_owned(),
            secret: secret.to_owned(),
        },
    );
    assert!(res.is_ok(), "{}", res.err().unwrap().to_string());

    let res = delete_credential(target);
    assert!(res.is_ok(), "{}", res.err().unwrap().to_string());

    let _ = delete_credential(target);
}
