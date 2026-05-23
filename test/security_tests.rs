use secure_radsec::config::{verify_file_permissions, load_config};
use std::fs;
use std::os::unix::fs::PermissionsExt;
use tempfile::NamedTempFile;

#[test]
fn test_stig_pci_file_permissions_enforcement() {
    let temp_file = NamedTempFile::new().unwrap();
    let path = temp_file.path().to_str().unwrap();

    // 1. Test Insecure Permissions (0644 - typical default)
    let mut perms = fs::metadata(path).unwrap().permissions();
    perms.set_mode(0o644);
    fs::set_permissions(path, perms.clone()).unwrap();

    let result = verify_file_permissions(path);
    assert!(result.is_err(), "Server must reject private keys with readable group/other permissions");

    // 2. Test Secure Permissions (0600 - owner read/write only)
    perms.set_mode(0o600);
    fs::set_permissions(path, perms.clone()).unwrap();

    let result = verify_file_permissions(path);
    assert!(result.is_ok(), "Server should accept 0600 permissions");

    // 3. Test Secure Permissions (0400 - owner read only)
    perms.set_mode(0o400);
    fs::set_permissions(path, perms).unwrap();

    let result = verify_file_permissions(path);
    assert!(result.is_ok(), "Server should accept 0400 permissions");
}
