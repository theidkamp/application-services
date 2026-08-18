/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

// This is the *local* encryption support - it has nothing to do with the
// encryption used by sync.

// For context, what "local encryption" means in this context is:
// * We use regular sqlite, but want to ensure the credit-card numbers are
//   encrypted in the DB - so we store the number encrypted, and the key
//   is managed by the app.
// * The credit-card API always just accepts and returns the encrypted string,
//   so we also expose encryption and decryption public functions that take
//   the key and text. The core storage API never knows the unencrypted number.
//
// This makes life tricky for Sync - sync has its own encryption and its own
// management of sync keys. The entire records are encrypted on the server -
// so the record on the server has the plain-text number (which is then
// encrypted as part of the entire record), so:
// * When transforming a record from the DB into a Sync record, we need to
//   *decrypt* the field.
// * When transforming a record from Sync into a DB record, we need to *encrypt*
//   the field.
//
// So Sync needs to know the key etc, and that needs to get passed down
// multiple layers, from the app saying "sync now" all the way down to the
// low level sync code.
// To make life a little easier, we do that via a struct.

use crate::error::*;
use error_support::handle_error;
use std::sync::Arc;

pub use encryption::{EncryptorDecryptor, KeyManager, ManagedEncryptorDecryptor, StaticKeyManager};

// TODO(FXCM-2281): the consumer will supply the encryptor when building the store.
pub(crate) fn static_key_encryptor(key: &str) -> Result<ManagedEncryptorDecryptor> {
    // Validate eagerly so an invalid key isn't treated as undecryptable card data.
    jwcrypto::EncryptorDecryptor::new(key)?;

    Ok(ManagedEncryptorDecryptor::new(Arc::new(
        StaticKeyManager::new(key.to_string()),
    )))
}

#[cfg(test)]
pub(crate) fn random_key_encryptor() -> Result<ManagedEncryptorDecryptor> {
    static_key_encryptor(&encryption::create_key()?)
}

pub(crate) fn encrypt_str(encdec: &dyn EncryptorDecryptor, cleartext: &str) -> Result<String> {
    let ciphertext = encdec.encrypt(cleartext.as_bytes().to_vec())?;
    String::from_utf8(ciphertext).map_err(|e| Error::CryptoNotUtf8(format!("encrypting: {e}")))
}

pub(crate) fn decrypt_str(encdec: &dyn EncryptorDecryptor, ciphertext: &str) -> Result<String> {
    let cleartext = encdec.decrypt(ciphertext.as_bytes().to_vec())?;
    String::from_utf8(cleartext).map_err(|e| Error::CryptoNotUtf8(format!("decrypting: {e}")))
}

// public functions we expose over the FFI (which is why they take `String`
// rather than the `&str` you'd otherwise expect)
#[handle_error(Error)]
pub fn encrypt_string(key: String, cleartext: String) -> ApiResult<String> {
    // It would be nice to have more detailed error messages, but that would require the consumer
    // to pass them in.  Let's not change the API yet.
    encrypt_str(&static_key_encryptor(&key)?, &cleartext)
}

#[handle_error(Error)]
pub fn decrypt_string(key: String, ciphertext: String) -> ApiResult<String> {
    // It would be nice to have more detailed error messages, but that would require the consumer
    // to pass them in.  Let's not change the API yet.
    decrypt_str(&static_key_encryptor(&key)?, &ciphertext)
}

#[handle_error(Error)]
pub fn create_autofill_key() -> ApiResult<String> {
    Ok(encryption::create_key()?)
}

#[cfg(test)]
mod test {
    use super::*;
    use nss_as::ensure_initialized;

    #[test]
    fn test_encrypt() {
        ensure_initialized();
        let ed = static_key_encryptor(&create_autofill_key().unwrap()).unwrap();
        let cleartext = "secret";
        let ciphertext = encrypt_str(&ed, cleartext).unwrap();
        assert_eq!(decrypt_str(&ed, &ciphertext).unwrap(), cleartext);
        let ed2 = static_key_encryptor(&create_autofill_key().unwrap()).unwrap();
        assert!(matches!(
            decrypt_str(&ed2, &ciphertext),
            Err(Error::EncryptionError(
                encryption::EncryptionApiError::DecryptionFailed { .. }
            ))
        ));
    }

    #[test]
    fn test_decryption_errors() {
        // The shared crate maps all jwcrypto decryption failures to DecryptionFailed.
        ensure_initialized();
        let ed = static_key_encryptor(&create_autofill_key().unwrap()).unwrap();
        assert!(matches!(
            decrypt_str(&ed, "invalid-ciphertext"),
            Err(Error::EncryptionError(
                encryption::EncryptionApiError::DecryptionFailed { .. }
            )),
        ));
        assert!(matches!(
            decrypt_str(&ed, ""),
            Err(Error::EncryptionError(
                encryption::EncryptionApiError::DecryptionFailed { .. }
            )),
        ));
    }

    #[test]
    fn test_trait_roundtrip_is_byte_oriented() {
        ensure_initialized();
        let ed = random_key_encryptor().unwrap();
        let ciphertext = ed.encrypt(b"secret".to_vec()).unwrap();
        assert_ne!(ciphertext, b"secret".to_vec());
        assert_eq!(ed.decrypt(ciphertext).unwrap(), b"secret".to_vec());
    }
}
