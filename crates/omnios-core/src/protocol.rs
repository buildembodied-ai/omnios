use crate::{crypto::*, OmniError};
use heapless::Vec;

pub trait Protocol {
    fn process_outgoing(&self, data: &[u8]) -> Result<Vec<u8, 1024>, OmniError>;
    fn process_incoming(&self, data: &[u8]) -> Result<Vec<u8, 1024>, OmniError>;
}

pub struct EncryptedProtocol {
    recipient_public_key: EccPublicKey,
    sender_private_key: EccPrivateKey,
}

impl Protocol for EncryptedProtocol {
    fn process_outgoing(&self, data: &[u8]) -> Result<Vec<u8, 1024>, OmniError> {
        let aes_key = generate_aes_key()?;
        let nonce = [0u8; 12];
        let encrypted_data = aes_encrypt(data, &aes_key, &nonce)?;
        let encrypted_key = ecc_encrypt(&aes_key.0, &self.recipient_public_key)?;
        let mut result = Vec::new();
        result.extend_from_slice(&encrypted_key);
        result.extend_from_slice(&encrypted_data);
        Ok(result)
    }

    fn process_incoming(&self, data: &[u8]) -> Result<Vec<u8, 1024>, OmniError> {
        let (encrypted_key, encrypted_data) = data.split_at(64);
        let aes_key_bytes = ecc_decrypt(encrypted_key, &self.sender_private_key)?;
        let aes_key = AesKey(aes_key_bytes.try_into().map_err(|_| OmniError::CryptoError)?);
        let nonce = [0u8; 12];
        aes_decrypt(encrypted_data, &aes_key, &nonce)
    }
}