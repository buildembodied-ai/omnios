#![no_std]

use ring::rand::{SecureRandom, SystemRandom};
use ring::signature::{self, EcdsaKeyPair, KeyPair, ECDSA_P256_SHA256_FIXED_SIGNING};
use ring::aead::{self, LessSafeKey, UnboundKey, AES_256_GCM, NONCE_LEN};
use core::convert::TryFrom;
use heapless::Vec;
use crate::OmniError;

/// ECC private key wrapper for ECDSA P-256.
#[derive(Clone)]
pub struct EccPrivateKey(EcdsaKeyPair);

/// ECC public key wrapper for ECDSA P-256.
#[derive(Clone)]
pub struct EccPublicKey(Vec<u8, 64>);

/// AES-256 symmetric encryption key.
#[derive(Clone)]
pub struct AesKey([u8; 32]);

impl AsRef<[u8]> for AesKey {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl TryFrom<&[u8]> for AesKey {
    type Error = OmniError;
    
    fn try_from(slice: &[u8]) -> Result<Self, Self::Error> {
        if slice.len() != 32 {
            return Err(OmniError::CryptoError);
        }
        
        let mut key = [0u8; 32];
        key.copy_from_slice(slice);
        Ok(AesKey(key))
    }
}

/// Generates a new ECC key pair for secure communication.
///
/// # Returns
/// * `Ok((private_key, public_key))` - The generated key pair
/// * `Err(OmniError)` - If key generation fails
pub fn generate_ecc_key_pair() -> Result<(EccPrivateKey, EccPublicKey), OmniError> {
    let rng = SystemRandom::new();
    let pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &rng)
        .map_err(|_| OmniError::CryptoError)?;
    let key_pair = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, pkcs8.as_ref(), &rng)
        .map_err(|_| OmniError::CryptoError)?;
    
    let public_key_bytes = key_pair.public_key().as_ref();
    let mut public_key = Vec::new();
    public_key.extend_from_slice(public_key_bytes)
        .map_err(|_| OmniError::BufferOverflow)?;
    
    Ok((EccPrivateKey(key_pair), EccPublicKey(public_key)))
}

/// Generates a new random AES-256 key.
///
/// # Returns
/// * `Ok(AesKey)` - The generated key
/// * `Err(OmniError)` - If key generation fails
pub fn generate_aes_key() -> Result<AesKey, OmniError> {
    let rng = SystemRandom::new();
    let mut key_bytes = [0u8; 32];
    rng.fill(&mut key_bytes).map_err(|_| OmniError::CryptoError)?;
    Ok(AesKey(key_bytes))
}

/// Generates a cryptographically secure random nonce.
///
/// # Returns
/// * `Ok([u8; NONCE_LEN])` - The generated nonce
/// * `Err(OmniError)` - If nonce generation fails
pub fn generate_nonce() -> Result<[u8; NONCE_LEN], OmniError> {
    let rng = SystemRandom::new();
    let mut nonce = [0u8; NONCE_LEN];
    rng.fill(&mut nonce).map_err(|_| OmniError::CryptoError)?;
    Ok(nonce)
}

/// Encrypts data using AES-256-GCM.
///
/// # Arguments
/// * `data` - The data to encrypt
/// * `key` - The AES key
/// * `nonce` - The nonce (must be unique for each encryption with the same key)
///
/// # Returns
/// * `Ok(Vec<u8, 256>)` - The encrypted data with authentication tag
/// * `Err(OmniError)` - If encryption fails
pub fn aes_encrypt(data: &[u8], key: &AesKey, nonce: &[u8; NONCE_LEN]) -> Result<Vec<u8, 256>, OmniError> {
    if data.len() > 240 {  // 256 - 16 (GCM tag size)
        return Err(OmniError::BufferOverflow);
    }
    
    let unbound_key = UnboundKey::new(&AES_256_GCM, &key.0).map_err(|_| OmniError::CryptoError)?;
    let key = LessSafeKey::new(unbound_key);
    let nonce = aead::Nonce::try_assume_unique_for_key(nonce).map_err(|_| OmniError::CryptoError)?;
    
    let mut in_out = Vec::new();
    in_out.extend_from_slice(data).map_err(|_| OmniError::BufferOverflow)?;
    
    key.seal_in_place_append_tag(nonce, aead::Aad::empty(), &mut in_out)
        .map_err(|_| OmniError::CryptoError)?;
    
    Ok(in_out)
}

/// Decrypts data using AES-256-GCM.
///
/// # Arguments
/// * `data` - The encrypted data with authentication tag
/// * `key` - The AES key
/// * `nonce` - The nonce used for encryption
///
/// # Returns
/// * `Ok(Vec<u8, 256>)` - The decrypted data
/// * `Err(OmniError)` - If decryption fails or authentication fails
pub fn aes_decrypt(data: &[u8], key: &AesKey, nonce: &[u8; NONCE_LEN]) -> Result<Vec<u8, 256>, OmniError> {
    if data.len() < 16 {  // Minimum size includes authentication tag
        return Err(OmniError::CryptoError);
    }
    
    let unbound_key = UnboundKey::new(&AES_256_GCM, &key.0).map_err(|_| OmniError::CryptoError)?;
    let key = LessSafeKey::new(unbound_key);
    let nonce = aead::Nonce::try_assume_unique_for_key(nonce).map_err(|_| OmniError::CryptoError)?;
    
    let mut in_out = Vec::new();
    in_out.extend_from_slice(data).map_err(|_| OmniError::BufferOverflow)?;
    
    let decrypted = key.open_in_place(nonce, aead::Aad::empty(), &mut in_out)
        .map_err(|_| OmniError::CryptoError)?;
    
    let mut result = Vec::new();
    result.extend_from_slice(decrypted).map_err(|_| OmniError::BufferOverflow)?;
    
    Ok(result)
}

/// Encrypts data using hybrid encryption (ECC + AES).
///
/// # Arguments
/// * `data` - The data to encrypt
/// * `public_key` - The recipient's public key
///
/// # Returns
/// * `Ok(Vec<u8, 128>)` - The encrypted data
/// * `Err(OmniError)` - If encryption fails
pub fn ecc_encrypt(data: &[u8], public_key: &EccPublicKey) -> Result<Vec<u8, 128>, OmniError> {
    // Generate a random AES key for symmetric encryption
    let aes_key = generate_aes_key()?;
    
    // Generate a random nonce
    let nonce = generate_nonce()?;
    
    // Encrypt the data with AES
    let encrypted_data = aes_encrypt(data, &aes_key, &nonce)?;
    
    // In a real implementation, you would encrypt the AES key with the ECC public key
    // For demonstration, we'll package the key, nonce, and encrypted data together
    // NOTE: This implementation needs to be replaced with actual ECC key encryption
    
    let mut result = Vec::new();
    
    // Add the AES key and nonce
    result.extend_from_slice(&aes_key.0).map_err(|_| OmniError::BufferOverflow)?;
    result.extend_from_slice(&nonce).map_err(|_| OmniError::BufferOverflow)?;
    
    // Add the encrypted data
    for byte in encrypted_data.iter() {
        result.push(*byte).map_err(|_| OmniError::BufferOverflow)?;
    }
    
    Ok(result)
}

/// Decrypts data using hybrid encryption (ECC + AES).
///
/// # Arguments
/// * `data` - The encrypted data
/// * `private_key` - The recipient's private key
///
/// # Returns
/// * `Ok(Vec<u8, 64>)` - The decrypted data
/// * `Err(OmniError)` - If decryption fails
pub fn ecc_decrypt(data: &[u8], _private_key: &EccPrivateKey) -> Result<Vec<u8, 64>, OmniError> {
    if data.len() < 32 + NONCE_LEN {
        return Err(OmniError::CryptoError);
    }
    
    // Extract the AES key, nonce, and encrypted data
    let aes_key_bytes: [u8; 32] = data[0..32]
        .try_into()
        .map_err(|_| OmniError::CryptoError)?;
    
    let nonce: [u8; NONCE_LEN] = data[32..32+NONCE_LEN]
        .try_into()
        .map_err(|_| OmniError::CryptoError)?;
    
    let encrypted_data = &data[32+NONCE_LEN..];
    
    let aes_key = AesKey(aes_key_bytes);
    
    // Convert slice to Vec<u8, 256> for aes_decrypt
    let mut encrypted_vec = Vec::new();
    encrypted_vec.extend_from_slice(encrypted_data)
        .map_err(|_| OmniError::BufferOverflow)?;
    
    // Decrypt the data
    let decrypted = aes_decrypt(&encrypted_vec, &aes_key, &nonce)?;
    
    // Convert to the return type Vec<u8, 64>
    let mut result = Vec::new();
    for byte in decrypted.iter() {
        if result.len() >= 64 {
            return Err(OmniError::BufferOverflow);
        }
        result.push(*byte).map_err(|_| OmniError::BufferOverflow)?;
    }
    
    Ok(result)
}

/// Signs data using the private ECC key.
///
/// # Arguments
/// * `data` - The data to sign
/// * `private_key` - The signer's private key
///
/// # Returns
/// * `Ok(Vec<u8, 64>)` - The signature
/// * `Err(OmniError)` - If signing fails
pub fn ecc_sign(data: &[u8], private_key: &EccPrivateKey) -> Result<Vec<u8, 64>, OmniError> {
    let signature = private_key.0.sign(data).map_err(|_| OmniError::CryptoError)?;
    
    let mut result = Vec::new();
    result.extend_from_slice(signature.as_ref())
        .map_err(|_| OmniError::BufferOverflow)?;
    
    Ok(result)
}

/// Verifies a signature using the public ECC key.
///
/// # Arguments
/// * `data` - The data that was signed
/// * `signature` - The signature to verify
/// * `public_key` - The signer's public key
///
/// # Returns
/// * `Ok(bool)` - True if the signature is valid, false otherwise
/// * `Err(OmniError)` - If verification fails for reasons other than an invalid signature
pub fn ecc_verify(data: &[u8], signature: &[u8], public_key: &EccPublicKey) -> Result<bool, OmniError> {
    if signature.len() != 64 {
        return Err(OmniError::CryptoError);
    }
    
    let peer_public_key = signature::UnparsedPublicKey::new(
        &signature::ECDSA_P256_SHA256_FIXED,
        &public_key.0
    );
    
    match peer_public_key.verify(data, signature) {
        Ok(()) => Ok(true),
        Err(_) => Ok(false),
    }
}