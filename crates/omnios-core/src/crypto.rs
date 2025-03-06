use ring::rand::{SecureRandom, SystemRandom};
use ring::signature::{self, EcdsaKeyPair, KeyPair, ECDSA_P256_SHA256_FIXED_SIGNING};
use ring::aead::{self, LessSafeKey, UnboundKey, AES_256_GCM, NONCE_LEN};
use crate::OmniError;

pub struct EccPrivateKey(EcdsaKeyPair);
pub struct EccPublicKey(Vec<u8>);
pub struct AesKey([u8; 32]);

pub fn generate_ecc_key_pair() -> Result<(EccPrivateKey, EccPublicKey), OmniError> {
    let rng = SystemRandom::new();
    let pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &rng)
        .map_err(|_| OmniError::CryptoError)?;
    let key_pair = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, pkcs8.as_ref(), &rng)
        .map_err(|_| OmniError::CryptoError)?;
    let public_key = key_pair.public_key().as_ref().to_vec();
    Ok((EccPrivateKey(key_pair), EccPublicKey(public_key)))
}

pub fn generate_aes_key() -> Result<AesKey, OmniError> {
    let rng = SystemRandom::new();
    let mut key_bytes = [0u8; 32];
    rng.fill(&mut key_bytes).map_err(|_| OmniError::CryptoError)?;
    Ok(AesKey(key_bytes))
}

pub fn aes_encrypt(data: &[u8], key: &AesKey, nonce: &[u8; NONCE_LEN]) -> Result<Vec<u8, 256>, OmniError> {
    let unbound_key = UnboundKey::new(&AES_256_GCM, &key.0).map_err(|_| OmniError::CryptoError)?;
    let key = LessSafeKey::new(unbound_key);
    let nonce = aead::Nonce::try_assume_unique_for_key(nonce).map_err(|_| OmniError::CryptoError)?;
    let mut in_out = data.to_vec();
    key.seal_in_place_append_tag(nonce, aead::Aad::empty(), &mut in_out)
        .map_err(|_| OmniError::CryptoError)?;
    Ok(in_out)
}

pub fn aes_decrypt(data: &[u8], key: &AesKey, nonce: &[u8; NONCE_LEN]) -> Result<Vec<u8, 256>, OmniError> {
    let unbound_key = UnboundKey::new(&AES_256_GCM, &key.0).map_err(|_| OmniError::CryptoError)?;
    let key = LessSafeKey::new(unbound_key);
    let nonce = aead::Nonce::try_assume_unique_for_key(nonce).map_err(|_| OmniError::CryptoError)?;
    let mut in_out = data.to_vec();
    let decrypted = key.open_in_place(nonce, aead::Aad::empty(), &mut in_out)
        .map_err(|_| OmniError::CryptoError)?;
    Ok(decrypted.to_vec())
}

pub fn ecc_encrypt(data: &[u8], public_key: &EccPublicKey) -> Result<Vec<u8>, OmniError> {
    // TODO: use hybrid encryption with ECC
    Ok(data.to_vec())
}

pub fn ecc_decrypt(data: &[u8], _private_key: &EccPrivateKey) -> Result<Vec<u8>, OmniError> {
    // TODO: use hybrid decryption with ECC
    Ok(data.to_vec())
}