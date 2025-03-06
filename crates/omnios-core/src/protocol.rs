use core::marker::PhantomData;
use crate::{crypto::*, OmniError};
use heapless::Vec;
use ring::rand::{SecureRandom, SystemRandom};

/// Maximum buffer size for protocol data
pub const MAX_BUFFER_SIZE: usize = 1024;

/// Version byte for the encrypted protocol format
const ENCRYPTED_PROTOCOL_VERSION: u8 = 0x01;

/// Type alias for protocol result with fixed buffer size
pub type ProtocolResult = Result<Vec<u8, MAX_BUFFER_SIZE>, OmniError>;

/// Trait defining a communication protocol for message processing.
pub trait Protocol {
    /// Processes outgoing data before transmission.
    ///
    /// # Arguments
    /// * `data` - The raw data to process
    ///
    /// # Returns
    /// * `Ok(Vec<u8, MAX_BUFFER_SIZE>)` - The processed data
    /// * `Err(OmniError)` - If processing fails
    fn process_outgoing(&self, data: &[u8]) -> ProtocolResult;
    
    /// Processes incoming data after reception.
    ///
    /// # Arguments
    /// * `data` - The raw received data
    ///
    /// # Returns
    /// * `Ok(Vec<u8, MAX_BUFFER_SIZE>)` - The processed data
    /// * `Err(OmniError)` - If processing fails
    fn process_incoming(&self, data: &[u8]) -> ProtocolResult;
}

/// Plain protocol that performs no processing on the data.
#[derive(Debug, Clone, Copy)]
pub struct PlainProtocol;

impl Protocol for PlainProtocol {
    fn process_outgoing(&self, data: &[u8]) -> ProtocolResult {
        let mut result = Vec::new();
        result.extend_from_slice(data)
            .map_err(|_| OmniError::BufferOverflow)?;
        Ok(result)
    }

    fn process_incoming(&self, data: &[u8]) -> ProtocolResult {
        let mut result = Vec::new();
        result.extend_from_slice(data)
            .map_err(|_| OmniError::BufferOverflow)?;
        Ok(result)
    }
}

/// Encrypted protocol using ECC for secure communication.
pub struct EncryptedProtocol {
    recipient_public_key: EccPublicKey,
    sender_private_key: EccPrivateKey,
    rng: SystemRandom,
}

impl EncryptedProtocol {
    /// Creates a new EncryptedProtocol instance.
    ///
    /// # Arguments
    /// * `recipient_public_key` - The public key of the recipient
    /// * `sender_private_key` - The private key of the sender
    ///
    /// # Returns
    /// * A new EncryptedProtocol instance
    pub fn new(recipient_public_key: EccPublicKey, sender_private_key: EccPrivateKey) -> Self {
        Self {
            recipient_public_key,
            sender_private_key,
            rng: SystemRandom::new(),
        }
    }
    
    /// Creates a new EncryptedProtocol instance with a custom random number generator.
    ///
    /// # Arguments
    /// * `recipient_public_key` - The public key of the recipient
    /// * `sender_private_key` - The private key of the sender
    /// * `rng` - The random number generator to use
    ///
    /// # Returns
    /// * A new EncryptedProtocol instance
    pub fn with_rng(
        recipient_public_key: EccPublicKey,
        sender_private_key: EccPrivateKey,
        rng: SystemRandom
    ) -> Self {
        Self {
            recipient_public_key,
            sender_private_key,
            rng,
        }
    }
    
    /// Generates an AES key using the protocol's RNG
    fn generate_aes_key(&self) -> Result<AesKey, OmniError> {
        let mut key_bytes = [0u8; 32];
        self.rng.fill(&mut key_bytes)
            .map_err(|_| OmniError::CryptoError)?;
        Ok(AesKey(key_bytes))
    }
    
    /// Generates a nonce using the protocol's RNG
    fn generate_nonce(&self) -> Result<[u8; NONCE_LEN], OmniError> {
        let mut nonce = [0u8; NONCE_LEN];
        self.rng.fill(&mut nonce)
            .map_err(|_| OmniError::CryptoError)?;
        Ok(nonce)
    }
}

impl Protocol for EncryptedProtocol {
    fn process_outgoing(&self, data: &[u8]) -> ProtocolResult {
        // Generate a random AES key for this message
        let aes_key = self.generate_aes_key()?;
        
        // Generate a random nonce for this message
        let nonce = self.generate_nonce()?;
        
        // Encrypt the data with AES
        let encrypted_data = aes_encrypt(data, &aes_key, &nonce)?;
        
        // Encrypt the AES key with the recipient's public key
        let encrypted_key = ecc_encrypt(&aes_key.0, &self.recipient_public_key)?;
        
        // Calculate total required size to avoid multiple resizing operations
        let total_size = 1 + 2 + encrypted_key.len() + NONCE_LEN + encrypted_data.len();
        if total_size > MAX_BUFFER_SIZE {
            return Err(OmniError::BufferOverflow);
        }
        
        // Combine the encrypted key and data
        let mut result = Vec::new();
        
        // Add a version byte for future compatibility
        result.push(ENCRYPTED_PROTOCOL_VERSION).map_err(|_| OmniError::BufferOverflow)?;
        
        // Add the encrypted key length as a 16-bit value
        let key_len = encrypted_key.len() as u16;
        result.push((key_len >> 8) as u8).map_err(|_| OmniError::BufferOverflow)?;
        result.push((key_len & 0xFF) as u8).map_err(|_| OmniError::BufferOverflow)?;
        
        // Add the encrypted key
        result.extend_from_slice(&encrypted_key)
            .map_err(|_| OmniError::BufferOverflow)?;
        
        // Add the nonce
        result.extend_from_slice(&nonce)
            .map_err(|_| OmniError::BufferOverflow)?;
        
        // Add the encrypted data
        result.extend_from_slice(&encrypted_data)
            .map_err(|_| OmniError::BufferOverflow)?;
        
        Ok(result)
    }

    fn process_incoming(&self, data: &[u8]) -> ProtocolResult {
        // Minimum size check: version(1) + key_length(2) + min_key_size(1) + nonce_len
        let min_size = 1 + 2 + 1 + NONCE_LEN;
        if data.len() < min_size {
            return Err(OmniError::InvalidFormat);
        }
        
        // Check version
        if data[0] != ENCRYPTED_PROTOCOL_VERSION {
            return Err(OmniError::UnsupportedVersion);
        }
        
        // Get encrypted key length
        let key_len = ((data[1] as usize) << 8) | (data[2] as usize);
        
        // Validate we have enough data
        if data.len() < 3 + key_len + NONCE_LEN {
            return Err(OmniError::InvalidFormat);
        }
        
        // Extract the encrypted key
        let encrypted_key = &data[3..3+key_len];
        
        // Extract the nonce
        let nonce_start = 3 + key_len;
        let nonce_end = nonce_start + NONCE_LEN;
        let nonce: [u8; NONCE_LEN] = data[nonce_start..nonce_end]
            .try_into()
            .map_err(|_| OmniError::CryptoError)?;
        
        // Extract the encrypted data
        let encrypted_data = &data[nonce_end..];
        
        // Decrypt the AES key
        let aes_key_vec = ecc_decrypt(encrypted_key, &self.sender_private_key)?;
        
        if aes_key_vec.len() != 32 {
            return Err(OmniError::CryptoError);
        }
        
        let mut aes_key_bytes = [0u8; 32];
        aes_key_bytes.copy_from_slice(&aes_key_vec);
        let aes_key = AesKey(aes_key_bytes);
        
        // Create a vector for the encrypted data
        let mut encrypted_data_vec = Vec::new();
        encrypted_data_vec.extend_from_slice(encrypted_data)
            .map_err(|_| OmniError::BufferOverflow)?;
        
        // Decrypt the data
        let decrypted = aes_decrypt(&encrypted_data_vec, &aes_key, &nonce)?;
        
        // Create final result
        let mut result = Vec::new();
        result.extend_from_slice(&decrypted)
            .map_err(|_| OmniError::BufferOverflow)?;
        
        Ok(result)
    }
}

/// Protocol that compresses data using LZ4 compression.
pub struct CompressedProtocol<P: Protocol> {
    inner: P,
    compression_level: CompressionLevel,
}

/// Compression level for the CompressedProtocol
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CompressionLevel {
    /// Fast compression with less compression ratio
    Fast,
    /// Default compression (balance between speed and ratio)
    Default,
    /// Maximum compression with slower speed
    Max,
}

impl<P: Protocol> CompressedProtocol<P> {
    /// Creates a new CompressedProtocol instance with default compression level.
    ///
    /// # Arguments
    /// * `inner` - The underlying protocol
    ///
    /// # Returns
    /// * A new CompressedProtocol instance
    pub fn new(inner: P) -> Self {
        Self { 
            inner,
            compression_level: CompressionLevel::Default,
        }
    }
    
    /// Creates a new CompressedProtocol instance with specified compression level.
    ///
    /// # Arguments
    /// * `inner` - The underlying protocol
    /// * `compression_level` - The compression level to use
    ///
    /// # Returns
    /// * A new CompressedProtocol instance
    pub fn with_level(inner: P, compression_level: CompressionLevel) -> Self {
        Self { inner, compression_level }
    }
    
    /// Get the current compression level
    pub fn compression_level(&self) -> CompressionLevel {
        self.compression_level
    }
    
    /// Set a new compression level
    pub fn set_compression_level(&mut self, level: CompressionLevel) {
        self.compression_level = level;
    }
    
    /// Compress data using LZ4 compression
    fn compress(&self, data: &[u8]) -> ProtocolResult {
        // Skip compression for very small data
        if data.len() < 64 {
            let mut result = Vec::new();
            // Add compression flag (0 = uncompressed)
            result.push(0).map_err(|_| OmniError::BufferOverflow)?;
            // Add original data
            result.extend_from_slice(data)
                .map_err(|_| OmniError::BufferOverflow)?;
            return Ok(result);
        }
    
        #[cfg(feature = "compression")]
        {
            use lz4_flex::compress_prepend_size;
            
            // Convert compression level to acceleration parameter
            let acceleration = match self.compression_level {
                CompressionLevel::Fast => 8,
                CompressionLevel::Default => 1,
                CompressionLevel::Max => 0,
            };
            
            // Compress the data
            let compressed = match compress_prepend_size(data, acceleration) {
                Ok(c) => c,
                Err(_) => return Err(OmniError::CompressionError),
            };
            
            // Ensure compression is actually beneficial
            if compressed.len() >= data.len() + 2 {
                // Compression not beneficial, use original data
                let mut result = Vec::new();
                // Add compression flag (0 = uncompressed)
                result.push(0).map_err(|_| OmniError::BufferOverflow)?;
                // Add original data
                result.extend_from_slice(data)
                    .map_err(|_| OmniError::BufferOverflow)?;
                return Ok(result);
            }
            
            let mut result = Vec::new();
            // Add compression flag (1 = LZ4 compressed)
            result.push(1).map_err(|_| OmniError::BufferOverflow)?;
            // Add compressed data
            result.extend_from_slice(&compressed)
                .map_err(|_| OmniError::BufferOverflow)?;
            
            Ok(result)
        }
        
        #[cfg(not(feature = "compression"))]
        {
            // Compression not available, use original data
            let mut result = Vec::new();
            // Add compression flag (0 = uncompressed)
            result.push(0).map_err(|_| OmniError::BufferOverflow)?;
            // Add original data
            result.extend_from_slice(data)
                .map_err(|_| OmniError::BufferOverflow)?;
            Ok(result)
        }
    }
    
    /// Decompress data using LZ4 decompression
    fn decompress(&self, data: &[u8]) -> ProtocolResult {
        if data.is_empty() {
            return Err(OmniError::InvalidFormat);
        }
        
        // Check compression flag
        match data[0] {
            0 => {
                // Uncompressed data, just copy without the flag
                let mut result = Vec::new();
                result.extend_from_slice(&data[1..])
                    .map_err(|_| OmniError::BufferOverflow)?;
                Ok(result)
            },
            1 => {
                #[cfg(feature = "compression")]
                {
                    use lz4_flex::decompress_size_prepended;
                    
                    // Decompress the data
                    let decompressed = match decompress_size_prepended(&data[1..]) {
                        Ok(d) => d,
                        Err(_) => return Err(OmniError::DecompressionError),
                    };
                    
                    let mut result = Vec::new();
                    result.extend_from_slice(&decompressed)
                        .map_err(|_| OmniError::BufferOverflow)?;
                    Ok(result)
                }
                
                #[cfg(not(feature = "compression"))]
                {
                    Err(OmniError::UnsupportedCompression)
                }
            },
            _ => Err(OmniError::UnsupportedCompression),
        }
    }
}

impl<P: Protocol> Protocol for CompressedProtocol<P> {
    fn process_outgoing(&self, data: &[u8]) -> ProtocolResult {
        // Compress the data
        let compressed = self.compress(data)?;
        
        // Process with the inner protocol
        self.inner.process_outgoing(&compressed)
    }

    fn process_incoming(&self, data: &[u8]) -> ProtocolResult {
        // Process with the inner protocol first
        let processed = self.inner.process_incoming(data)?;
        
        // Decompress the processed data
        self.decompress(&processed)
    }
}

/// Protocol combinator that allows chaining multiple protocols together.
pub struct ProtocolChain<P1: Protocol, P2: Protocol> {
    inner1: P1,
    inner2: P2,
}

impl<P1: Protocol, P2: Protocol> ProtocolChain<P1, P2> {
    /// Creates a new ProtocolChain instance.
    ///
    /// # Arguments
    /// * `inner1` - The first protocol in the chain
    /// * `inner2` - The second protocol in the chain
    ///
    /// # Returns
    /// * A new ProtocolChain instance
    pub fn new(inner1: P1, inner2: P2) -> Self {
        Self { inner1, inner2 }
    }
}

impl<P1: Protocol, P2: Protocol> Protocol for ProtocolChain<P1, P2> {
    fn process_outgoing(&self, data: &[u8]) -> ProtocolResult {
        // Apply second protocol first (innermost in the chain)
        let processed = self.inner2.process_outgoing(data)?;
        
        // Then apply first protocol
        self.inner1.process_outgoing(&processed)
    }

    fn process_incoming(&self, data: &[u8]) -> ProtocolResult {
        // Apply first protocol first (outermost in the chain)
        let processed = self.inner1.process_incoming(data)?;
        
        // Then apply second protocol
        self.inner2.process_incoming(&processed)
    }
}

/// Protocol factory for creating common protocol stacks
pub struct ProtocolFactory;

impl ProtocolFactory {
    /// Creates a plain protocol
    pub fn plain() -> PlainProtocol {
        PlainProtocol
    }
    
    /// Creates an encrypted protocol
    pub fn encrypted(
        recipient_public_key: EccPublicKey,
        sender_private_key: EccPrivateKey
    ) -> EncryptedProtocol {
        EncryptedProtocol::new(recipient_public_key, sender_private_key)
    }
    
    /// Creates a compressed protocol with a plain inner protocol
    pub fn compressed() -> CompressedProtocol<PlainProtocol> {
        CompressedProtocol::new(PlainProtocol)
    }
    
    /// Creates an encrypted and compressed protocol
    pub fn secure(
        recipient_public_key: EccPublicKey,
        sender_private_key: EccPrivateKey
    ) -> CompressedProtocol<EncryptedProtocol> {
        let encrypted = EncryptedProtocol::new(recipient_public_key, sender_private_key);
        CompressedProtocol::new(encrypted)
    }
    
    /// Creates a secure protocol with custom compression level
    pub fn secure_with_compression(
        recipient_public_key: EccPublicKey,
        sender_private_key: EccPrivateKey,
        compression_level: CompressionLevel
    ) -> CompressedProtocol<EncryptedProtocol> {
        let encrypted = EncryptedProtocol::new(recipient_public_key, sender_private_key);
        CompressedProtocol::with_level(encrypted, compression_level)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_plain_protocol() {
        let protocol = PlainProtocol;
        let data = b"Hello, OmniOS!";
        
        let processed = protocol.process_outgoing(data).unwrap();
        let result = protocol.process_incoming(&processed).unwrap();
        
        assert_eq!(data, &result[..]);
    }
    
    #[test]
    fn test_protocol_chaining() {
        let p1 = PlainProtocol;
        let p2 = PlainProtocol;
        let chain = ProtocolChain::new(p1, p2);
        
        let data = b"Test chaining protocols";
        
        let processed = chain.process_outgoing(data).unwrap();
        let result = chain.process_incoming(&processed).unwrap();
        
        assert_eq!(data, &result[..]);
    }
    
    // Additional tests would be implemented here
}