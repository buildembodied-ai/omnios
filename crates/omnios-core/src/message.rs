use core::fmt;
use crate::OmniError;
use heapless::Vec;
use serde::{Serialize, Deserialize};

/// Unique identifier for an OmniOS user.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct OmniId(pub [u8; 16]);

impl fmt::Display for OmniId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in &self.0[..4] {
            write!(f, "{:02x}", byte)?;
        }
        write!(f, "-")?;
        for byte in &self.0[4..8] {
            write!(f, "{:02x}", byte)?;
        }
        write!(f, "-")?;
        for byte in &self.0[8..12] {
            write!(f, "{:02x}", byte)?;
        }
        write!(f, "-")?;
        for byte in &self.0[12..] {
            write!(f, "{:02x}", byte)?;
        }
        Ok(())
    }
}

/// Unique identifier for a device within an OmniOS network.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct DeviceId(pub [u8; 8]);

impl fmt::Display for DeviceId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in &self.0 {
            write!(f, "{:02x}", byte)?;
        }
        Ok(())
    }
}

/// A message in the OmniOS system.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Message {
    /// Message header containing routing information.
    pub header: Header,
    
    /// Message payload containing the actual data.
    pub payload: Vec<u8, 256>,
}

/// Message header containing routing and identification information.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Header {
    /// The OmniID of the message source.
    pub source_omni_id: OmniId,
    
    /// The DeviceID of the specific source device.
    pub source_device_id: DeviceId,
    
    /// The destination OmniIDs (can be multiple for broadcasts).
    pub dest_omni_id: Vec<OmniId, 8>,
    
    /// The destination DeviceIDs (can be multiple for broadcasts).
    pub dest_device_id: Vec<DeviceId, 8>,
    
    /// Optional temporary ID for session management.
    pub temp_id: Option<OmniId>,
    
    /// Message timestamp for ordering and expiration.
    pub timestamp: u64,
    
    /// Time-to-live counter for limiting message propagation.
    pub ttl: u8,
    
    /// Message type identifier.
    pub message_type: MessageType,
}

/// Defines the type of message and how it should be processed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum MessageType {
    /// Regular data message.
    Data,
    
    /// Control message for system management.
    Control,
    
    /// Acknowledgment of a previous message.
    Ack,
    
    /// Discovery message for finding devices.
    Discovery,
    
    /// Authentication-related message.
    Auth,
}

/// Trait for serializing and deserializing messages.
pub trait MessageFormat {
    /// Serializes a message to a byte vector.
    ///
    /// # Arguments
    /// * `message` - The message to serialize
    ///
    /// # Returns
    /// * `Ok(Vec<u8, 512>)` - The serialized message
    /// * `Err(OmniError)` - If serialization fails
    fn serialize(&self, message: &Message) -> Result<Vec<u8, 512>, OmniError>;
    
    /// Deserializes a byte array to a message.
    ///
    /// # Arguments
    /// * `data` - The serialized message data
    ///
    /// # Returns
    /// * `Ok(Message)` - The deserialized message
    /// * `Err(OmniError)` - If deserialization fails
    fn deserialize(&self, data: &[u8]) -> Result<Message, OmniError>;
}

/// Implementation of MessageFormat using postcard for compact serialization.
pub struct PostcardFormat;

impl MessageFormat for PostcardFormat {
    fn serialize(&self, message: &Message) -> Result<Vec<u8, 512>, OmniError> {
        let mut buffer = Vec::new();
        postcard::to_vec_cobs(message, &mut buffer)
            .map_err(|_| OmniError::SerializationError)?;
        Ok(buffer)
    }

    fn deserialize(&self, data: &[u8]) -> Result<Message, OmniError> {
        postcard::from_bytes_cobs(data)
            .map_err(|_| OmniError::SerializationError)
    }
}