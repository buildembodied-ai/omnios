#![no_std]

pub mod channel;
pub mod crypto;
pub mod device;
pub mod error;
pub mod message;
pub mod protocol;
pub mod stack;

pub use channel::Channel;
pub use crypto::{EccPrivateKey, EccPublicKey, AesKey};
pub use device::Device;
pub use error::OmniError;
pub use message::{Message, MessageFormat};
pub use protocol::{Protocol, EncryptedProtocol};
pub use stack::CommunicationStack;