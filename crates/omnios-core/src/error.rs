use core::fmt;

/// Error types for the OmniOS system.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OmniError {
    /// Buffer overflow occurred
    BufferOverflow,
    /// Error in cryptographic operations
    CryptoError,
    /// Invalid data format
    InvalidFormat,
    /// Unsupported version
    UnsupportedVersion,
    /// Compression error
    CompressionError,
    /// Decompression error
    DecompressionError,
    /// Compression method not supported
    UnsupportedCompression,
    /// Too many protocols in stack
    TooManyProtocols,
    /// Channel error
    ChannelError,
    /// Device error
    DeviceError,
    /// Message cannot be delivered to the specified recipient
    UndeliverableMessage,
    /// Missing required component
    MissingComponent,
    /// Message format error
    MessageFormatError,
    /// Invalid key
    InvalidKey,
    /// Authentication failed
    AuthenticationFailed,
    /// Authorization failed
    AuthorizationFailed,
    /// Identity expired
    IdentityExpired,
    /// Network unavailable
    NetworkUnavailable,
    /// Channel timeout
    Timeout,
    /// Not implemented
    NotImplemented,
}

impl fmt::Display for OmniError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BufferOverflow => write!(f, "Buffer overflow"),
            Self::CryptoError => write!(f, "Cryptographic error"),
            Self::InvalidFormat => write!(f, "Invalid data format"),
            Self::UnsupportedVersion => write!(f, "Unsupported version"),
            Self::CompressionError => write!(f, "Compression error"),
            Self::DecompressionError => write!(f, "Decompression error"),
            Self::UnsupportedCompression => write!(f, "Compression method not supported"),
            Self::TooManyProtocols => write!(f, "Too many protocols in stack"),
            Self::ChannelError => write!(f, "Channel error"),
            Self::DeviceError => write!(f, "Device error"),
            Self::UndeliverableMessage => write!(f, "Message cannot be delivered to recipient"),
            Self::MissingComponent => write!(f, "Missing required component"),
            Self::MessageFormatError => write!(f, "Message cannot be formatted"),

            // TODO: Implement missing messages.
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for OmniError {}