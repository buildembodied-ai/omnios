#[derive(Debug)]
pub enum OmniError {
    CryptoError,
    HardwareFailure,
    SerializationError,
    Unauhtorized,
    BufferOverflow
}