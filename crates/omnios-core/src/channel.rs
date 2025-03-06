use crate::OmniError;

/// A communication channel for sending and receiving data.
///
/// Implementations should handle the specifics of the underlying
/// transport protocol (UART, Bluetooth, MQTT, etc.).
pub trait Channel {
    /// Sends raw data through the channel.
    ///
    /// # Arguments
    /// * `data` - The data to be sent
    ///
    /// # Returns
    /// * `Ok(())` if successful
    /// * `Err(OmniError)` otherwise
    fn send(&mut self, data: &[u8]) -> Result<(), OmniError>;
    
    /// Receives data from the channel.
    ///
    /// # Arguments
    /// * `buf` - Buffer to store received data
    ///
    /// # Returns
    /// * `Ok(usize)` - Number of bytes read if successful
    /// * `Err(OmniError)` otherwise
    fn receive(&mut self, buf: &mut [u8]) -> Result<usize, OmniError>;
    
    /// Returns the maximum transmission unit (MTU) for this channel.
    ///
    /// This helps callers optimize buffer sizes and prevent fragmentation.
    fn max_transmission_unit(&self) -> usize {
        1024 // Default conservative MTU
    }
}