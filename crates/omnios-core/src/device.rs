use crate::OmniError;

/// A physical or virtual device that can send and receive data.
///
/// Implementations represent the lowest layer of the communication stack,
/// providing direct access to hardware or virtual devices.
pub trait Device {
    /// Writes data to the device.
    ///
    /// # Arguments
    /// * `buf` - The data to write
    ///
    /// # Returns
    /// * `Ok(usize)` - Number of bytes written if successful
    /// * `Err(OmniError)` otherwise
    fn write(&mut self, buf: &[u8]) -> Result<usize, OmniError>;
    
    /// Reads data from the device.
    ///
    /// # Arguments
    /// * `buf` - Buffer to store read data
    ///
    /// # Returns
    /// * `Ok(usize)` - Number of bytes read if successful
    /// * `Err(OmniError)` otherwise
    fn read(&mut self, buf: &mut [u8]) -> Result<usize, OmniError>;
    
    /// Returns whether the device is ready for reading.
    ///
    /// This helps avoid blocking operations when no data is available.
    fn is_readable(&self) -> bool {
        true // Default implementation always returns ready
    }
    
    /// Returns whether the device is ready for writing.
    ///
    /// This helps avoid blocking operations when device buffers are full.
    fn is_writable(&self) -> bool {
        true // Default implementation always returns ready
    }
}