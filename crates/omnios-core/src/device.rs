use crate::OmniError;

pub trait Device {
    fn write(&mut self, buf: &[u8]) -> Result<usize, OmniError>;
    fn read(&mut self, buf: &mut [u8]) -> Result<usize, OmniError>;
}