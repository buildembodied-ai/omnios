use crate::OmniError;


pub trait Channel {
    fn send(&mut self, data: &[u8]) -> Result<(), OmniError>;
    fn receive(&mut self, buf: &mut [u8]) -> Result<usize, OmniError>;
}