use crate::OmniError;
use heapless::Vec;

pub type OmniId = [u8; 16];
pub type DeviceId = [u8; 8];

pub struct Message {
    pub header: Header,
    pub payload: Vec<u8, 256>,
}

pub struct Header {
    pub source_omni_id: OmniId,
    pub source_device_id: DeviceId,
    pub dest_omni_id: Vec<OmniId, 256>,
    pub dest_device_id: Vec<OmniId, 256>,
    pub temp_id: Option<OmniId>,
}

pub trait MessageFormat {
    fn serialize(&self, message: &Message) -> Result<Vec<u8, 512>, OmniError>;
    fn deserialize(&self, data: &[u8]) -> Result<Message, OmniError>;
}