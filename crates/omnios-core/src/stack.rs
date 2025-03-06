use crate::{Device, Channel, Protocol, MessageFormat, Message, OmniError};
use heapless::Vec;

pub struct CommunicationStack<D: Device, C: Channel, P: Protocol, M: MessageFormat> {
    device: D,
    channel: C,
    protocols: Vec<P, 16>,
    message_format: M,
}

impl<D: Device, C: Channel, P: Protocol, M: MessageFormat> CommunicationStack<D, C, P, M> {
    pub fn new(device: D, channel: C, protocols: Vec<P, 16>, message_format: M) -> Self {
        Self { device, channel, protocols, message_format }
    }

    pub fn send_message(&mut self, message: &Message) -> Result<(), OmniError> {
        let mut data = self.message_format.serialize(message)?;
        for protocol in self.protocols.iter().rev() {
            data = protocol.process_outgoing(&data)?;
        }
        self.channel.send(&data)
    }

    pub fn receive_message(&mut self) -> Result<Message, OmniError> {
        let mut buf = [0u8; 1024];
        let len = self.channel.receive(&mut buf)?;
        let mut data = &buf[..len];
        for protocol in &self.protocols {
            data = protocol.process_incoming(data)?;
        }
        self.message_format.deserialize(data)
    }
}