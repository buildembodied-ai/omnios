use crate::{Device, Channel, Protocol, MessageFormat, Message, OmniError};
use heapless::Vec;
use typenum::U16;

/// Maximum number of protocols that can be chained in a stack
pub type MaxProtocols = U16;

/// Communication stack that composes devices, channels, protocols and message formats
/// to provide a cohesive communication system.
pub struct CommunicationStack<D: Device, C: Channel, P: Protocol, M: MessageFormat> {
    device: D,
    channel: C,
    protocols: Vec<P, MaxProtocols>,
    message_format: M,
}

impl<D: Device, C: Channel, P: Protocol, M: MessageFormat> CommunicationStack<D, C, P, M> {
    /// Creates a new communication stack.
    ///
    /// # Arguments
    /// * `device` - The device identity
    /// * `channel` - The communication channel
    /// * `protocols` - Vector of protocols to use (applied in order)
    /// * `message_format` - The message format handler
    ///
    /// # Returns
    /// * A new CommunicationStack instance
    pub fn new(device: D, channel: C, protocols: Vec<P, MaxProtocols>, message_format: M) -> Self {
        Self { device, channel, protocols, message_format }
    }

    /// Sends a message through the communication stack.
    ///
    /// # Arguments
    /// * `message` - The message to send
    ///
    /// # Returns
    /// * `Ok(())` if successful
    /// * `Err(OmniError)` if an error occurs
    pub fn send_message(&mut self, message: &Message) -> Result<(), OmniError> {
        // Ensure the message has valid sender information
        if message.sender.is_none() {
            let mut message = message.clone();
            message.sender = Some(self.device.get_id());
            return self.send_message(&message);
        }

        // Serialize the message first
        let mut data = self.message_format.serialize(message)?;
        
        // Apply all protocols in reverse order (so the outermost protocol is applied last)
        for protocol in self.protocols.iter().rev() {
            data = protocol.process_outgoing(&data)?;
        }
        
        // Send the data through the channel
        self.channel.send(&data)
    }

    /// Receives a message from the communication stack.
    ///
    /// # Returns
    /// * `Ok(Message)` - The received message
    /// * `Err(OmniError)` - If an error occurs
    pub fn receive_message(&mut self) -> Result<Message, OmniError> {
        // Use a sufficiently sized buffer for receiving data
        let mut buf = [0u8; 1024];
        
        // Receive raw data from the channel
        let len = self.channel.receive(&mut buf)?;
        
        // Process the data through each protocol
        let mut data = Vec::<u8, 1024>::new();
        data.extend_from_slice(&buf[..len])
            .map_err(|_| OmniError::BufferOverflow)?;
        
        // Apply all protocols in order (so the outermost protocol is applied first)
        for protocol in &self.protocols {
            data = protocol.process_incoming(&data)?;
        }
        
        // Deserialize the processed data into a message
        let mut message = self.message_format.deserialize(&data)?;
        
        // Filter out messages not intended for this device
        if let Some(recipient) = &message.recipient {
            if !self.device.can_receive(recipient) {
                return Err(OmniError::UndeliverableMessage);
            }
        }
        
        Ok(message)
    }
    
    /// Gets a reference to the device
    pub fn device(&self) -> &D {
        &self.device
    }
    
    /// Gets a mutable reference to the device
    pub fn device_mut(&mut self) -> &mut D {
        &mut self.device
    }
    
    /// Gets a reference to the channel
    pub fn channel(&self) -> &C {
        &self.channel
    }
    
    /// Gets a mutable reference to the channel
    pub fn channel_mut(&mut self) -> &mut C {
        &mut self.channel
    }
    
    /// Gets a reference to the protocols
    pub fn protocols(&self) -> &Vec<P, MaxProtocols> {
        &self.protocols
    }
    
    /// Adds a protocol to the stack (will be innermost in the chain)
    pub fn add_protocol(&mut self, protocol: P) -> Result<(), OmniError> {
        self.protocols.push(protocol)
            .map_err(|_| OmniError::TooManyProtocols)
    }
    
    /// Gets a reference to the message format
    pub fn message_format(&self) -> &M {
        &self.message_format
    }
}

/// Builder for constructing a communication stack step by step
pub struct CommunicationStackBuilder<D: Device, C: Channel, M: MessageFormat> {
    device: Option<D>,
    channel: Option<C>,
    protocols: Vec<Box<dyn Protocol>, MaxProtocols>,
    message_format: Option<M>,
}

impl<D: Device, C: Channel, M: MessageFormat> Default for CommunicationStackBuilder<D, C, M> {
    fn default() -> Self {
        Self {
            device: None,
            channel: None,
            protocols: Vec::new(),
            message_format: None,
        }
    }
}

impl<D: Device, C: Channel, M: MessageFormat> CommunicationStackBuilder<D, C, M> {
    /// Creates a new builder
    pub fn new() -> Self {
        Self::default()
    }
    
    /// Sets the device for the stack
    pub fn with_device(mut self, device: D) -> Self {
        self.device = Some(device);
        self
    }
    
    /// Sets the channel for the stack
    pub fn with_channel(mut self, channel: C) -> Self {
        self.channel = Some(channel);
        self
    }
    
    /// Adds a protocol to the stack
    pub fn with_protocol<P: Protocol + 'static>(mut self, protocol: P) -> Result<Self, OmniError> {
        self.protocols.push(Box::new(protocol))
            .map_err(|_| OmniError::TooManyProtocols)?;
        Ok(self)
    }
    
    /// Sets the message format for the stack
    pub fn with_message_format(mut self, format: M) -> Self {
        self.message_format = Some(format);
        self
    }
    
    /// Builds the communication stack
    pub fn build(self) -> Result<CommunicationStack<D, C, Box<dyn Protocol>, M>, OmniError> {
        let device = self.device.ok_or(OmniError::MissingComponent)?;
        let channel = self.channel.ok_or(OmniError::MissingComponent)?;
        let message_format = self.message_format.ok_or(OmniError::MissingComponent)?;
        
        Ok(CommunicationStack::new(device, channel, self.protocols, message_format))
    }
}