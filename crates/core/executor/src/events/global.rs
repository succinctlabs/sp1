use deepsize2::DeepSizeOf;
use serde::{Deserialize, Serialize};

/// Global Interaction Event.
///
/// This event is emitted for all interactions that are sent or received across different shards.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize, DeepSizeOf)]
#[repr(C)]
pub struct GlobalInteractionEvent {
    /// The message.
    pub message: [u32; 8],
    /// Whether the interaction is received or sent.
    pub is_receive: bool,
    /// The kind of the interaction event.
    pub kind: u8,
}
