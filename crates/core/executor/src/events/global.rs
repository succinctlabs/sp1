use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, Default, Serialize, Deserialize)]
pub struct GlobalInteractionEvent {
    pub message: [u32; 7],
    pub is_receive: bool,
}
