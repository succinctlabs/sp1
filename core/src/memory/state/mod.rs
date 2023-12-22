use super::page::{InputPage, OutputPage};

pub struct MemoryState {
    pub input_pages: Vec<InputPage>,
    pub output_pages: Vec<OutputPage>,
}
