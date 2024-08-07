use anyhow::Result;
use std::{fs::File, io::Read};

pub fn read_bin_file_to_vec(mut file: File) -> Result<Vec<u8>> {
    let metadata = file.metadata()?;
    let file_size = metadata.len() as usize;
    let mut buffer = Vec::with_capacity(file_size);
    file.read_to_end(&mut buffer)?;

    Ok(buffer)
}
