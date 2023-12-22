use crate::memory::page::PAGE_DEGREE;

/// Calculate page id from address.
///
/// The page is is calculated by taking the top `PAGE_DEGREE` bits of the address.
pub fn page_id(address: u32) -> u16 {
    (address >> (32 - PAGE_DEGREE)) as u16
}
