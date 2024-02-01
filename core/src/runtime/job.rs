use std::collections::BTreeMap;

use crate::alu::AluEvent;
use crate::bytes::ByteLookupEvent;
use crate::cpu::CpuEvent;
use crate::field::event::FieldEvent;
use crate::precompiles::edwards::ed_decompress::EdDecompressEvent;
use crate::precompiles::k256::decompress::K256DecompressEvent;
use crate::precompiles::keccak256::KeccakPermuteEvent;
use crate::precompiles::sha256::{ShaCompressEvent, ShaExtendEvent};
use crate::precompiles::{ECAddEvent, ECDoubleEvent};
use crate::runtime::MemoryRecord;
