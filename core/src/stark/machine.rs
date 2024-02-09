use crate::alu::AddChip;
use crate::alu::BitwiseChip;
use crate::alu::DivRemChip;
use crate::alu::LtChip;
use crate::alu::MulChip;
use crate::alu::ShiftLeft;
use crate::alu::ShiftRightChip;
use crate::alu::SubChip;
use crate::bytes::ByteChip;
use crate::cpu::CpuChip;
use crate::field::FieldLTUChip;
use crate::memory::MemoryChipKind;
use crate::memory::MemoryGlobalChip;
use crate::program::ProgramChip;
use crate::syscall::precompiles::edwards::EdAddAssignChip;
use crate::syscall::precompiles::edwards::EdDecompressChip;
use crate::syscall::precompiles::k256::K256DecompressChip;
use crate::syscall::precompiles::keccak256::KeccakPermuteChip;
use crate::syscall::precompiles::sha256::ShaCompressChip;
use crate::syscall::precompiles::sha256::ShaExtendChip;
use crate::syscall::precompiles::weierstrass::WeierstrassAddAssignChip;
use crate::syscall::precompiles::weierstrass::WeierstrassDoubleAssignChip;
use crate::utils::ec::edwards::ed25519::Ed25519Parameters;
use crate::utils::ec::edwards::EdwardsCurve;
use crate::utils::ec::weierstrass::secp256k1::Secp256k1Parameters;
use crate::utils::ec::weierstrass::SWCurve;
use p3_air::BaseAir;
use p3_commit::Pcs;

use super::Chip;
use super::ChipRef;
use super::Com;
use super::StarkConfig;

pub struct MachineRef<'a, SC: StarkConfig> {
    pub local_chips: &'a [ChipRef<'a, SC>],
    pub global_chips: &'a [ChipRef<'a, SC>],

    // Commitment to the preprocessed data
    preprocessed_local_commitment: Option<Com<SC>>,
    preprocessed_global_commitment: Option<Com<SC>>,
}

pub struct RiscvStark<SC: StarkConfig> {
    config: SC,

    program: Chip<SC::Val, ProgramChip>,
    cpu: Chip<SC::Val, CpuChip>,
    sha_extend: Chip<SC::Val, ShaExtendChip>,
    sha_compress: Chip<SC::Val, ShaCompressChip>,
    ed_add_assign:
        Chip<SC::Val, EdAddAssignChip<EdwardsCurve<Ed25519Parameters>, Ed25519Parameters>>,
    ed_decompress: Chip<SC::Val, EdDecompressChip<Ed25519Parameters>>,
    k256_decompress: Chip<SC::Val, K256DecompressChip>,
    weierstrass_add_assign:
        Chip<SC::Val, WeierstrassAddAssignChip<SWCurve<Secp256k1Parameters>, Secp256k1Parameters>>,
    weierstrass_double_assign: Chip<
        SC::Val,
        WeierstrassDoubleAssignChip<SWCurve<Secp256k1Parameters>, Secp256k1Parameters>,
    >,
    keccak_permute: Chip<SC::Val, KeccakPermuteChip>,
    add: Chip<SC::Val, AddChip>,
    sub: Chip<SC::Val, SubChip>,
    bitwise: Chip<SC::Val, BitwiseChip>,
    div_rem: Chip<SC::Val, DivRemChip>,
    mul: Chip<SC::Val, MulChip>,
    shift_right: Chip<SC::Val, ShiftRightChip>,
    shift_left: Chip<SC::Val, ShiftLeft>,
    lt: Chip<SC::Val, LtChip>,
    field_ltu: Chip<SC::Val, FieldLTUChip>,
    byte: Chip<SC::Val, ByteChip<SC::Val>>,

    // Global chips
    memory_init: Chip<SC::Val, MemoryGlobalChip>,
    memory_finalize: Chip<SC::Val, MemoryGlobalChip>,
    program_memory_init: Chip<SC::Val, MemoryGlobalChip>,

    // Commitment to the preprocessed data
    preprocessed_local_commitment: Option<Com<SC>>,
    preprocessed_global_commitment: Option<Com<SC>>,
}

impl<SC: StarkConfig> RiscvStark<SC> {
    pub fn new(config: SC) -> Self {
        let program = Chip::new(ProgramChip::default());
        let cpu = Chip::new(CpuChip::default());
        let sha_extend = Chip::new(ShaExtendChip::default());
        let sha_compress = Chip::new(ShaCompressChip::default());
        let ed_add_assign = Chip::new(EdAddAssignChip::<
            EdwardsCurve<Ed25519Parameters>,
            Ed25519Parameters,
        >::new());
        let ed_decompress = Chip::new(EdDecompressChip::<Ed25519Parameters>::default());
        let k256_decompress = Chip::new(K256DecompressChip::default());
        let weierstrass_add_assign = Chip::new(WeierstrassAddAssignChip::<
            SWCurve<Secp256k1Parameters>,
            Secp256k1Parameters,
        >::new());
        let weierstrass_double_assign = Chip::new(WeierstrassDoubleAssignChip::<
            SWCurve<Secp256k1Parameters>,
            Secp256k1Parameters,
        >::new());
        let keccak_permute = Chip::new(KeccakPermuteChip::new());
        let add = Chip::new(AddChip::default());
        let sub = Chip::new(SubChip::default());
        let bitwise = Chip::new(BitwiseChip::default());
        let div_rem = Chip::new(DivRemChip::default());
        let mul = Chip::new(MulChip::default());
        let shift_right = Chip::new(ShiftRightChip::default());
        let shift_left = Chip::new(ShiftLeft::default());
        let lt = Chip::new(LtChip::default());
        let field_ltu = Chip::new(FieldLTUChip::default());
        let byte = Chip::new(ByteChip::<SC::Val>::new());

        // Global chips
        let memory_init = Chip::new(MemoryGlobalChip::new(MemoryChipKind::Init));
        let memory_finalize = Chip::new(MemoryGlobalChip::new(MemoryChipKind::Finalize));
        let program_memory_init = Chip::new(MemoryGlobalChip::new(MemoryChipKind::Program));

        let mut machine = Self {
            config,
            program,
            cpu,
            sha_extend,
            sha_compress,
            ed_add_assign,
            ed_decompress,
            k256_decompress,
            weierstrass_add_assign,
            weierstrass_double_assign,
            keccak_permute,
            add,
            sub,
            bitwise,
            div_rem,
            mul,
            shift_right,
            shift_left,
            lt,
            field_ltu,
            byte,
            memory_init,
            memory_finalize,
            program_memory_init,

            preprocessed_local_commitment: None,
            preprocessed_global_commitment: None,
        };

        // Compute commitments to the preprocessed data
        let local_preprocessed_traces = machine
            .local_chips()
            .iter()
            .flat_map(|chip| chip.preprocessed_trace())
            .collect::<Vec<_>>();
        let (local_commit, _) = machine
            .config
            .pcs()
            .commit_batches(local_preprocessed_traces);

        // Compute commitments to the global preprocessed data
        let global_preprocessed_traces = machine
            .global_chips()
            .iter()
            .flat_map(|chip| chip.preprocessed_trace())
            .collect::<Vec<_>>();
        let (global_commit, _) = machine
            .config
            .pcs()
            .commit_batches(global_preprocessed_traces);

        // Store the commitments in the machine
        machine.preprocessed_local_commitment = Some(local_commit);
        machine.preprocessed_global_commitment = Some(global_commit);

        machine
    }

    pub fn local_chips(&self) -> [ChipRef<SC>; 20] {
        [
            self.program.as_ref(),
            self.cpu.as_ref(),
            self.sha_extend.as_ref(),
            self.sha_compress.as_ref(),
            self.ed_add_assign.as_ref(),
            self.ed_decompress.as_ref(),
            self.k256_decompress.as_ref(),
            self.weierstrass_add_assign.as_ref(),
            self.weierstrass_double_assign.as_ref(),
            self.keccak_permute.as_ref(),
            self.add.as_ref(),
            self.sub.as_ref(),
            self.bitwise.as_ref(),
            self.div_rem.as_ref(),
            self.mul.as_ref(),
            self.shift_right.as_ref(),
            self.shift_left.as_ref(),
            self.lt.as_ref(),
            self.field_ltu.as_ref(),
            self.byte.as_ref(),
        ]
    }

    pub fn global_chips(&self) -> [ChipRef<SC>; 3] {
        [
            self.memory_init.as_ref(),
            self.memory_finalize.as_ref(),
            self.program_memory_init.as_ref(),
        ]
    }

    pub fn as_ref(&self) -> MachineRef<SC> {
        MachineRef {
            local_chips: &self.local_chips(),
            global_chips: &self.global_chips(),
            preprocessed_local_commitment: self.preprocessed_local_commitment,
            preprocessed_global_commitment: self.preprocessed_global_commitment,
        }
    }
}
