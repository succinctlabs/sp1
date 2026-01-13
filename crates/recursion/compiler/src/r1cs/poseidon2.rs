//! Poseidon2 R1CS expansion for BabyBear.
//!
//! This module expands Poseidon2 permutation into explicit R1CS constraints.
//! The S-box for BabyBear is x^7, which requires 4 multiplication constraints.
//!
//! SECURITY CRITICAL: This must be semantically equivalent to SP1's native Poseidon2.
//! Round constants sourced from: sp1/crates/recursion/gnark-ffi/go/sp1/poseidon2/constants.go

use p3_field::PrimeField64;
use super::types::{R1CS, SparseRow};

/// Poseidon2 parameters for BabyBear
pub const WIDTH: usize = 16;
pub const NUM_EXTERNAL_ROUNDS: usize = 8;
pub const NUM_INTERNAL_ROUNDS: usize = 13;
pub const TOTAL_ROUNDS: usize = NUM_EXTERNAL_ROUNDS + NUM_INTERNAL_ROUNDS; // 21

/// Round constants for BabyBear Poseidon2
/// Sourced from gnark-ffi/go/sp1/poseidon2/constants.go (rc16 array, 30 rounds)
/// External rounds: 0-3, 17-20 (full width)
/// Internal rounds: 4-16 (only first element is used, rest are 0)
#[rustfmt::skip]
pub const RC16: [[u32; WIDTH]; 30] = [
    // Round 0
    [2110014213, 3964964605, 2190662774, 2732996483, 640767983, 3403899136, 1716033721, 1606702601,
     3759873288, 1466015491, 1498308946, 2844375094, 3042463841, 1969905919, 4109944726, 3925048366],
    // Round 1
    [3706859504, 759122502, 3167665446, 1131812921, 1080754908, 4080114493, 893583089, 2019677373,
     3128604556, 580640471, 3277620260, 842931656, 548879852, 3608554714, 3575647916, 81826002],
    // Round 2
    [4289086263, 1563933798, 1440025885, 184445025, 2598651360, 1396647410, 1575877922, 3303853401,
     137125468, 765010148, 633675867, 2037803363, 2573389828, 1895729703, 541515871, 1783382863],
    // Round 3
    [2641856484, 3035743342, 3672796326, 245668751, 2025460432, 201609705, 286217151, 4093475563,
     2519572182, 3080699870, 2762001832, 1244250808, 606038199, 3182740831, 73007766, 2572204153],
    // Round 4
    [1196780786, 3447394443, 747167305, 2968073607, 1053214930, 1074411832, 4016794508, 1570312929,
     113576933, 4042581186, 3634515733, 1032701597, 2364839308, 3840286918, 888378655, 2520191583],
    // Round 5
    [36046858, 2927525953, 3912129105, 4004832531, 193772436, 1590247392, 4125818172, 2516251696,
     4050945750, 269498914, 1973292656, 891403491, 1845429189, 2611996363, 2310542653, 4071195740],
    // Round 6
    [3505307391, 786445290, 3815313971, 1111591756, 4233279834, 2775453034, 1991257625, 2940505809,
     2751316206, 1028870679, 1282466273, 1059053371, 834521354, 138721483, 3100410803, 3843128331],
    // Round 7
    [3878220780, 4058162439, 1478942487, 799012923, 496734827, 3521261236, 755421082, 1361409515,
     392099473, 3178453393, 4068463721, 7935614, 4140885645, 2150748066, 1685210312, 3852983224],
    // Round 8
    [2896943075, 3087590927, 992175959, 970216228, 3473630090, 3899670400, 3603388822, 2633488197,
     2479406964, 2420952999, 1852516800, 4253075697, 979699862, 1163403191, 1608599874, 3056104448],
    // Round 9
    [3779109343, 536205958, 4183458361, 1649720295, 1444912244, 3122230878, 384301396, 4228198516,
     1662916865, 4082161114, 2121897314, 1706239958, 4166959388, 1626054781, 3005858978, 1431907253],
    // Round 10
    [1418914503, 1365856753, 3942715745, 1429155552, 3545642795, 3772474257, 1621094396, 2154399145,
     826697382, 1700781391, 3539164324, 652815039, 442484755, 2055299391, 1064289978, 1152335780],
    // Round 11
    [3417648695, 186040114, 3475580573, 2113941250, 1779573826, 1573808590, 3235694804, 2922195281,
     1119462702, 3688305521, 1849567013, 667446787, 753897224, 1896396780, 3143026334, 3829603876],
    // Round 12
    [859661334, 3898844357, 180258337, 2321867017, 3599002504, 2886782421, 3038299378, 1035366250,
     2038912197, 2920174523, 1277696101, 2785700290, 3806504335, 3518858933, 654843672, 2127120275],
    // Round 13
    [1548195514, 2378056027, 390914568, 1472049779, 1552596765, 1905886441, 1611959354, 3653263304,
     3423946386, 340857935, 2208879480, 139364268, 3447281773, 3777813707, 55640413, 4101901741],
    // Round 14
    [104929687, 1459980974, 1831234737, 457139004, 2581487628, 2112044563, 3567013861, 2792004347,
     576325418, 41126132, 2713562324, 151213722, 2891185935, 546846420, 2939794919, 2543469905],
    // Round 15
    [2191909784, 3315138460, 530414574, 1242280418, 1211740715, 3993672165, 2505083323, 3845798801,
     538768466, 2063567560, 3366148274, 1449831887, 2408012466, 294726285, 3943435493, 924016661],
    // Round 16
    [3633138367, 3222789372, 809116305, 30100013, 2655172876, 2564247117, 2478649732, 4113689151,
     4120146082, 2512308515, 650406041, 4240012393, 2683508708, 951073977, 3460081988, 339124269],
    // Round 17
    [130182653, 2755946749, 542600513, 2816103022, 1931786340, 2044470840, 1709908013, 2938369043,
     3640399693, 1374470239, 2191149676, 2637495682, 4236394040, 2289358846, 3833368530, 974546524],
    // Round 18
    [3306659113, 2234814261, 1188782305, 223782844, 2248980567, 2309786141, 2023401627, 3278877413,
     2022138149, 575851471, 1612560780, 3926656936, 3318548977, 2591863678, 188109355, 4217723909],
    // Round 19
    [1564209905, 2154197895, 2459687029, 2870634489, 1375012945, 1529454825, 306140690, 2855578299,
     1246997295, 3024298763, 1915270363, 1218245412, 2479314020, 2989827755, 814378556, 4039775921],
    // Round 20
    [1165280628, 1203983801, 3814740033, 1919627044, 600240215, 773269071, 486685186, 4254048810,
     1415023565, 502840102, 4225648358, 510217063, 166444818, 1430745893, 1376516190, 1775891321],
    // Round 21
    [1170945922, 1105391877, 261536467, 1401687994, 1022529847, 2476446456, 2603844878, 3706336043,
     3463053714, 1509644517, 588552318, 65252581, 3696502656, 2183330763, 3664021233, 1643809916],
    // Round 22
    [2922875898, 3740690643, 3932461140, 161156271, 2619943483, 4077039509, 2921201703, 2085619718,
     2065264646, 2615693812, 3116555433, 246100007, 4281387154, 4046141001, 4027749321, 111611860],
    // Round 23
    [2066954820, 2502099969, 2915053115, 2362518586, 366091708, 2083204932, 4138385632, 3195157567,
     1318086382, 521723799, 702443405, 2507670985, 1760347557, 2631999893, 1672737554, 1060867760],
    // Round 24
    [2359801781, 2800231467, 3010357035, 1035997899, 1210110952, 1018506770, 2799468177, 1479380761,
     1536021911, 358993854, 579904113, 3432144800, 3625515809, 199241497, 4058304109, 2590164234],
    // Round 25
    [1688530738, 1580733335, 2443981517, 2206270565, 2780074229, 2628739677, 2940123659, 4145206827,
     3572278009, 2779607509, 1098718697, 1424913749, 2224415875, 1108922178, 3646272562, 3935186184],
    // Round 26
    [820046587, 1393386250, 2665818575, 2231782019, 672377010, 1920315467, 1913164407, 2029526876,
     2629271820, 384320012, 4112320585, 3131824773, 2347818197, 2220997386, 1772368609, 2579960095],
    // Round 27
    [3544930873, 225847443, 3070082278, 95643305, 3438572042, 3312856509, 615850007, 1863868773,
     803582265, 3461976859, 2903025799, 1482092434, 3902972499, 3872341868, 1530411808, 2214923584],
    // Round 28
    [3118792481, 2241076515, 3983669831, 3180915147, 3838626501, 1921630011, 3415351771, 2249953859,
     3755081630, 486327260, 1227575720, 3643869379, 2982026073, 2466043731, 1982634375, 3769609014],
    // Round 29
    [2195455495, 2596863283, 4244994973, 1983609348, 4019674395, 3469982031, 1458697570, 1593516217,
     1963896497, 3115309118, 1659132465, 2536770756, 3059294171, 2618031334, 2040903247, 3799795076],
];

/// Get round constants as field elements
/// Note: Values in RC16 may exceed the field modulus, so we use from_wrapped_u32
pub fn get_round_constants<F: PrimeField64>() -> Vec<[F; WIDTH]> {
    RC16.iter()
        .map(|row| {
            let mut result = [F::zero(); WIDTH];
            for (i, &v) in row.iter().enumerate() {
                // Use from_wrapped to handle values >= modulus
                result[i] = F::from_wrapped_u32(v);
            }
            result
        })
        .collect()
}

/// Internal diagonal matrix constants (matInternalDiagM1)
/// From gnark-ffi/go/sp1/poseidon2/poseidon2_babybear.go
pub fn get_internal_diag<F: PrimeField64>() -> [F; WIDTH] {
    [
        F::from_canonical_u64(2013265919), // -2 mod p
        F::from_canonical_u64(1),
        F::from_canonical_u64(2),
        F::from_canonical_u64(4),
        F::from_canonical_u64(8),
        F::from_canonical_u64(16),
        F::from_canonical_u64(32),
        F::from_canonical_u64(64),
        F::from_canonical_u64(128),
        F::from_canonical_u64(256),
        F::from_canonical_u64(512),
        F::from_canonical_u64(1024),
        F::from_canonical_u64(2048),
        F::from_canonical_u64(4096),
        F::from_canonical_u64(8192),
        F::from_canonical_u64(32768),
    ]
}

/// Monty inverse constant
pub fn get_monty_inverse<F: PrimeField64>() -> F {
    F::from_canonical_u64(943718400)
}

/// R1CS helper for Poseidon2 expansion
pub struct Poseidon2R1CS<F: PrimeField64> {
    _phantom: std::marker::PhantomData<F>,
}

impl<F: PrimeField64> Poseidon2R1CS<F> {
    /// Expand a BabyBear Poseidon2 permutation into R1CS constraints.
    ///
    /// Returns the output state variable indices. The caller is responsible
    /// for binding these to the declared output variables.
    ///
    /// # Arguments
    /// * `r1cs` - The R1CS being constructed
    /// * `next_var` - Next available variable index (updated by this function)
    /// * `input_state` - The 16 input state variable indices
    ///
    /// # Returns
    /// The 16 output state variable indices
    pub fn expand_permute_babybear(
        r1cs: &mut R1CS<F>,
        next_var: &mut usize,
        input_state: &[usize],
    ) -> [usize; WIDTH] {
        assert_eq!(input_state.len(), WIDTH);
        
        // Working state (we'll track current indices for each position)
        let mut current_state: [usize; WIDTH] = input_state.try_into().unwrap();
        
        let rc = get_round_constants::<F>();
        let internal_diag = get_internal_diag::<F>();
        let monty_inv = get_monty_inverse::<F>();
        
        // Initial linear layer
        Self::external_linear_layer(r1cs, next_var, &mut current_state);
        
        // First half of external rounds (4 rounds)
        let rounds_f_beginning = NUM_EXTERNAL_ROUNDS / 2;
        for r in 0..rounds_f_beginning {
            Self::add_round_constants(r1cs, next_var, &mut current_state, &rc[r]);
            Self::sbox_layer(r1cs, next_var, &mut current_state);
            Self::external_linear_layer(r1cs, next_var, &mut current_state);
        }
        
        // Internal rounds (13 rounds)
        let p_end = rounds_f_beginning + NUM_INTERNAL_ROUNDS;
        for r in rounds_f_beginning..p_end {
            // Only add RC to first element
            current_state[0] = Self::add_const(r1cs, next_var, current_state[0], rc[r][0]);
            // S-box only on first element
            current_state[0] = Self::sbox_single(r1cs, next_var, current_state[0]);
            // Diffusion permutation
            Self::diffusion_permute(r1cs, next_var, &mut current_state, &internal_diag, monty_inv);
        }
        
        // Second half of external rounds (4 rounds)
        let total_rounds = NUM_EXTERNAL_ROUNDS + NUM_INTERNAL_ROUNDS;
        for r in p_end..total_rounds {
            Self::add_round_constants(r1cs, next_var, &mut current_state, &rc[r]);
            Self::sbox_layer(r1cs, next_var, &mut current_state);
            Self::external_linear_layer(r1cs, next_var, &mut current_state);
        }
        
        // Return the computed output state indices
        current_state
    }

    /// Expand a BabyBear Poseidon2 permutation into R1CS constraints **and** compute witness
    /// values for all intermediate variables allocated during the expansion.
    ///
    /// The caller must provide a witness vector where:
    /// - `witness[0] == 1` (constant one),
    /// - `witness[input_state[i]]` is already populated for all inputs.
    ///
    /// This function will `resize` the witness vector as needed and will assign values to every
    /// newly allocated variable index, exactly matching the allocation order used by
    /// `expand_permute_babybear`.
    pub fn expand_permute_babybear_with_witness(
        r1cs: &mut R1CS<F>,
        next_var: &mut usize,
        input_state: &[usize],
        witness: &mut Vec<F>,
    ) -> [usize; WIDTH] {
        assert_eq!(input_state.len(), WIDTH);

        // Ensure witness is large enough for current indices.
        let need = (*next_var).max(input_state.iter().copied().max().unwrap_or(0) + 1);
        if witness.len() < need {
            witness.resize(need, F::zero());
        }

        // Working state (we'll track current indices for each position)
        let mut current_state: [usize; WIDTH] = input_state.try_into().unwrap();

        let rc = get_round_constants::<F>();
        let internal_diag = get_internal_diag::<F>();
        let monty_inv = get_monty_inverse::<F>();

        // Initial linear layer
        Self::external_linear_layer_w(r1cs, next_var, &mut current_state, witness);

        // First half of external rounds (4 rounds)
        let rounds_f_beginning = NUM_EXTERNAL_ROUNDS / 2;
        for r in 0..rounds_f_beginning {
            Self::add_round_constants_w(r1cs, next_var, &mut current_state, &rc[r], witness);
            Self::sbox_layer_w(r1cs, next_var, &mut current_state, witness);
            Self::external_linear_layer_w(r1cs, next_var, &mut current_state, witness);
        }

        // Internal rounds (13 rounds)
        let p_end = rounds_f_beginning + NUM_INTERNAL_ROUNDS;
        for r in rounds_f_beginning..p_end {
            // Only add RC to first element
            current_state[0] = Self::add_const_w(r1cs, next_var, current_state[0], rc[r][0], witness);
            // S-box only on first element
            current_state[0] = Self::sbox_single_w(r1cs, next_var, current_state[0], witness);
            // Diffusion permutation
            Self::diffusion_permute_w(
                r1cs,
                next_var,
                &mut current_state,
                &internal_diag,
                monty_inv,
                witness,
            );
        }

        // Second half of external rounds (4 rounds)
        let total_rounds = NUM_EXTERNAL_ROUNDS + NUM_INTERNAL_ROUNDS;
        for r in p_end..total_rounds {
            Self::add_round_constants_w(r1cs, next_var, &mut current_state, &rc[r], witness);
            Self::sbox_layer_w(r1cs, next_var, &mut current_state, witness);
            Self::external_linear_layer_w(r1cs, next_var, &mut current_state, witness);
        }

        current_state
    }
    
    /// Allocate a new variable
    fn alloc(next_var: &mut usize) -> usize {
        let idx = *next_var;
        *next_var += 1;
        idx
    }

    fn alloc_w(next_var: &mut usize, r1cs: &mut R1CS<F>, witness: &mut Vec<F>) -> usize {
        let idx = Self::alloc(next_var);
        r1cs.num_vars = *next_var;
        if witness.len() < *next_var {
            witness.resize(*next_var, F::zero());
        }
        idx
    }
    
    /// Add a constant to a variable: result = var + const
    fn add_const(r1cs: &mut R1CS<F>, next_var: &mut usize, var: usize, constant: F) -> usize {
        if constant.is_zero() {
            return var;
        }
        let result = Self::alloc(next_var);
        r1cs.num_vars = *next_var;
        
        // result = var + constant
        // (1) * (var + constant) = result
        let mut sum = SparseRow::new();
        sum.add_term(var, F::one());
        sum.add_term(0, constant); // constant uses index 0 (which holds 1)
        r1cs.add_constraint(
            SparseRow::single(0),
            sum,
            SparseRow::single(result),
        );
        result
    }

    fn add_const_w(
        r1cs: &mut R1CS<F>,
        next_var: &mut usize,
        var: usize,
        constant: F,
        witness: &mut Vec<F>,
    ) -> usize {
        if constant.is_zero() {
            return var;
        }
        let result = Self::alloc_w(next_var, r1cs, witness);
        witness[result] = witness[var] + constant;

        // result = var + constant
        // (1) * (var + constant) = result
        let mut sum = SparseRow::new();
        sum.add_term(var, F::one());
        sum.add_term(0, constant); // constant uses index 0 (which holds 1)
        r1cs.add_constraint(
            SparseRow::single(0),
            sum,
            SparseRow::single(result),
        );
        result
    }
    
    /// Multiply two variables: result = a * b
    fn mul(r1cs: &mut R1CS<F>, next_var: &mut usize, a: usize, b: usize) -> usize {
        let result = Self::alloc(next_var);
        r1cs.num_vars = *next_var;
        
        r1cs.add_constraint(
            SparseRow::single(a),
            SparseRow::single(b),
            SparseRow::single(result),
        );
        result
    }

    fn mul_w(
        r1cs: &mut R1CS<F>,
        next_var: &mut usize,
        a: usize,
        b: usize,
        witness: &mut Vec<F>,
    ) -> usize {
        let result = Self::alloc_w(next_var, r1cs, witness);
        witness[result] = witness[a] * witness[b];
        r1cs.add_constraint(
            SparseRow::single(a),
            SparseRow::single(b),
            SparseRow::single(result),
        );
        result
    }
    
    /// Multiply variable by constant: result = var * const
    fn mul_const(r1cs: &mut R1CS<F>, next_var: &mut usize, var: usize, constant: F) -> usize {
        if constant == F::one() {
            return var;
        }
        let result = Self::alloc(next_var);
        r1cs.num_vars = *next_var;
        
        // result = var * constant
        // (1) * (var * constant) = result
        r1cs.add_constraint(
            SparseRow::single(0),
            SparseRow::single_with_coeff(var, constant),
            SparseRow::single(result),
        );
        result
    }

    fn mul_const_w(
        r1cs: &mut R1CS<F>,
        next_var: &mut usize,
        var: usize,
        constant: F,
        witness: &mut Vec<F>,
    ) -> usize {
        if constant == F::one() {
            return var;
        }
        let result = Self::alloc_w(next_var, r1cs, witness);
        witness[result] = witness[var] * constant;
        r1cs.add_constraint(
            SparseRow::single(0),
            SparseRow::single_with_coeff(var, constant),
            SparseRow::single(result),
        );
        result
    }
    
    /// Add two variables: result = a + b
    fn add(r1cs: &mut R1CS<F>, next_var: &mut usize, a: usize, b: usize) -> usize {
        let result = Self::alloc(next_var);
        r1cs.num_vars = *next_var;
        
        let mut sum = SparseRow::new();
        sum.add_term(a, F::one());
        sum.add_term(b, F::one());
        r1cs.add_constraint(
            SparseRow::single(0),
            sum,
            SparseRow::single(result),
        );
        result
    }

    fn add_w(
        r1cs: &mut R1CS<F>,
        next_var: &mut usize,
        a: usize,
        b: usize,
        witness: &mut Vec<F>,
    ) -> usize {
        let result = Self::alloc_w(next_var, r1cs, witness);
        witness[result] = witness[a] + witness[b];
        let mut sum = SparseRow::new();
        sum.add_term(a, F::one());
        sum.add_term(b, F::one());
        r1cs.add_constraint(
            SparseRow::single(0),
            sum,
            SparseRow::single(result),
        );
        result
    }
    
    /// S-box: x^7 using 4 multiplications
    /// x² = x * x
    /// x⁴ = x² * x²
    /// x⁶ = x⁴ * x²
    /// x⁷ = x⁶ * x
    pub fn sbox_single(r1cs: &mut R1CS<F>, next_var: &mut usize, x: usize) -> usize {
        let x2 = Self::mul(r1cs, next_var, x, x);
        let x4 = Self::mul(r1cs, next_var, x2, x2);
        let x6 = Self::mul(r1cs, next_var, x4, x2);
        let x7 = Self::mul(r1cs, next_var, x6, x);
        x7
    }

    fn sbox_single_w(
        r1cs: &mut R1CS<F>,
        next_var: &mut usize,
        x: usize,
        witness: &mut Vec<F>,
    ) -> usize {
        let x2 = Self::mul_w(r1cs, next_var, x, x, witness);
        let x4 = Self::mul_w(r1cs, next_var, x2, x2, witness);
        let x6 = Self::mul_w(r1cs, next_var, x4, x2, witness);
        let x7 = Self::mul_w(r1cs, next_var, x6, x, witness);
        x7
    }
    
    /// Apply S-box to all state elements
    fn sbox_layer(r1cs: &mut R1CS<F>, next_var: &mut usize, state: &mut [usize; WIDTH]) {
        for i in 0..WIDTH {
            state[i] = Self::sbox_single(r1cs, next_var, state[i]);
        }
    }

    fn sbox_layer_w(
        r1cs: &mut R1CS<F>,
        next_var: &mut usize,
        state: &mut [usize; WIDTH],
        witness: &mut Vec<F>,
    ) {
        for i in 0..WIDTH {
            state[i] = Self::sbox_single_w(r1cs, next_var, state[i], witness);
        }
    }
    
    /// Add round constants to state
    fn add_round_constants(
        r1cs: &mut R1CS<F>,
        next_var: &mut usize,
        state: &mut [usize; WIDTH],
        rc: &[F; WIDTH],
    ) {
        for i in 0..WIDTH {
            state[i] = Self::add_const(r1cs, next_var, state[i], rc[i]);
        }
    }

    fn add_round_constants_w(
        r1cs: &mut R1CS<F>,
        next_var: &mut usize,
        state: &mut [usize; WIDTH],
        rc: &[F; WIDTH],
        witness: &mut Vec<F>,
    ) {
        for i in 0..WIDTH {
            state[i] = Self::add_const_w(r1cs, next_var, state[i], rc[i], witness);
        }
    }
    
    /// MDS light permutation for 4x4 block
    fn mds_light_4x4(
        r1cs: &mut R1CS<F>,
        next_var: &mut usize,
        state: &mut [usize],
    ) {
        assert_eq!(state.len(), 4);
        
        // t01 = state[0] + state[1]
        let t01 = Self::add(r1cs, next_var, state[0], state[1]);
        // t23 = state[2] + state[3]
        let t23 = Self::add(r1cs, next_var, state[2], state[3]);
        // t0123 = t01 + t23
        let t0123 = Self::add(r1cs, next_var, t01, t23);
        // t01123 = t0123 + state[1]
        let t01123 = Self::add(r1cs, next_var, t0123, state[1]);
        // t01233 = t0123 + state[3]
        let t01233 = Self::add(r1cs, next_var, t0123, state[3]);
        
        // state[3] = t01233 + 2*state[0]
        let two_s0 = Self::mul_const(r1cs, next_var, state[0], F::from_canonical_u64(2));
        let new_s3 = Self::add(r1cs, next_var, t01233, two_s0);
        
        // state[1] = t01123 + 2*state[2]
        let two_s2 = Self::mul_const(r1cs, next_var, state[2], F::from_canonical_u64(2));
        let new_s1 = Self::add(r1cs, next_var, t01123, two_s2);
        
        // state[0] = t01123 + t01
        let new_s0 = Self::add(r1cs, next_var, t01123, t01);
        
        // state[2] = t01233 + t23
        let new_s2 = Self::add(r1cs, next_var, t01233, t23);
        
        state[0] = new_s0;
        state[1] = new_s1;
        state[2] = new_s2;
        state[3] = new_s3;
    }

    fn mds_light_4x4_w(
        r1cs: &mut R1CS<F>,
        next_var: &mut usize,
        state: &mut [usize],
        witness: &mut Vec<F>,
    ) {
        assert_eq!(state.len(), 4);

        let t01 = Self::add_w(r1cs, next_var, state[0], state[1], witness);
        let t23 = Self::add_w(r1cs, next_var, state[2], state[3], witness);
        let t0123 = Self::add_w(r1cs, next_var, t01, t23, witness);
        let t01123 = Self::add_w(r1cs, next_var, t0123, state[1], witness);
        let t01233 = Self::add_w(r1cs, next_var, t0123, state[3], witness);

        let two_s0 = Self::mul_const_w(r1cs, next_var, state[0], F::from_canonical_u64(2), witness);
        let new_s3 = Self::add_w(r1cs, next_var, t01233, two_s0, witness);

        let two_s2 = Self::mul_const_w(r1cs, next_var, state[2], F::from_canonical_u64(2), witness);
        let new_s1 = Self::add_w(r1cs, next_var, t01123, two_s2, witness);

        let new_s0 = Self::add_w(r1cs, next_var, t01123, t01, witness);
        let new_s2 = Self::add_w(r1cs, next_var, t01233, t23, witness);

        state[0] = new_s0;
        state[1] = new_s1;
        state[2] = new_s2;
        state[3] = new_s3;
    }
    
    /// External linear layer
    fn external_linear_layer(
        r1cs: &mut R1CS<F>,
        next_var: &mut usize,
        state: &mut [usize; WIDTH],
    ) {
        // Apply 4x4 MDS to each block of 4
        for i in (0..WIDTH).step_by(4) {
            let mut block = [state[i], state[i+1], state[i+2], state[i+3]];
            Self::mds_light_4x4(r1cs, next_var, &mut block);
            state[i] = block[0];
            state[i+1] = block[1];
            state[i+2] = block[2];
            state[i+3] = block[3];
        }
        
        // Compute sums
        let mut sums = [state[0], state[1], state[2], state[3]];
        for i in (4..WIDTH).step_by(4) {
            sums[0] = Self::add(r1cs, next_var, sums[0], state[i]);
            sums[1] = Self::add(r1cs, next_var, sums[1], state[i+1]);
            sums[2] = Self::add(r1cs, next_var, sums[2], state[i+2]);
            sums[3] = Self::add(r1cs, next_var, sums[3], state[i+3]);
        }
        
        // Add sums to each element
        for i in 0..WIDTH {
            state[i] = Self::add(r1cs, next_var, state[i], sums[i % 4]);
        }
    }

    fn external_linear_layer_w(
        r1cs: &mut R1CS<F>,
        next_var: &mut usize,
        state: &mut [usize; WIDTH],
        witness: &mut Vec<F>,
    ) {
        for i in (0..WIDTH).step_by(4) {
            let mut block = [state[i], state[i + 1], state[i + 2], state[i + 3]];
            Self::mds_light_4x4_w(r1cs, next_var, &mut block, witness);
            state[i] = block[0];
            state[i + 1] = block[1];
            state[i + 2] = block[2];
            state[i + 3] = block[3];
        }

        let mut sums = [state[0], state[1], state[2], state[3]];
        for i in (4..WIDTH).step_by(4) {
            sums[0] = Self::add_w(r1cs, next_var, sums[0], state[i], witness);
            sums[1] = Self::add_w(r1cs, next_var, sums[1], state[i + 1], witness);
            sums[2] = Self::add_w(r1cs, next_var, sums[2], state[i + 2], witness);
            sums[3] = Self::add_w(r1cs, next_var, sums[3], state[i + 3], witness);
        }

        for i in 0..WIDTH {
            state[i] = Self::add_w(r1cs, next_var, state[i], sums[i % 4], witness);
        }
    }
    
    /// Internal matrix multiplication
    fn matmul_internal(
        r1cs: &mut R1CS<F>,
        next_var: &mut usize,
        state: &mut [usize; WIDTH],
        diag: &[F; WIDTH],
    ) {
        // sum = sum of all state elements
        let mut sum = state[0];
        for i in 1..WIDTH {
            sum = Self::add(r1cs, next_var, sum, state[i]);
        }
        
        // state[i] = state[i] * diag[i] + sum
        for i in 0..WIDTH {
            let scaled = Self::mul_const(r1cs, next_var, state[i], diag[i]);
            state[i] = Self::add(r1cs, next_var, scaled, sum);
        }
    }

    fn matmul_internal_w(
        r1cs: &mut R1CS<F>,
        next_var: &mut usize,
        state: &mut [usize; WIDTH],
        diag: &[F; WIDTH],
        witness: &mut Vec<F>,
    ) {
        let mut sum = state[0];
        for i in 1..WIDTH {
            sum = Self::add_w(r1cs, next_var, sum, state[i], witness);
        }
        for i in 0..WIDTH {
            let scaled = Self::mul_const_w(r1cs, next_var, state[i], diag[i], witness);
            state[i] = Self::add_w(r1cs, next_var, scaled, sum, witness);
        }
    }
    
    /// Diffusion permutation (internal rounds)
    fn diffusion_permute(
        r1cs: &mut R1CS<F>,
        next_var: &mut usize,
        state: &mut [usize; WIDTH],
        internal_diag: &[F; WIDTH],
        monty_inv: F,
    ) {
        Self::matmul_internal(r1cs, next_var, state, internal_diag);
        
        // Multiply each element by monty_inv
        for i in 0..WIDTH {
            state[i] = Self::mul_const(r1cs, next_var, state[i], monty_inv);
        }
    }

    fn diffusion_permute_w(
        r1cs: &mut R1CS<F>,
        next_var: &mut usize,
        state: &mut [usize; WIDTH],
        internal_diag: &[F; WIDTH],
        monty_inv: F,
        witness: &mut Vec<F>,
    ) {
        Self::matmul_internal_w(r1cs, next_var, state, internal_diag, witness);
        for i in 0..WIDTH {
            state[i] = Self::mul_const_w(r1cs, next_var, state[i], monty_inv, witness);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use p3_baby_bear::BabyBear;
    use p3_field::AbstractField;

    #[test]
    fn test_round_constants_loaded() {
        let rc = get_round_constants::<BabyBear>();
        assert_eq!(rc.len(), 30);
        
        // Verify first constant of round 0 (need from_wrapped_u32 as values may exceed modulus)
        assert_eq!(rc[0][0], BabyBear::from_wrapped_u32(2110014213));
        // Verify last constant of round 29
        assert_eq!(rc[29][15], BabyBear::from_wrapped_u32(3799795076));
    }

    #[test]
    fn test_sbox_constraints() {
        // Verify that x^7 is correctly constrained
        let mut r1cs = R1CS::<BabyBear>::new();
        let mut next_var = 1;
        
        // Allocate input variable
        let x = next_var;
        next_var += 1;
        r1cs.num_vars = next_var;
        
        // Apply S-box
        let x7 = Poseidon2R1CS::<BabyBear>::sbox_single(&mut r1cs, &mut next_var, x);
        
        // Should have 4 multiplication constraints (x², x⁴, x⁶, x⁷)
        assert_eq!(r1cs.num_constraints, 4);
        
        // Verify with a concrete value
        let test_val = BabyBear::from_canonical_u64(7);
        let expected = test_val * test_val * test_val * test_val * test_val * test_val * test_val;
        
        // Build witness
        let mut witness = vec![BabyBear::one(); r1cs.num_vars]; // witness[0] = 1
        witness[x] = test_val;
        
        // Compute intermediate values
        let x2_val = test_val * test_val;
        let x4_val = x2_val * x2_val;
        let x6_val = x4_val * x2_val;
        let x7_val = x6_val * test_val;
        
        // Fill in intermediates (indices 2, 3, 4, 5 based on allocation order)
        witness[2] = x2_val;
        witness[3] = x4_val;
        witness[4] = x6_val;
        witness[5] = x7_val;
        
        assert!(r1cs.is_satisfied(&witness));
        assert_eq!(witness[x7], expected);
    }
}
