//! GPU implementations of the two 2-to-1 reduction options.  The CPU
//! reference + protocol description lives in
//! [`slop_multilinear::two_to_one`].
//!
//! These are bench-focused implementations used to decide which option to
//! wire into the production jagged prover.

#![allow(dead_code)]

use std::sync::OnceLock;

use slop_algebra::{AbstractField, Field, UnivariatePolynomial};
use slop_alloc::Buffer;
use slop_challenger::FieldChallenger;
use slop_multilinear::Point;
use slop_tensor::Tensor;
use sp1_gpu_cudart::sys::v2_kernels::two_to_one_sum_as_poly_zero_kernel;
use sp1_gpu_cudart::{args, DeviceMle, DevicePoint, DeviceTensor, TaskScope};
use sp1_gpu_utils::{Ext, Felt};

// =========================================================================
// Lagrange-to-power matrix cache for nodes {0, 1, ..., n}.
//
// The 2-to-1 univariate `F(T) = h(z + T(z'-z))` has degree `n`
// (= log_stacking_height, in [18, 21] in production).  Interpolating from
// n+1 evaluations to power-form coefficients via the generic
// `interpolate_univariate_polynomial` is O(n^3) in EF ops; using the
// precomputed base-field Lagrange matrix turns this into (n+1)^2 EF * F
// mults.  Mirrors the strategy in `sp1_gpu_jagged_sumcheck::product`.
// =========================================================================

/// Build the (n+1) x (n+1) Lagrange-to-power matrix for nodes {0, 1, ..., n}.
///
/// Entry `M[j * (n+1) + i]` is the coefficient of `x^j` in the i-th Lagrange
/// basis polynomial `L_i(x) = Π_{q ≠ i} (x - q) / (i - q)`.  All entries
/// live in `Felt` (the base field), so applying the matrix to ext-typed y
/// values is `(n+1)^2` cheap ext-by-felt mults.
fn build_lagrange_matrix(n: usize) -> Vec<Felt> {
    let m_size = n + 1;
    let mut m = vec![Felt::zero(); m_size * m_size];

    let mut num_coefs: Vec<Felt> = Vec::with_capacity(m_size);
    let mut next_coefs: Vec<Felt> = Vec::with_capacity(m_size + 1);

    for i in 0..m_size {
        let xi = Felt::from_canonical_u32(i as u32);

        // Numerator polynomial Π_{q ≠ i} (x - q), expanded into power form.
        num_coefs.clear();
        num_coefs.push(Felt::one());
        for q in 0..m_size {
            if q == i {
                continue;
            }
            let xq = Felt::from_canonical_u32(q as u32);
            next_coefs.clear();
            next_coefs.resize(num_coefs.len() + 1, Felt::zero());
            for (r, &c) in num_coefs.iter().enumerate() {
                next_coefs[r + 1] += c;
                next_coefs[r] -= c * xq;
            }
            std::mem::swap(&mut num_coefs, &mut next_coefs);
        }

        let mut denom = Felt::one();
        for q in 0..m_size {
            if q == i {
                continue;
            }
            let xq = Felt::from_canonical_u32(q as u32);
            denom *= xi - xq;
        }
        let denom_inv = denom.inverse();

        for j in 0..m_size {
            m[j * m_size + i] = num_coefs[j] * denom_inv;
        }
    }

    m
}

/// Per-n cached Lagrange-to-power matrix.  Production `log_stacking_height`
/// lives in `[18, 21]`; we only cache those plus a few small sizes useful
/// for tests.
fn lagrange_matrix(n: usize) -> &'static [Felt] {
    static M_2: OnceLock<Vec<Felt>> = OnceLock::new();
    static M_4: OnceLock<Vec<Felt>> = OnceLock::new();
    static M_8: OnceLock<Vec<Felt>> = OnceLock::new();
    static M_18: OnceLock<Vec<Felt>> = OnceLock::new();
    static M_19: OnceLock<Vec<Felt>> = OnceLock::new();
    static M_20: OnceLock<Vec<Felt>> = OnceLock::new();
    static M_21: OnceLock<Vec<Felt>> = OnceLock::new();

    let slot = match n {
        2 => &M_2,
        4 => &M_4,
        8 => &M_8,
        18 => &M_18,
        19 => &M_19,
        20 => &M_20,
        21 => &M_21,
        _ => panic!("unsupported n={n} for two-to-one Lagrange matrix"),
    };

    slot.get_or_init(|| build_lagrange_matrix(n)).as_slice()
}

/// Interpolate a degree-`n` univariate from its evaluations at the n+1 nodes
/// `{0, 1, ..., n}` using the cached Lagrange-to-power matrix.
fn interpolate_from_nodes(evals: &[Ext]) -> UnivariatePolynomial<Ext> {
    let m_size = evals.len();
    let n = m_size - 1;
    let m = lagrange_matrix(n);
    let mut coefs: Vec<Ext> = Vec::with_capacity(m_size);
    for j in 0..m_size {
        let row_start = j * m_size;
        let mut acc = Ext::zero();
        for (i, &y) in evals.iter().enumerate() {
            acc += y * m[row_start + i];
        }
        coefs.push(acc);
    }
    UnivariatePolynomial::new(coefs)
}

// =========================================================================
// Option 1: univariate-on-the-line.
// =========================================================================

/// Prove the Option-1 reduction on device.
///
/// `h` is on device (a single polynomial of `n` variables).  `z` and
/// `z_prime` live on the host.  The prover evaluates
/// `F(T_k) = h(z + T_k (z' - z))` at `T_k = k` for `k = 0..=n` using a
/// single multi-point `partial_lagrange` launch + a `[n+1, 2^n]`-by-`[1, 2^n]`
/// dot product, then host-interpolates `F` via the cached Lagrange matrix.
///
/// Returns the coefficients of `F`, the new claim point `z''`, and
/// `h(z'') = F(λ')`.
pub fn prove_two_to_one_option1_gpu<Chal>(
    h: &DeviceMle<Ext>,
    z: &Point<Ext>,
    z_prime: &Point<Ext>,
    challenger: &mut Chal,
    backend: &TaskScope,
) -> (UnivariatePolynomial<Ext>, Point<Ext>, Ext)
where
    Chal: FieldChallenger<Felt>,
{
    let n = z.dimension();
    assert_eq!(z_prime.dimension(), n);
    let two_n = 1usize << n;
    // The device MLE may be reshaped/padded; we only need that its leading
    // dimension is at most 1 (single polynomial) and the entries cover 2^n.
    debug_assert_eq!(h.guts().sizes()[0], 1);
    debug_assert!(h.guts().sizes()[1] >= two_n);

    // Build the n+1 line points on host as a single concatenated buffer of
    // length (n+1) * n EF values, point p at offset p * n: p_k = z + k*(z'-z).
    let num_points = n + 1;
    let mut line_points: Vec<Ext> = Vec::with_capacity(num_points * n);
    for k in 0..num_points {
        let tk = Ext::from_canonical_usize(k);
        for i in 0..n {
            line_points.push(*z[i] + tk * (*z_prime[i] - *z[i]));
        }
    }

    // Upload as a single DevicePoint and run the multi-point partial_lagrange.
    let line_point_buf = Buffer::<Ext>::from(line_points);
    let line_point_host: Point<Ext> = line_point_buf.to_vec().into();
    let device_line = DevicePoint::from_host(&line_point_host, backend).unwrap();
    let eq_tensor = device_line.partial_lagrange_batched(n, num_points);

    // Dot the [num_points, 2^n] eq tensor with the [1, 2^n] h tensor along
    // the entries dim, getting [num_points] evaluations.
    let evals_tensor: DeviceTensor<Ext> = eq_tensor.guts().dot_along_dim(h.guts(), 1);

    let evals_host: Vec<Ext> = evals_tensor.to_host().unwrap().into_buffer().into_vec();
    debug_assert_eq!(evals_host.len(), num_points);

    let f = interpolate_from_nodes(&evals_host);

    for &c in &f.coefficients {
        challenger.observe_ext_element(c);
    }

    let lambda_prime: Ext = challenger.sample_ext_element();

    let z_pp: Point<Ext> =
        (0..n).map(|i| *z[i] + lambda_prime * (*z_prime[i] - *z[i])).collect::<Vec<_>>().into();
    let claim_z_pp = f.eval_at_point(lambda_prime);

    (f, z_pp, claim_z_pp)
}

// =========================================================================
// Option 2: batched sumcheck with Gruen + 1-accumulator-per-track.
// =========================================================================

/// Per-round message: only `G_T1(0)` and `G_T2(0)`.  Verifier reconstructs
/// the full degree-2 round univariates per track using the eq-factor
/// structure + the running sub-claims (see CPU reference).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Option2RoundMessage {
    pub g_t1_zero: Ext,
    pub g_t2_zero: Ext,
}

/// Launch the device sum-as-poly kernel and reduce block partials on host.
fn sum_as_poly_zero(
    eq_z: &DeviceMle<Ext>,
    eq_zp: &DeviceMle<Ext>,
    h: &DeviceMle<Ext>,
    half: usize,
    backend: &TaskScope,
) -> (Ext, Ext) {
    const BLOCK_SIZE: usize = 128;
    let grid_x = half.div_ceil(BLOCK_SIZE);

    let mut block_partial: Buffer<Ext, TaskScope> =
        Buffer::with_capacity_in(2 * grid_x, backend.clone());
    unsafe { block_partial.set_len(2 * grid_x) };

    // `BLOCK_SIZE / 32` Ext warp-tile scratch for `partialBlockReduce`.
    let shared_mem = (BLOCK_SIZE / 32).max(1) * std::mem::size_of::<Ext>();

    unsafe {
        let kernel = two_to_one_sum_as_poly_zero_kernel();
        let kargs = args!(
            eq_z.guts().as_ptr(),
            eq_zp.guts().as_ptr(),
            h.guts().as_ptr(),
            half as u32,
            block_partial.as_mut_ptr()
        );
        backend
            .launch_kernel(kernel, (grid_x, 1, 1), (BLOCK_SIZE, 1, 1), &kargs, shared_mem)
            .unwrap();
    }

    let host: Vec<Ext> = DeviceTensor::from_raw(Tensor::from(block_partial))
        .to_host()
        .unwrap()
        .into_buffer()
        .into_vec();
    let mut t1 = Ext::zero();
    let mut t2 = Ext::zero();
    for chunk in host.chunks_exact(2) {
        t1 += chunk[0];
        t2 += chunk[1];
    }
    (t1, t2)
}

/// Given `G(0)` and the running sub-claim `A = G(0) + G(1)`, reconstruct
/// `G(ρ)` using the Gruen factorization `G(t) = eq(z_round, t) · H(t)` with
/// `H` linear.  Mirrors the CPU helper in `slop_multilinear::two_to_one`.
fn g_round_at_rho(g_zero: Ext, a_k: Ext, z_round: Ext, rho: Ext) -> Ext {
    let g_one = a_k - g_zero;
    let one_minus_z = Ext::one() - z_round;
    let h_zero = if one_minus_z.is_zero() { Ext::zero() } else { g_zero * one_minus_z.inverse() };
    let h_one = if z_round.is_zero() { Ext::zero() } else { g_one * z_round.inverse() };
    let h_rho = h_zero + rho * (h_one - h_zero);
    let eq_round_rho = one_minus_z + (z_round + z_round - Ext::one()) * rho;
    eq_round_rho * h_rho
}

/// Prove the Option-2 reduction on device.
///
/// Round structure: per round, launch one sum-as-poly kernel to get
/// `(G_T1(0), G_T2(0))`, sample ρ via the host challenger, fold all three
/// device tables (`eq_z`, `eq_zp`, `h_current`) via the existing
/// `fix_last_variable_constant_padding` kernel.  Total per round: 1
/// sum-as-poly launch + 1 DtoH (block partials) + 3 fix_last_variable
/// launches.
///
/// Returns the per-round messages, the sumcheck point `ρ` in original-
/// variable order, and `h(ρ)`.
pub fn prove_two_to_one_option2_gpu<Chal>(
    h: DeviceMle<Ext>,
    z: &Point<Ext>,
    z_prime: &Point<Ext>,
    claim_z: Ext,
    claim_z_prime: Ext,
    challenger: &mut Chal,
    backend: &TaskScope,
) -> (Vec<Option2RoundMessage>, Point<Ext>, Ext)
where
    Chal: FieldChallenger<Felt>,
{
    let n = z.dimension();
    assert_eq!(z_prime.dimension(), n);

    // Build the two eq tables on device.  Each ends up shape [1, 2^n].
    let z_dev = DevicePoint::from_host(z, backend).unwrap();
    let zp_dev = DevicePoint::from_host(z_prime, backend).unwrap();
    let mut eq_z_curr = z_dev.partial_lagrange();
    let mut eq_zp_curr = zp_dev.partial_lagrange();

    // Take ownership of h; we fold it in place each round.
    let mut h_curr = h;

    let mut claim_t1 = claim_z;
    let mut claim_t2 = claim_z_prime;
    let mut messages: Vec<Option2RoundMessage> = Vec::with_capacity(n);
    let mut rhos: Vec<Ext> = Vec::with_capacity(n);

    for r in 0..n {
        let half = 1usize << (n - r - 1);
        let z_round = *z[n - r - 1];
        let zp_round = *z_prime[n - r - 1];

        let (g_t1_zero, g_t2_zero) =
            sum_as_poly_zero(&eq_z_curr, &eq_zp_curr, &h_curr, half, backend);

        challenger.observe_ext_element(g_t1_zero);
        challenger.observe_ext_element(g_t2_zero);
        let rho: Ext = challenger.sample_ext_element();
        rhos.push(rho);
        messages.push(Option2RoundMessage { g_t1_zero, g_t2_zero });

        claim_t1 = g_round_at_rho(g_t1_zero, claim_t1, z_round, rho);
        claim_t2 = g_round_at_rho(g_t2_zero, claim_t2, zp_round, rho);

        eq_z_curr = eq_z_curr.fix_last_variable_constant_padding(rho, Ext::zero());
        eq_zp_curr = eq_zp_curr.fix_last_variable_constant_padding(rho, Ext::zero());
        h_curr = h_curr.fix_last_variable_constant_padding(rho, Ext::zero());
    }

    // Final h(ρ) — h_curr now has shape [1, 1].
    let h_rho_vec: Vec<Ext> = h_curr.into_guts().to_host().unwrap().into_buffer().into_vec();
    let h_rho = h_rho_vec[0];

    // Point in original-variable order: variable k was fixed at round
    // (n-1-k), so original-position k carries `rhos[n - 1 - k]`.
    let point_orig: Point<Ext> = (0..n).map(|k| rhos[n - 1 - k]).collect::<Vec<_>>().into();

    let _ = (claim_t1, claim_t2);
    (messages, point_orig, h_rho)
}

// =========================================================================
// Tests.
// =========================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use rand::{rngs::StdRng, Rng, SeedableRng};
    use slop_alloc::Buffer;
    use slop_challenger::IopCtx;
    use slop_multilinear::Mle;
    use slop_tensor::Tensor;
    use sp1_gpu_cudart::{run_sync_in_place, DeviceBuffer};
    use sp1_primitives::SP1GlobalContext;

    type HostChallenger = <SP1GlobalContext as IopCtx>::Challenger;

    fn random_setup(n: usize, seed: u64) -> (Vec<Ext>, Point<Ext>, Point<Ext>, Ext, Ext) {
        let mut rng = StdRng::seed_from_u64(seed);
        let h_data: Vec<Ext> = (0..(1usize << n)).map(|_| rng.gen()).collect();
        let z: Point<Ext> = (0..n).map(|_| rng.gen()).collect::<Vec<_>>().into();
        let zp: Point<Ext> = (0..n).map(|_| rng.gen()).collect::<Vec<_>>().into();

        let mut tensor_cpu = Tensor::from(h_data.clone());
        tensor_cpu.reshape_in_place([1usize << n, 1usize]);
        let h_cpu = Mle::<Ext>::new(tensor_cpu);
        let claim_z = h_cpu.eval_at(&z).to_vec()[0];
        let claim_zp = h_cpu.eval_at(&zp).to_vec()[0];

        (h_data, z, zp, claim_z, claim_zp)
    }

    fn upload_h(h_data: &[Ext], n: usize, backend: &TaskScope) -> DeviceMle<Ext> {
        let h_buf_host = Buffer::<Ext>::from(h_data.to_vec());
        let h_dev = DeviceBuffer::from_host(&h_buf_host, backend).unwrap().into_inner();
        let dims = slop_tensor::Dimensions::try_from([1usize, 1usize << n]).unwrap();
        let h_tensor = slop_tensor::Tensor { storage: h_dev, dimensions: dims };
        DeviceMle::new(DeviceTensor::from_raw(h_tensor))
    }

    /// Option-1 GPU matches the CPU reference byte-for-byte (same RNG seed
    /// and the same challenger initialisation).
    #[test]
    fn option1_gpu_matches_cpu() {
        let n = 8usize;
        let (h_data, z, zp, _, _) = random_setup(n, 0xA1A1);
        let mut tensor_cpu = Tensor::from(h_data.clone());
        tensor_cpu.reshape_in_place([1usize << n, 1usize]);
        let h_cpu = Mle::<Ext>::new(tensor_cpu);

        let mut chal_cpu: HostChallenger = SP1GlobalContext::default_challenger();
        let (cpu_proof, cpu_zpp, cpu_claim) = slop_multilinear::prove_two_to_one_option1::<
            Felt,
            Ext,
            _,
        >(&h_cpu, &z, &zp, &mut chal_cpu);

        let (gpu_f, gpu_zpp, gpu_claim) = run_sync_in_place(|backend| {
            let h_mle = upload_h(&h_data, n, &backend);
            let mut chal_gpu: HostChallenger = SP1GlobalContext::default_challenger();
            prove_two_to_one_option1_gpu(&h_mle, &z, &zp, &mut chal_gpu, &backend)
        })
        .unwrap();

        assert_eq!(cpu_proof.f.coefficients, gpu_f.coefficients, "F coefficients mismatch");
        assert_eq!(
            cpu_zpp.iter().copied().collect::<Vec<_>>(),
            gpu_zpp.iter().copied().collect::<Vec<_>>(),
            "z'' mismatch",
        );
        assert_eq!(cpu_claim, gpu_claim, "h(z'') mismatch");
    }

    /// Option-2 GPU matches the CPU reference byte-for-byte.
    #[test]
    fn option2_gpu_matches_cpu() {
        let n = 8usize;
        let (h_data, z, zp, claim_z, claim_zp) = random_setup(n, 0xB2B2);
        let mut tensor_cpu = Tensor::from(h_data.clone());
        tensor_cpu.reshape_in_place([1usize << n, 1usize]);
        let h_cpu = Mle::<Ext>::new(tensor_cpu);

        let mut chal_cpu: HostChallenger = SP1GlobalContext::default_challenger();
        let (cpu_proof, cpu_point, cpu_claim) = slop_multilinear::prove_two_to_one_option2::<
            Felt,
            Ext,
            _,
        >(
            &h_cpu, &z, &zp, claim_z, claim_zp, &mut chal_cpu
        );

        let (gpu_msgs, gpu_point, gpu_claim) = run_sync_in_place(|backend| {
            let h_mle = upload_h(&h_data, n, &backend);
            let mut chal_gpu: HostChallenger = SP1GlobalContext::default_challenger();
            prove_two_to_one_option2_gpu(h_mle, &z, &zp, claim_z, claim_zp, &mut chal_gpu, &backend)
        })
        .unwrap();

        assert_eq!(gpu_msgs.len(), cpu_proof.rounds.len(), "round count mismatch");
        for (r, (cpu_r, gpu_r)) in cpu_proof.rounds.iter().zip(gpu_msgs.iter()).enumerate() {
            assert_eq!(cpu_r.g_t1_zero, gpu_r.g_t1_zero, "round {r}: G_T1(0) mismatch");
            assert_eq!(cpu_r.g_t2_zero, gpu_r.g_t2_zero, "round {r}: G_T2(0) mismatch");
        }
        assert_eq!(
            cpu_point.iter().copied().collect::<Vec<_>>(),
            gpu_point.iter().copied().collect::<Vec<_>>(),
            "sumcheck point mismatch",
        );
        assert_eq!(cpu_claim, gpu_claim, "h(ρ) mismatch");
    }
}
