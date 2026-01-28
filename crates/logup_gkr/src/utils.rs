use slop_alloc::{Backend, CpuBackend, HasBackend};
use slop_tensor::Tensor;
use sp1_gpu_cudart::{DeviceBuffer, DeviceMle, DeviceTensor, TaskScope};
use std::collections::BTreeSet;
use std::{collections::BTreeMap, iter::once};

use slop_algebra::AbstractField;
use slop_alloc::Buffer;
use slop_multilinear::{Mle, Point};
use std::sync::Arc;

use rand::Rng;

use crate::{
    interactions::Interactions,
    layer::{JaggedFirstGkrLayer, JaggedGkrLayer},
};
use sp1_gpu_utils::traces::JaggedTraceMle;
use sp1_gpu_utils::{DenseData, Ext, Felt, JaggedMle};

/// A layer of the GKR circuit.
///
/// This layer contains the polynomials p_0, p_1, q_0, q_1 evaluated at the layer size. The circuit
/// represents sparse values that can come from various chips with different sizes.
#[derive(Clone)]
pub struct GkrLayerGeneric<Layer: DenseData<B>, B: Backend = TaskScope> {
    /// A jagged MLE containing the polynomials p_0, p_1, q_0, q_1 evaluated at the layer size.
    pub jagged_mle: JaggedMle<Layer, B>,
    /// The number of row variables.
    pub num_row_variables: u32,
    /// The total number of interaction variables
    pub num_interaction_variables: u32,
}

#[allow(clippy::type_complexity)]
pub struct GkrInputData<'a> {
    /// Interactions per chip, on host.
    pub all_interactions: BTreeMap<String, Arc<Interactions<Felt, TaskScope>>>,

    pub chip_set: BTreeSet<String>,
    /// The jagged traces.
    pub jagged_trace_data: &'a JaggedTraceMle<Felt, TaskScope>,
    /// Some randomness used to initialize the denominators
    pub alpha: Ext,
    /// Some randomness used to batch the interaction values.
    pub beta_seed: Point<Ext>,
    /// The number of row variables.
    pub num_row_variables: u32,
    /// The backend.
    pub backend: TaskScope,
}

impl<'a> GkrInputData<'a> {
    /// Returns the height of the main trace for the given chip.
    ///
    /// Panics if the chip doesn't exist in the traces.
    #[inline]
    pub fn main_poly_height(&self, name: &str) -> Option<usize> {
        self.jagged_trace_data.main_poly_height(name)
    }

    /// # Safety
    ///
    /// The caller must ensure that the dense data is not dropped while the pointer is used.
    ///
    /// Returns a pointer to the dense data for the preprocessed traces of the given chip.
    ///
    /// If the chip doesn't exist, returns the null pointer.
    #[inline]
    pub unsafe fn preprocessed_ptr(&self, name: &str) -> *const Felt {
        match self.jagged_trace_data.dense_data.preprocessed_table_index.get(name) {
            Some(range) => {
                let base = self.jagged_trace_data.dense_data.dense.as_ptr();
                base.add(range.dense_offset.start)
            }
            None => std::ptr::null(),
        }
    }

    /// # Safety
    ///
    /// The caller must ensure that the dense data is not dropped while the pointer is used.
    ///
    /// Returns a pointer to the dense data for the main traces of the given chip.
    ///
    /// If the chip doesn't exist, returns the null pointer.
    #[inline]
    pub unsafe fn main_ptr(&self, name: &str) -> *const Felt {
        match self.jagged_trace_data.dense_data.main_table_index.get(name) {
            Some(range) => {
                let base = self.jagged_trace_data.dense_data.dense.as_ptr();
                base.add(range.dense_offset.start)
            }
            None => std::ptr::null(),
        }
    }
}

pub struct FirstLayerData<F, EF, B: Backend> {
    pub numerator: Tensor<F, B>,
    pub denominator: Tensor<EF, B>,
}

pub type GkrLayer<B = TaskScope> = GkrLayerGeneric<JaggedGkrLayer<B>, B>;

pub type FirstGkrLayer<B = TaskScope> = GkrLayerGeneric<JaggedFirstGkrLayer<B>, B>;

/// A layer of the GKR circuit.
pub enum GkrCircuitLayer<'a, B: Backend = TaskScope> {
    Materialized(GkrLayer<B>),
    FirstLayer(FirstGkrLayer<B>),
    FirstLayerVirtual(GkrInputData<'a>),
}

impl<'a> HasBackend for GkrCircuitLayer<'a, TaskScope> {
    type Backend = TaskScope;
    fn backend(&self) -> &TaskScope {
        match self {
            GkrCircuitLayer::Materialized(layer) => layer.jagged_mle.backend(),
            GkrCircuitLayer::FirstLayer(layer) => layer.jagged_mle.backend(),
            GkrCircuitLayer::FirstLayerVirtual(input_data) => &input_data.backend,
        }
    }
}

/// A polynomial layer of the GKR circuit.
#[derive(Clone)]
pub enum PolynomialLayer<B: Backend = TaskScope> {
    CircuitLayer(GkrLayer<B>),
    InteractionsLayer(Tensor<Ext, TaskScope>),
}

/// The first layer polynomial of the GKR circuit.
pub struct FirstLayerPolynomial {
    pub layer: FirstGkrLayer,
    pub eq_row: DeviceMle<Ext>,
    pub eq_interaction: DeviceMle<Ext>,
    pub lambda: Ext,
    pub point: Point<Ext>,
}

impl FirstLayerPolynomial {
    pub fn num_variables(&self) -> u32 {
        self.eq_row.num_variables() + self.eq_interaction.num_variables()
    }
}

/// A representation of the Logup GKR circuit on a GPU.
///
///
pub struct LogUpCudaCircuit<'a, A: Backend> {
    /// The materialized layers of the circuit.
    pub materialized_layers: Vec<GkrCircuitLayer<'a, A>>,
    /// The input data for the circuit.
    pub input_data: GkrInputData<'a>,
    /// The number of virtual layers.
    ///
    /// In practice, this is set to 1 when the circuit is initially generated with the first layer,
    /// and 0 after the materialized layers are exhausted and we finish generating the first layer.
    pub num_virtual_layers: usize,
}

impl<'a> HasBackend for LogUpCudaCircuit<'a, TaskScope> {
    type Backend = TaskScope;
    fn backend(&self) -> &TaskScope {
        &self.input_data.backend
    }
}

/// A normal GKR round polynomial. Compare this to FirstLayerPolynomial.
#[derive(Clone)]
pub struct LogupRoundPolynomial {
    /// The values of the numerator and denominator polynomials.
    pub layer: PolynomialLayer,
    /// The partial lagrange evaluation for the row variables.
    pub eq_row: DeviceMle<Ext>,
    /// The partial lagrange evaluation for the interaction variables.
    pub eq_interaction: DeviceMle<Ext>,
    /// The correction term for the eq polynomial.
    pub eq_adjustment: Ext,
    /// The correction term for padding.
    pub padding_adjustment: Ext,
    /// The batching factor for the numerator and denominator claims.
    pub lambda: Ext,
    /// The random point for the current GKR round.
    pub point: Point<Ext>,
}

impl LogupRoundPolynomial {
    pub fn num_variables(&self) -> u32 {
        self.eq_row.num_variables() + self.eq_interaction.num_variables()
    }
}

pub fn jagged_gkr_layer_to_device(
    jagged: JaggedMle<JaggedGkrLayer<CpuBackend>, CpuBackend>,
    backend: &TaskScope,
) -> JaggedMle<JaggedGkrLayer<TaskScope>, TaskScope> {
    let jagged_dense_device = JaggedGkrLayer {
        layer: DeviceTensor::from_host(&jagged.dense_data.layer, backend).unwrap().into_inner(),
        height: jagged.dense_data.height,
    };

    JaggedMle::new(
        jagged_dense_device,
        DeviceBuffer::from_host(&jagged.col_index, backend).unwrap().into_inner(),
        DeviceBuffer::from_host(&jagged.start_indices, backend).unwrap().into_inner(),
        jagged.column_heights,
    )
}

pub fn jagged_gkr_layer_to_host(
    jagged: JaggedMle<JaggedGkrLayer<TaskScope>, TaskScope>,
) -> JaggedMle<JaggedGkrLayer<CpuBackend>, CpuBackend> {
    let jagged_dense_host = JaggedGkrLayer {
        layer: DeviceTensor::from_raw(jagged.dense_data.layer).to_host().unwrap(),
        height: jagged.dense_data.height,
    };

    JaggedMle::new(
        jagged_dense_host,
        DeviceBuffer::from_raw(jagged.col_index).to_host().unwrap().into(),
        DeviceBuffer::from_raw(jagged.start_indices).to_host().unwrap().into(),
        jagged.column_heights,
    )
}

pub fn jagged_first_gkr_layer_to_device(
    jagged: JaggedMle<JaggedFirstGkrLayer<CpuBackend>, CpuBackend>,
    backend: &TaskScope,
) -> JaggedMle<JaggedFirstGkrLayer<TaskScope>, TaskScope> {
    let jagged_dense_device = JaggedFirstGkrLayer {
        numerator: DeviceTensor::from_host(&jagged.dense_data.numerator, backend)
            .unwrap()
            .into_inner(),
        denominator: DeviceTensor::from_host(&jagged.dense_data.denominator, backend)
            .unwrap()
            .into_inner(),
        height: jagged.dense_data.height,
    };

    JaggedMle::new(
        jagged_dense_device,
        DeviceBuffer::from_host(&jagged.col_index, backend).unwrap().into_inner(),
        DeviceBuffer::from_host(&jagged.start_indices, backend).unwrap().into_inner(),
        jagged.column_heights,
    )
}

pub fn jagged_first_gkr_layer_to_host(
    jagged: JaggedMle<JaggedFirstGkrLayer<TaskScope>, TaskScope>,
) -> JaggedMle<JaggedFirstGkrLayer<CpuBackend>, CpuBackend> {
    let jagged_dense_host = JaggedFirstGkrLayer {
        numerator: DeviceTensor::from_raw(jagged.dense_data.numerator).to_host().unwrap(),
        denominator: DeviceTensor::from_raw(jagged.dense_data.denominator).to_host().unwrap(),
        height: jagged.dense_data.height,
    };

    JaggedMle::new(
        jagged_dense_host,
        DeviceBuffer::from_raw(jagged.col_index).to_host().unwrap().into(),
        DeviceBuffer::from_raw(jagged.start_indices).to_host().unwrap().into(),
        jagged.column_heights,
    )
}

// TODO: The rest of these should be configured for only test.
pub struct GkrTestData {
    pub numerator_0: Mle<Ext, CpuBackend>,
    pub numerator_1: Mle<Ext, CpuBackend>,
    pub denominator_0: Mle<Ext, CpuBackend>,
    pub denominator_1: Mle<Ext, CpuBackend>,
}

/// Generates a random first layer from an rng, and some interaction row counts.
///
/// Padded to num_row_variables if provided.
pub fn random_first_layer<R: Rng>(
    rng: &mut R,
    interaction_row_counts: Vec<u32>,
    num_row_variables: Option<u32>,
) -> FirstGkrLayer<CpuBackend> {
    let max_row_variables =
        interaction_row_counts.iter().max().copied().unwrap().next_power_of_two().ilog2() + 1;

    let num_row_variables = if let Some(num_vars) = num_row_variables {
        assert!(num_vars >= max_row_variables);
        num_vars
    } else {
        max_row_variables
    };

    let num_interaction_variables = interaction_row_counts.len().next_power_of_two().ilog2();

    let interaction_start_indices = once(0)
        .chain(interaction_row_counts.iter().scan(0u32, |acc, x| {
            *acc += x;
            Some(*acc)
        }))
        .collect::<Buffer<_>>();
    let height = interaction_start_indices.last().copied().unwrap() as usize;
    let col_index = interaction_row_counts
        .iter()
        .enumerate()
        .flat_map(|(i, c)| vec![i as u32; *c as usize])
        .collect::<Buffer<_>>();

    let numerator = Tensor::<Felt>::rand(rng, [2, 1, height << 1]);
    let denominator = Tensor::<Ext>::rand(rng, [2, 1, height << 1]);
    let layer_data = JaggedFirstGkrLayer::new(numerator, denominator, height);

    let jagged_mle =
        JaggedMle::new(layer_data, col_index, interaction_start_indices, interaction_row_counts);

    FirstGkrLayer { jagged_mle, num_interaction_variables, num_row_variables }
}

/// Generates a random layer from an rng, and some interaction row counts.
///
/// Padded to num_row_variables if provided.
pub fn random_layer<R: Rng>(
    rng: &mut R,
    interaction_row_counts: Vec<u32>,
    num_row_variables: Option<u32>,
) -> GkrLayer<CpuBackend> {
    let max_row_variables =
        interaction_row_counts.iter().max().copied().unwrap().next_power_of_two().ilog2() + 1;

    let num_row_variables = if let Some(num_vars) = num_row_variables {
        assert!(num_vars >= max_row_variables);
        num_vars
    } else {
        max_row_variables
    };

    let num_interaction_variables = interaction_row_counts.len().next_power_of_two().ilog2();

    let interaction_start_indices = once(0)
        .chain(interaction_row_counts.iter().scan(0u32, |acc, x| {
            *acc += x;
            Some(*acc)
        }))
        .collect::<Buffer<_>>();
    let height = interaction_start_indices.last().copied().unwrap() as usize;
    let col_index = interaction_row_counts
        .iter()
        .enumerate()
        .flat_map(|(i, c)| {
            let data = i as u32;
            vec![data; *c as usize]
        })
        .collect::<Buffer<_>>();

    let layer_data = Tensor::<Ext>::rand(rng, [4, 1, 2 * height]);

    let jagged_gkr_layer = JaggedGkrLayer::new(layer_data, height);

    GkrLayer {
        jagged_mle: JaggedMle::new(
            jagged_gkr_layer,
            col_index,
            interaction_start_indices,
            interaction_row_counts,
        ),
        num_interaction_variables,
        num_row_variables,
    }
}

/// Generates test data for a layer.
pub fn generate_test_data<R: Rng>(
    rng: &mut R,
    interaction_row_counts: Vec<u32>,
    num_row_variables: Option<u32>,
) -> (GkrLayer<CpuBackend>, GkrTestData) {
    let layer = random_layer(rng, interaction_row_counts, num_row_variables);
    let test_data = get_polys_from_layer(&layer);
    (layer, test_data)
}

/// Gets nicely formatted numerator_0, numerator_1, denominator_0, denominator_1 polynomials from dense GkrLayer data.
/// Materializes padding for each row to 2^num_row_variables.
pub fn get_polys_from_layer(layer: &GkrLayer<CpuBackend>) -> GkrTestData {
    let GkrLayer {
        jagged_mle: JaggedMle { dense_data: layer_data, column_heights: interaction_row_counts, .. },
        num_interaction_variables,
        num_row_variables,
        ..
    } = layer;

    let full_padded_height = 1usize << num_row_variables;
    let get_mle = |values: Vec<Ext>,
                   padding: Ext,
                   interaction_row_counts: &[u32],
                   num_interaction_variables: u32,
                   full_padded_height: usize| {
        let total_size = (1 << num_interaction_variables) * full_padded_height;

        // Pre-allocate the entire result vector
        let mut result = vec![padding; total_size];

        // Calculate cumulative sizes to know where to read from values
        let mut read_offset = 0;

        // Process each interaction in forward order
        for (i, &row_count) in interaction_row_counts.iter().enumerate() {
            let h = (row_count as usize) << 1;
            let write_start = i * full_padded_height;

            // // Copy the actual values
            result[write_start..write_start + h]
                .copy_from_slice(&values[read_offset..read_offset + h]);
            // The rest is already filled with padding

            read_offset += h;
        }

        // Padding polynomials are already in place (filled with padding value)
        Mle::from(result)
    };

    // Extract numerator_0, numerator_1, denominator_0, denominator_1 from the layer_data
    let data_0 = layer_data.layer.get(0).unwrap().get(0).unwrap().as_slice().to_vec();
    let data_1 = layer_data.layer.get(1).unwrap().get(0).unwrap().as_slice().to_vec();
    let data_2 = layer_data.layer.get(2).unwrap().get(0).unwrap().as_slice().to_vec();
    let data_3 = layer_data.layer.get(3).unwrap().get(0).unwrap().as_slice().to_vec();

    let num_interaction_vars = *num_interaction_variables;

    let numerator_0 = get_mle(
        data_0,
        Ext::zero(),
        interaction_row_counts,
        num_interaction_vars,
        full_padded_height,
    );
    let numerator_1 = get_mle(
        data_1,
        Ext::zero(),
        interaction_row_counts,
        num_interaction_vars,
        full_padded_height,
    );
    let denominator_0 = get_mle(
        data_2,
        Ext::one(),
        interaction_row_counts,
        num_interaction_vars,
        full_padded_height,
    );
    let denominator_1 = get_mle(
        data_3,
        Ext::one(),
        interaction_row_counts,
        num_interaction_vars,
        full_padded_height,
    );

    GkrTestData { numerator_0, numerator_1, denominator_0, denominator_1 }
}
