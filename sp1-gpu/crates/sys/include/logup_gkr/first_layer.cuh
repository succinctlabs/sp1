#pragma once

#include "logup_gkr/round.cuh"
#include "config.cuh"

extern "C" void* logup_gkr_fix_last_variable_first_layer();
extern "C" void* logup_gkr_sum_as_poly_first_layer();
extern "C" void* logup_gkr_first_layer_transition();

struct FirstLayerCircuitValues {
  public:
    felt_t numeratorZero;
    felt_t numeratorOne;
    ext_t denominatorZero;
    ext_t denominatorOne;

  public:
    static __device__ __forceinline__ FirstLayerCircuitValues
    load(felt_t* numeratorValues, ext_t* denominatorValues, size_t i, size_t height) {
        FirstLayerCircuitValues values;

        // Load the numerator and denominator values
        // numeratorValues is the concatenation of numerator evaluations at 0 and then 1
        // likewise for denominatorValues

        values.numeratorZero = felt_t::load(numeratorValues, i);
        values.numeratorOne = felt_t::load(numeratorValues, i + 2 * height);
        values.denominatorZero = ext_t::load(denominatorValues, i);
        values.denominatorOne = ext_t::load(denominatorValues, i + 2 * height);

        return values;
    }

    static __device__ __forceinline__ FirstLayerCircuitValues
    load(const felt_t* numeratorValues, const ext_t* denominatorValues, size_t i, size_t height) {
        FirstLayerCircuitValues values;

        // Load the numerator and denominator values
        // numeratorValues is the concatenation of numerator evaluations at 0 and then 1
        // likewise for denominatorValues

        values.numeratorZero = felt_t::load(numeratorValues, i);
        values.numeratorOne = felt_t::load(numeratorValues, i + 2 * height);
        values.denominatorZero = ext_t::load(denominatorValues, i);
        values.denominatorOne = ext_t::load(denominatorValues, i + 2 * height);

        return values;
    }

    static __device__ __forceinline__ FirstLayerCircuitValues paddingValues() {
        FirstLayerCircuitValues values;
        values.numeratorZero = felt_t::zero();
        values.numeratorOne = felt_t::zero();
        values.denominatorZero = ext_t::one();
        values.denominatorOne = ext_t::one();
        return values;
    }

    static __device__ __forceinline__ CircuitValues fix_last_variable(
        FirstLayerCircuitValues zeroValues,
        FirstLayerCircuitValues oneValues,
        ext_t alpha) {
        CircuitValues values;
        values.numeratorZero =
            alpha.interpolateLinear(oneValues.numeratorZero, zeroValues.numeratorZero);
        values.numeratorOne =
            alpha.interpolateLinear(oneValues.numeratorOne, zeroValues.numeratorOne);
        values.denominatorZero =
            alpha.interpolateLinear(oneValues.denominatorZero, zeroValues.denominatorZero);
        values.denominatorOne =
            alpha.interpolateLinear(oneValues.denominatorOne, zeroValues.denominatorOne);
        return values;
    }

    __device__ __forceinline__ void
    store(felt_t* numeratorValues, ext_t* denominatorValues, size_t i, size_t height) {

        felt_t::store(numeratorValues, i, numeratorZero);
        felt_t::store(numeratorValues, i + 2 * height, numeratorOne);
        ext_t::store(denominatorValues, i, denominatorZero);
        ext_t::store(denominatorValues, i + 2 * height, denominatorOne);
    }

    /// Compute the sumcheck sum values
    __device__ __forceinline__ ext_t sumAsPoly(ext_t lambda, ext_t eqValue) {
        ext_t numerator = numeratorZero * denominatorOne + numeratorOne * denominatorZero;
        ext_t denominator = denominatorZero * denominatorOne;
        return eqValue * (numerator * lambda + denominator);
    }
};


/// A GKR layer.
struct JaggedFirstGkrLayer {
    using OutputDenseData = JaggedGkrLayer;

  public:
    /// numerator_0 || numerator_1
    felt_t* numeratorValues;
    /// denominator_0 || denominator_1
    ext_t* denominatorValues;
    /// Half of the length of each section.
    size_t height;

    __forceinline__ __device__ void fixLastVariable(
        JaggedGkrLayer& other,
        size_t restrictedIdx,
        size_t zeroIdx,
        size_t oneIdx,
        ext_t alpha) const {

        FirstLayerCircuitValues valuesZero =
            FirstLayerCircuitValues::load(numeratorValues, denominatorValues, zeroIdx, height);
        FirstLayerCircuitValues valuesOne =
            FirstLayerCircuitValues::load(numeratorValues, denominatorValues, oneIdx, height);
        CircuitValues values =
            FirstLayerCircuitValues::fix_last_variable(valuesZero, valuesOne, alpha);

        values.store(other.layer, restrictedIdx, other.height);
    }

    __forceinline__ __device__ void pad(JaggedGkrLayer& other, size_t restrictedIdx) const {
        CircuitValues values = CircuitValues::paddingValues();
        values.store(other.layer, restrictedIdx, other.height);
    }

    __forceinline__ __device__ void
    circuitTransition(JaggedGkrLayer& other, size_t restrictedIdx, size_t zeroIdx, size_t oneIdx)
        const {

        CircuitValues values;

        FirstLayerCircuitValues valuesZero =
            FirstLayerCircuitValues::load(numeratorValues, denominatorValues, zeroIdx, height);
        values.numeratorZero = valuesZero.numeratorZero * valuesZero.denominatorOne +
                               valuesZero.numeratorOne * valuesZero.denominatorZero;
        values.denominatorZero = valuesZero.denominatorZero * valuesZero.denominatorOne;

        FirstLayerCircuitValues valuesOne =
            FirstLayerCircuitValues::load(numeratorValues, denominatorValues, oneIdx, height);
        values.numeratorOne = (valuesOne.denominatorOne * valuesOne.numeratorZero) +
                              (valuesOne.denominatorZero * valuesOne.numeratorOne);
        values.denominatorOne = valuesOne.denominatorZero * valuesOne.denominatorOne;

        values.store(other.layer, restrictedIdx, other.height);
    }
};