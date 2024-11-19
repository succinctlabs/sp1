#pragma once

#include "prelude.hpp"
#include "babybear.hpp"

namespace sp1_core_machine_sys::septic {
    struct BabyBearSeptic {
        // The value of BabyBear septic extension element, in Montgomery form. 
        BabyBear value[7];

        __SP1_INLINE__ BabyBearSeptic() {} 

        __SP1_INLINE__ BabyBearSeptic(BabyBearP3 value) {
            this->value[0] = BabyBear(value);
            for (uintptr_t i = 1 ; i < 7 ; i++) {
                this->value[i] = BabyBear(0);
            }
        }

        __SP1_INLINE__ BabyBearSeptic(BabyBear value) {
            this->value[0] = value;
            for (uintptr_t i = 1 ; i < 7 ; i++) {
                this->value[i] = BabyBear(0);
            }
        }

        __SP1_INLINE__ BabyBearSeptic(BabyBearP3 value[7]) {
            for (uintptr_t i = 0 ; i < 7 ; i++) {
                this->value[i] = BabyBear(value[i]);
            }
        }

        __SP1_INLINE__ BabyBearSeptic(BabyBear value[7]) {
            for (uintptr_t i = 0 ; i < 7 ; i++) {
                this->value[i] = value[i];
            }
        }

        __SP1_INLINE__ BabyBearSeptic(SepticExtension<BabyBearP3> value) {
            for (uintptr_t i = 0 ; i < 7 ; i++) {
                this->value[i] = BabyBear(value._0[i]);
            }
        }

        BabyBearSeptic zero();

        BabyBearSeptic one();

        BabyBearSeptic two();

        BabyBearSeptic from_canonical_u32(uint32_t n);

        BabyBearSeptic& operator+=(const BabyBear b);

        friend __SP1_INLINE__ BabyBearSeptic operator+(BabyBearSeptic a, const BabyBear b) {
            return a += b;
        }

        BabyBearSeptic& operator+=(const BabyBearSeptic b);

        friend __SP1_INLINE__ BabyBearSeptic operator+(BabyBearSeptic a, const BabyBearSeptic b) {
            return a += b;
        }

        BabyBearSeptic& operator-=(const BabyBear b);

        friend __SP1_INLINE__ BabyBearSeptic operator-(BabyBearSeptic a, const BabyBear b) {
            return a -= b;
        }

        BabyBearSeptic& operator-=(const BabyBearSeptic b);

        friend __SP1_INLINE__ BabyBearSeptic operator-(BabyBearSeptic a, const BabyBearSeptic b) {
            return a -= b;
        }

        BabyBearSeptic& operator*=(const BabyBear b);

        friend __SP1_INLINE__ BabyBearSeptic operator*(BabyBearSeptic a, const BabyBear b) {
            return a *= b;
        }

        BabyBearSeptic& operator*=(const BabyBearSeptic b);

        friend __SP1_INLINE__ BabyBearSeptic operator*(BabyBearSeptic a, const BabyBearSeptic b) {
            return a *= b;
        }

        /// Inverts a BabyBear septic extension field element.
        BabyBearSeptic reciprocal() const;

        /// Divides one BabyBear field element by another.
        friend __SP1_INLINE__ BabyBearSeptic operator/(BabyBearSeptic a, BabyBearSeptic b) {
            return a * b.reciprocal();
        }

        __SP1_INLINE__ BabyBearSeptic& operator/=(const BabyBearSeptic a) {
            return *this *= a.reciprocal();
        }

        BabyBear pow_r() const;

        BabyBearSeptic sqrt() const;

        BabyBearSeptic pow_r_1() const;

        BabyBearSeptic frobenius() const;

        BabyBearSeptic double_frobenius() const;
    };

    struct BabyBearSepticCurve {
        BabyBearSeptic x;
        BabyBearSeptic y;

        __SP1_INLINE__ BabyBearSepticCurve(BabyBearSeptic x, BabyBearSeptic y) {
            this->x = x;
            this->y = y;
        }
    };

    struct BabyBearCipolla {
        BabyBear real;
        BabyBear imag;

         __SP1_INLINE__ BabyBearCipolla(BabyBearP3 real, BabyBearP3 imag) {
            this->real = BabyBear(real);
            this->imag = BabyBear(imag);
        }

        __SP1_INLINE__ BabyBearCipolla(BabyBear real, BabyBear imag) {
            this->real = real;
            this->imag = imag;
        }

        BabyBearCipolla one() const;

        BabyBearCipolla mul_ext(BabyBearCipolla other, BabyBear nonresidue);

        BabyBearCipolla pow(uint32_t exponent, BabyBear nonresidue);
    };
}
