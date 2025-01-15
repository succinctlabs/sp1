#pragma once

#include "prelude.hpp"
#include "bb31_t.hpp"
#include <cstdio>

#ifdef __CUDA_ARCH__
#define FUN __host__ __device__
#endif
#ifndef __CUDA_ARCH__
#define FUN inline
#endif

class bb31_cipolla_t {
    public:
        bb31_t real;
        bb31_t imag;

        FUN bb31_cipolla_t(bb31_t real, bb31_t imag) {
            this->real = bb31_t(real);
            this->imag = bb31_t(imag);
        }

        FUN static bb31_cipolla_t one() {
            return bb31_cipolla_t(bb31_t::one(), bb31_t::zero());
        }

        FUN bb31_cipolla_t mul_ext(bb31_cipolla_t other, bb31_t nonresidue) {
            bb31_t new_real = real * other.real + nonresidue * imag * other.imag;
            bb31_t new_imag = real * other.imag + imag * other.real;
            return bb31_cipolla_t(new_real, new_imag);
        }

        FUN bb31_cipolla_t pow(uint32_t exponent, bb31_t nonresidue) {
            bb31_cipolla_t result = bb31_cipolla_t::one();
            bb31_cipolla_t base = *this;

            while(exponent) {
                if(exponent & 1) {
                    result = result.mul_ext(base, nonresidue);
                }
                exponent >>= 1;
                base = base.mul_ext(base, nonresidue);
            }

            return result;
        }
};

namespace constants {
    #ifdef __CUDA_ARCH__
        __constant__ constexpr const bb31_t frobenius_const[49] = {
            bb31_t(int(1)), bb31_t(int(0)), bb31_t(int(0)), bb31_t(int(0)), bb31_t(int(0)), bb31_t(int(0)), bb31_t(int(0)),
            bb31_t(int(954599710)), bb31_t(int(1359279693)), bb31_t(int(566669999)), bb31_t(int(1982781815)), bb31_t(int(1735718361)), bb31_t(int(1174868538)), bb31_t(int(1120871770)),
            bb31_t(int(862825265)), bb31_t(int(597046311)), bb31_t(int(978840770)), bb31_t(int(1790138282)), bb31_t(int(1044777201)), bb31_t(int(835869808)), bb31_t(int(1342179023)),
            bb31_t(int(596273169)), bb31_t(int(658837454)), bb31_t(int(1515468261)), bb31_t(int(367059247)), bb31_t(int(781278880)), bb31_t(int(1544222616)), bb31_t(int(155490465)),
            bb31_t(int(557608863)), bb31_t(int(1173670028)), bb31_t(int(1749546888)), bb31_t(int(1086464137)), bb31_t(int(803900099)), bb31_t(int(1288818584)), bb31_t(int(1184677604)),
            bb31_t(int(763416381)), bb31_t(int(1252567168)), bb31_t(int(628856225)), bb31_t(int(1771903394)), bb31_t(int(650712211)), bb31_t(int(19417363)), bb31_t(int(57990258)),
            bb31_t(int(1734711039)), bb31_t(int(1749813853)), bb31_t(int(1227235221)), bb31_t(int(1707730636)), bb31_t(int(424560395)), bb31_t(int(1007029514)), bb31_t(int(498034669)),
        };

        __constant__ constexpr const bb31_t double_frobenius_const[49] = {
            bb31_t(int(1)), bb31_t(int(0)), bb31_t(int(0)), bb31_t(int(0)), bb31_t(int(0)), bb31_t(int(0)), bb31_t(int(0)),
            bb31_t(int(1013489358)), bb31_t(int(1619071628)), bb31_t(int(304593143)), bb31_t(int(1949397349)), bb31_t(int(1564307636)), bb31_t(int(327761151)), bb31_t(int(415430835)),
            bb31_t(int(209824426)), bb31_t(int(1313900768)), bb31_t(int(38410482)), bb31_t(int(256593180)), bb31_t(int(1708830551)), bb31_t(int(1244995038)), bb31_t(int(1555324019)),
            bb31_t(int(1475628651)), bb31_t(int(777565847)), bb31_t(int(704492386)), bb31_t(int(1218528120)), bb31_t(int(1245363405)), bb31_t(int(475884575)), bb31_t(int(649166061)),
            bb31_t(int(550038364)), bb31_t(int(948935655)), bb31_t(int(68722023)), bb31_t(int(1251345762)), bb31_t(int(1692456177)), bb31_t(int(1177958698)), bb31_t(int(350232928)),
            bb31_t(int(882720258)), bb31_t(int(821925756)), bb31_t(int(199955840)), bb31_t(int(812002876)), bb31_t(int(1484951277)), bb31_t(int(1063138035)), bb31_t(int(491712810)),
            bb31_t(int(738287111)), bb31_t(int(1955364991)), bb31_t(int(552724293)), bb31_t(int(1175775744)), bb31_t(int(341623997)), bb31_t(int(1454022463)), bb31_t(int(408193320))
        };

        __constant__ constexpr const bb31_t A_EC_LOGUP[7] = {bb31_t(int(0x31415926)), bb31_t(int(0x53589793)), bb31_t(int(0x23846264)), bb31_t(int(0x33832795)), bb31_t(int(0x02884197)), bb31_t(int(0x16939937)), bb31_t(int(0x51058209))};

        __constant__ constexpr const bb31_t B_EC_LOGUP[7] = {bb31_t(int(0x74944592)), bb31_t(int(0x30781640)), bb31_t(int(0x62862089)), bb31_t(int(0x9862803)), bb31_t(int(0x48253421)), bb31_t(int(0x17067982)), bb31_t(int(0x14808651))};

        __constant__ constexpr const bb31_t dummy_x[7] = {bb31_t(int(0x2738281)), bb31_t(int(0x8284590)), bb31_t(int(0x4523536)), bb31_t(int(0x0287471)), bb31_t(int(0x3526624)), bb31_t(int(0x9775724)), bb31_t(int(0x7093699))};
        __constant__ constexpr const bb31_t dummy_y[7] = {bb31_t(int(48041908)), bb31_t(int(550064556)), bb31_t(int(415267377)), bb31_t(int(1726976249)), bb31_t(int(1253299140)), bb31_t(int(209439863)), bb31_t(int(1302309485))};

        __constant__ constexpr bb31_t start_x[7] = {bb31_t(int(0x1434213)), bb31_t(int(0x5623730)), bb31_t(int(0x9504880)), bb31_t(int(0x1688724)), bb31_t(int(0x2096980)), bb31_t(int(0x7856967)), bb31_t(int(0x1875376))};
        __constant__ constexpr bb31_t start_y[7] = {bb31_t(int(885797405)), bb31_t(int(1130275556)), bb31_t(int(567836311)), bb31_t(int(52700240)), bb31_t(int(239639200)), bb31_t(int(442612155)), bb31_t(int(1839439733))};

    #endif

    #ifndef __CUDA_ARCH__
        static constexpr const bb31_t frobenius_const[49] = {
            bb31_t(int(1)), bb31_t(int(0)), bb31_t(int(0)), bb31_t(int(0)), bb31_t(int(0)), bb31_t(int(0)), bb31_t(int(0)),
            bb31_t(int(954599710)), bb31_t(int(1359279693)), bb31_t(int(566669999)), bb31_t(int(1982781815)), bb31_t(int(1735718361)), bb31_t(int(1174868538)), bb31_t(int(1120871770)),
            bb31_t(int(862825265)), bb31_t(int(597046311)), bb31_t(int(978840770)), bb31_t(int(1790138282)), bb31_t(int(1044777201)), bb31_t(int(835869808)), bb31_t(int(1342179023)),
            bb31_t(int(596273169)), bb31_t(int(658837454)), bb31_t(int(1515468261)), bb31_t(int(367059247)), bb31_t(int(781278880)), bb31_t(int(1544222616)), bb31_t(int(155490465)),
            bb31_t(int(557608863)), bb31_t(int(1173670028)), bb31_t(int(1749546888)), bb31_t(int(1086464137)), bb31_t(int(803900099)), bb31_t(int(1288818584)), bb31_t(int(1184677604)),
            bb31_t(int(763416381)), bb31_t(int(1252567168)), bb31_t(int(628856225)), bb31_t(int(1771903394)), bb31_t(int(650712211)), bb31_t(int(19417363)), bb31_t(int(57990258)),
            bb31_t(int(1734711039)), bb31_t(int(1749813853)), bb31_t(int(1227235221)), bb31_t(int(1707730636)), bb31_t(int(424560395)), bb31_t(int(1007029514)), bb31_t(int(498034669))
        };

        static constexpr const bb31_t double_frobenius_const[49] = {
            bb31_t(int(1)), bb31_t(int(0)), bb31_t(int(0)), bb31_t(int(0)), bb31_t(int(0)), bb31_t(int(0)), bb31_t(int(0)),
            bb31_t(int(1013489358)), bb31_t(int(1619071628)), bb31_t(int(304593143)), bb31_t(int(1949397349)), bb31_t(int(1564307636)), bb31_t(int(327761151)), bb31_t(int(415430835)),
            bb31_t(int(209824426)), bb31_t(int(1313900768)), bb31_t(int(38410482)), bb31_t(int(256593180)), bb31_t(int(1708830551)), bb31_t(int(1244995038)), bb31_t(int(1555324019)),
            bb31_t(int(1475628651)), bb31_t(int(777565847)), bb31_t(int(704492386)), bb31_t(int(1218528120)), bb31_t(int(1245363405)), bb31_t(int(475884575)), bb31_t(int(649166061)),
            bb31_t(int(550038364)), bb31_t(int(948935655)), bb31_t(int(68722023)), bb31_t(int(1251345762)), bb31_t(int(1692456177)), bb31_t(int(1177958698)), bb31_t(int(350232928)),
            bb31_t(int(882720258)), bb31_t(int(821925756)), bb31_t(int(199955840)), bb31_t(int(812002876)), bb31_t(int(1484951277)), bb31_t(int(1063138035)), bb31_t(int(491712810)),
            bb31_t(int(738287111)), bb31_t(int(1955364991)), bb31_t(int(552724293)), bb31_t(int(1175775744)), bb31_t(int(341623997)), bb31_t(int(1454022463)), bb31_t(int(408193320))
        };

        static constexpr const bb31_t A_EC_LOGUP[7] = {bb31_t(int(0x31415926)), bb31_t(int(0x53589793)), bb31_t(int(0x23846264)), bb31_t(int(0x33832795)), bb31_t(int(0x02884197)), bb31_t(int(0x16939937)), bb31_t(int(0x51058209))};
        static constexpr const bb31_t B_EC_LOGUP[7] = {bb31_t(int(0x74944592)), bb31_t(int(0x30781640)), bb31_t(int(0x62862089)), bb31_t(int(0x9862803)), bb31_t(int(0x48253421)), bb31_t(int(0x17067982)), bb31_t(int(0x14808651))};

        static constexpr bb31_t dummy_x[7] = {bb31_t(int(0x2738281)), bb31_t(int(0x8284590)), bb31_t(int(0x4523536)), bb31_t(int(0x0287471)), bb31_t(int(0x3526624)), bb31_t(int(0x9775724)), bb31_t(int(0x7093699))};
        static constexpr bb31_t dummy_y[7] = {bb31_t(int(48041908)), bb31_t(int(550064556)), bb31_t(int(415267377)), bb31_t(int(1726976249)), bb31_t(int(1253299140)), bb31_t(int(209439863)), bb31_t(int(1302309485))};

        static constexpr bb31_t start_x[7] = {bb31_t(int(0x1434213)), bb31_t(int(0x5623730)), bb31_t(int(0x9504880)), bb31_t(int(0x1688724)), bb31_t(int(0x2096980)), bb31_t(int(0x7856967)), bb31_t(int(0x1875376))};
        static constexpr bb31_t start_y[7] = {bb31_t(int(885797405)), bb31_t(int(1130275556)), bb31_t(int(567836311)), bb31_t(int(52700240)), bb31_t(int(239639200)), bb31_t(int(442612155)), bb31_t(int(1839439733))};

    #endif     
}   

class bb31_septic_extension_t {
    // The value of BabyBear septic extension element.
    public:
        bb31_t value[7];    
        static constexpr const bb31_t* frobenius_const = constants::frobenius_const;
        static constexpr const bb31_t* double_frobenius_const = constants::double_frobenius_const;
        static constexpr const bb31_t* A_EC_LOGUP = constants::A_EC_LOGUP;
        static constexpr const bb31_t* B_EC_LOGUP = constants::B_EC_LOGUP;

        FUN bb31_septic_extension_t() {
            for (uintptr_t i = 0 ; i < 7 ; i++) {
                this->value[i] = bb31_t(0);
            }
        } 

        FUN bb31_septic_extension_t(bb31_t value) {
            this->value[0] = value;
            for (uintptr_t i = 1 ; i < 7 ; i++) {
                this->value[i] = bb31_t(0);
            }
        }

        FUN bb31_septic_extension_t(bb31_t value[7]) {
            for (uintptr_t i = 0 ; i < 7 ; i++) {
                this->value[i] = value[i];
            }
        }

        FUN bb31_septic_extension_t(const bb31_t value[7]) {
            for (uintptr_t i = 0 ; i < 7 ; i++) {
                this->value[i] = value[i];
            }
        }

        static FUN bb31_septic_extension_t zero() {
            return bb31_septic_extension_t();
        }

        static FUN bb31_septic_extension_t one() {
            return bb31_septic_extension_t(bb31_t::one());
        }

        static FUN bb31_septic_extension_t two() {
            return bb31_septic_extension_t(bb31_t::two());
        }

        static FUN bb31_septic_extension_t from_canonical_u32(uint32_t n) {
            return bb31_septic_extension_t(bb31_t::from_canonical_u32(n));
        }

        FUN bb31_septic_extension_t& operator+=(const bb31_t b) {
            value[0] += b;
            return *this;
        }

        friend FUN bb31_septic_extension_t operator+(bb31_septic_extension_t a, const bb31_t b) {
            return a += b;
        }

        FUN bb31_septic_extension_t& operator+=(const bb31_septic_extension_t b) {
            for (uintptr_t i = 0 ; i < 7 ; i++) {
                value[i] += b.value[i];
            }
            return *this;
        }

        friend FUN bb31_septic_extension_t operator+(bb31_septic_extension_t a, const bb31_septic_extension_t b) {
            return a += b;
        }

        FUN bb31_septic_extension_t& operator-=(const bb31_t b) {
            value[0] -= b;
            return *this;
        }

        friend FUN bb31_septic_extension_t operator-(bb31_septic_extension_t a, const bb31_t b) {
            return a -= b;
        }

        FUN bb31_septic_extension_t& operator-=(const bb31_septic_extension_t b) {
            for (uintptr_t i = 0 ; i < 7 ; i++) {
                value[i] -= b.value[i];
            }
            return *this;
        }

        friend FUN bb31_septic_extension_t operator-(bb31_septic_extension_t a, const bb31_septic_extension_t b) {
            return a -= b;
        }

        FUN bb31_septic_extension_t& operator*=(const bb31_t b) {
            for (uintptr_t i = 0 ; i < 7 ; i++) {
                value[i] *= b;
            }
            return *this;
        }

        friend FUN bb31_septic_extension_t operator*(bb31_septic_extension_t a, const bb31_t b) {
            return a *= b;
        }

        FUN bb31_septic_extension_t& operator*=(const bb31_septic_extension_t b) {
            {
                bb31_t res[13] = {};
                for(uintptr_t i = 0 ; i < 13 ; i++) {
                    res[i] = bb31_t::zero();
                }
                for(uintptr_t i = 0 ; i < 7 ; i++) {
                    for(uintptr_t j = 0 ; j < 7 ; j++) {
                        res[i + j] += value[i] * b.value[j];
                    }
                }
                for(uintptr_t i = 7 ; i < 13 ; i++) {
                    res[i - 7] += res[i] * bb31_t::from_canonical_u32(5);
                    res[i - 6] += res[i] * bb31_t::from_canonical_u32(2);
                }
                for(uintptr_t i = 0 ; i < 7 ; i++) {
                    value[i] = res[i];
                }
            }
            return *this;
        }  

        friend FUN bb31_septic_extension_t operator*(bb31_septic_extension_t a, const bb31_septic_extension_t b) {
            return a *= b;
        }

        FUN bool operator==(const bb31_septic_extension_t rhs) const {
             for(uintptr_t i = 0 ; i < 7 ; i++) {
                if(value[i] != rhs.value[i]) {
                    return false;
                }
            }
            return true;
        }

        FUN bb31_septic_extension_t frobenius() const {
            bb31_t res[7] = {};
            res[0] = value[0];
            for(uintptr_t i = 1 ; i < 7 ; i++) {
                res[i] = bb31_t::zero();
            }
            for(uintptr_t i = 1 ; i < 7 ; i++) {
                for(uintptr_t j = 0 ; j < 7 ; j++) {
                    res[j] += value[i] * frobenius_const[7 * i + j];
                }
            }
            return bb31_septic_extension_t(res);

        }

        FUN bb31_septic_extension_t double_frobenius() const {
            bb31_t res[7] = {};
            res[0] = value[0];
            for(uintptr_t i = 1 ; i < 7 ; i++) {
                res[i] = bb31_t::zero();
            }
            for(uintptr_t i = 1 ; i < 7 ; i++) {
                for(uintptr_t j = 0 ; j < 7 ; j++) {
                    res[j] += value[i] * double_frobenius_const[7 * i + j];
                }
            }
            return bb31_septic_extension_t(res);

        }

        FUN bb31_septic_extension_t pow_r_1() const {
            bb31_septic_extension_t base = frobenius();
            base *= double_frobenius();
            bb31_septic_extension_t base_p2 = base.double_frobenius();
            bb31_septic_extension_t base_p4 = base_p2.double_frobenius();
            return base * base_p2 * base_p4;
        }

        FUN bb31_t pow_r() const {
            bb31_septic_extension_t pow_r1 = pow_r_1();
            bb31_septic_extension_t pow_r = pow_r1 * *this;
            return pow_r.value[0];
        }

        FUN bb31_septic_extension_t reciprocal() const {
            bb31_septic_extension_t pow_r1 = pow_r_1();
            bb31_septic_extension_t pow_r = pow_r1 * *this;
            return pow_r1 * pow_r.value[0].reciprocal();
        }

        friend FUN bb31_septic_extension_t operator/(bb31_septic_extension_t a, bb31_septic_extension_t b) {
            return a * b.reciprocal();
        }

        FUN bb31_septic_extension_t& operator/=(const bb31_septic_extension_t a) {
            return *this *= a.reciprocal();
        }

        FUN bb31_septic_extension_t sqrt(bb31_t pow_r) const {
            if (*this == bb31_septic_extension_t::zero()) {
                return *this;
            }

            bb31_septic_extension_t n_iter = *this;
            bb31_septic_extension_t n_power = *this;
            for(uintptr_t i = 1 ; i < 30 ; i++) {
                n_iter *= n_iter;
                if(i >= 26) {
                    n_power *= n_iter;
                }
            }

            bb31_septic_extension_t n_frobenius = n_power.frobenius();
            bb31_septic_extension_t denominator = n_frobenius;

            n_frobenius = n_frobenius.double_frobenius();
            denominator *= n_frobenius;
            n_frobenius = n_frobenius.double_frobenius();
            denominator *= n_frobenius;
            denominator *= *this;

            bb31_t base = pow_r.reciprocal();
            bb31_t g = bb31_t::from_canonical_u32(31);
            bb31_t a = bb31_t::one();
            bb31_t nonresidue = bb31_t::one() - base;

            while (true) {
                bb31_t is_square = nonresidue ^ 1006632960;
                if (is_square != bb31_t::one()) {
                    break;
                }
                a *= g;
                nonresidue = a.square() - base;
            }

            bb31_cipolla_t x = bb31_cipolla_t(a, bb31_t::one());
            x = x.pow(1006632961, nonresidue);

            return denominator * x.real;
        }

        FUN bb31_septic_extension_t universal_hash() const {
            return *this * bb31_septic_extension_t(A_EC_LOGUP) + bb31_septic_extension_t(B_EC_LOGUP);
        }

        FUN bb31_septic_extension_t curve_formula() const {
            bb31_septic_extension_t result = *this * *this * *this;
            result += *this;
            result += *this;
            result.value[5] += bb31_t::from_canonical_u32(26);
            return result;
        }

        FUN bool is_receive() const {
            uint32_t limb = value[6].as_canonical_u32();
            return 1 <= limb && limb <= (bb31_t::MOD - 1) / 2;
        }

        FUN bool is_send() const {
            uint32_t limb = value[6].as_canonical_u32();
            return (bb31_t::MOD + 1) / 2 <= limb && limb <= (bb31_t::MOD - 1);
        }

        FUN bool is_exception() const {
            return value[6] == bb31_t::zero();
        }
};


class bb31_septic_curve_t {
    public:
        bb31_septic_extension_t x;
        bb31_septic_extension_t y;

        static constexpr const bb31_t* dummy_x = constants::dummy_x;
        static constexpr const bb31_t* dummy_y = constants::dummy_y;
        static constexpr const bb31_t* start_x = constants::start_x;
        static constexpr const bb31_t* start_y = constants::start_y;
        
        FUN bb31_septic_curve_t() {
            this->x = bb31_septic_extension_t::zero();
            this->y = bb31_septic_extension_t::zero();
        }

        FUN bb31_septic_curve_t(bb31_septic_extension_t x, bb31_septic_extension_t y) {
            this->x = x;
            this->y = y;
        }

        FUN bb31_septic_curve_t(bb31_t value[14]) {
            for (uintptr_t i = 0 ; i < 7 ; i++) {
                this->x.value[i] = value[i];
            }
            for (uintptr_t i = 0 ; i < 7 ; i++) {
                this->y.value[i] = value[i + 7];
            }
        }

        FUN bb31_septic_curve_t(bb31_t value_x[7], bb31_t value_y[7]) {
            for (uintptr_t i = 0 ; i < 7 ; i++) {
                this->x.value[i] = value_x[i];
                this->y.value[i] = value_y[i];
            }
        }

        static FUN bb31_septic_curve_t dummy_point() {
            bb31_septic_extension_t x;
            bb31_septic_extension_t y;
            for (uintptr_t i = 0 ; i < 7 ; i++) {
                x.value[i] = dummy_x[i];
                y.value[i] = dummy_y[i];
            }
            return bb31_septic_curve_t(x, y);
        }

        static FUN bb31_septic_curve_t start_point() {
            bb31_septic_extension_t x;
            bb31_septic_extension_t y;
            for (uintptr_t i = 0 ; i < 7 ; i++) {
                x.value[i] = start_x[i];
                y.value[i] = start_y[i];
            }
            return bb31_septic_curve_t(x, y);
        }

        FUN bool is_infinity() const {
            return x == bb31_septic_extension_t::zero() && y == bb31_septic_extension_t::zero();
        }

        FUN bb31_septic_curve_t& operator+=(const bb31_septic_curve_t b) {
            if (b.is_infinity()) {
                return *this;
            }
            if (is_infinity()) {
                x = b.x;
                y = b.y;
                return *this;
            }

            bb31_septic_extension_t x_diff = b.x - x;
            if (x_diff == bb31_septic_extension_t::zero()) {
                if (y == b.y) {
                    bb31_septic_extension_t y2 = y + y; 
                    bb31_septic_extension_t x2 = x * x;
                    bb31_septic_extension_t slope = (x2 + x2 + x2 + bb31_t::two()) / y2;
                    bb31_septic_extension_t result_x = slope * slope - x - x;
                    bb31_septic_extension_t result_y = slope * (x - result_x) - y;
                    x = result_x;
                    y = result_y;
                    return *this;
                }
                else {
                    x = bb31_septic_extension_t::zero();
                    y = bb31_septic_extension_t::zero();
                    return *this;
                }
            }
            else {
                bb31_septic_extension_t slope = (b.y - y) / x_diff;
                bb31_septic_extension_t new_x = slope * slope - x - b.x;
                y = slope * (x - new_x) - y;
                x = new_x;
                return *this;
            }
        }

        friend FUN bb31_septic_curve_t operator+(bb31_septic_curve_t a, const bb31_septic_curve_t b) {
            return a += b;
        }

        static FUN bb31_septic_extension_t sum_checker_x(
            const bb31_septic_curve_t& p1,
            const bb31_septic_curve_t& p2,
            const bb31_septic_curve_t& p3
        ) {
            bb31_septic_extension_t x_diff = p2.x - p1.x;
            bb31_septic_extension_t y_diff = p2.y - p1.y;
            return (p1.x + p2.x + p3.x) * x_diff * x_diff - y_diff * y_diff;
        }
};

class bb31_septic_digest_t {
    public:
        bb31_septic_curve_t point;

        FUN bb31_septic_digest_t() {
            this->point = bb31_septic_curve_t();
        }

        FUN bb31_septic_digest_t(bb31_t value[14]) {
            this->point = bb31_septic_curve_t(value);
        }

        FUN bb31_septic_digest_t(bb31_septic_extension_t x, bb31_septic_extension_t y) {
            this->point = bb31_septic_curve_t(x, y);
        }

        FUN bb31_septic_digest_t(bb31_septic_curve_t point) {
            this->point = point;
        }
};

