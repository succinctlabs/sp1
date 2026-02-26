#pragma once

#include "fields/kb31_t.cuh"
// #include <cstdio>

#ifdef __CUDA_ARCH__
#define FUN __host__ __device__
#endif
#ifndef __CUDA_ARCH__
#define FUN inline
#endif

class bb31_cipolla_t {
  public:
    kb31_t real;
    kb31_t imag;

    FUN bb31_cipolla_t(kb31_t real, kb31_t imag) {
        this->real = kb31_t(real);
        this->imag = kb31_t(imag);
    }

    FUN static bb31_cipolla_t one() { return bb31_cipolla_t(kb31_t::one(), kb31_t::zero()); }

    FUN bb31_cipolla_t mul_ext(bb31_cipolla_t other, kb31_t nonresidue) {
        kb31_t new_real = real * other.real + nonresidue * imag * other.imag;
        kb31_t new_imag = real * other.imag + imag * other.real;
        return bb31_cipolla_t(new_real, new_imag);
    }

    FUN bb31_cipolla_t pow(uint32_t exponent, kb31_t nonresidue) {
        bb31_cipolla_t result = bb31_cipolla_t::one();
        bb31_cipolla_t base = *this;

        while (exponent) {
            if (exponent & 1) {
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
__constant__ constexpr const kb31_t frobenius_const[49] = {
    kb31_t(int(1)),          kb31_t(int(0)),          kb31_t(int(0)),
    kb31_t(int(0)),          kb31_t(int(0)),          kb31_t(int(0)),
    kb31_t(int(0)),          kb31_t(int(1272123317)), kb31_t(int(1950759909)),
    kb31_t(int(1879852731)), kb31_t(int(746569225)),  kb31_t(int(180350946)),
    kb31_t(int(1600835585)), kb31_t(int(333893434)),  kb31_t(int(129050189)),
    kb31_t(int(1749509219)), kb31_t(int(983995729)),  kb31_t(int(711096547)),
    kb31_t(int(1505254548)), kb31_t(int(639452798)),  kb31_t(int(68186395)),
    kb31_t(int(1911662442)), kb31_t(int(1095215454)), kb31_t(int(1794102427)),
    kb31_t(int(1173566779)), kb31_t(int(140526665)),  kb31_t(int(110899104)),
    kb31_t(int(1387282150)), kb31_t(int(1366416596)), kb31_t(int(1212861)),
    kb31_t(int(2104391040)), kb31_t(int(1447859676)), kb31_t(int(308944373)),
    kb31_t(int(106444152)),  kb31_t(int(1362577042)), kb31_t(int(1411781189)),
    kb31_t(int(1580508159)), kb31_t(int(1332301780)), kb31_t(int(1528790701)),
    kb31_t(int(380217034)),  kb31_t(int(1752756730)), kb31_t(int(989817517)),
    kb31_t(int(37669840)),   kb31_t(int(439102875)),  kb31_t(int(410223214)),
    kb31_t(int(964813232)),  kb31_t(int(1250258104)), kb31_t(int(877333757)),
    kb31_t(int(222095778)),
};

__constant__ constexpr const kb31_t double_frobenius_const[49] = {

    kb31_t(int(1)),          kb31_t(int(0)),          kb31_t(int(0)),
    kb31_t(int(0)),          kb31_t(int(0)),          kb31_t(int(0)),
    kb31_t(int(0)),          kb31_t(int(1330073564)), kb31_t(int(1724372201)),
    kb31_t(int(942213154)),  kb31_t(int(258987814)),  kb31_t(int(1836986639)),
    kb31_t(int(566030553)),  kb31_t(int(2086945921)), kb31_t(int(473977877)),
    kb31_t(int(99096011)),   kb31_t(int(1919717963)), kb31_t(int(733784355)),
    kb31_t(int(1167998744)), kb31_t(int(19619652)),   kb31_t(int(1354518805)),
    kb31_t(int(1040563478)), kb31_t(int(1866766699)), kb31_t(int(1875293643)),
    kb31_t(int(846885082)),  kb31_t(int(1921678452)), kb31_t(int(2127718474)),
    kb31_t(int(1489297699)), kb31_t(int(1350284585)), kb31_t(int(1583164394)),
    kb31_t(int(512913106)),  kb31_t(int(1818487640)), kb31_t(int(2116891899)),
    kb31_t(int(318922921)),  kb31_t(int(1013732863)), kb31_t(int(887772098)),
    kb31_t(int(1971095075)), kb31_t(int(843183752)),  kb31_t(int(711838602)),
    kb31_t(int(1717807390)), kb31_t(int(521017530)),  kb31_t(int(1548716569)),
    kb31_t(int(372606377)),  kb31_t(int(357514301)),  kb31_t(int(335089633)),
    kb31_t(int(330400379)),  kb31_t(int(1545190367)), kb31_t(int(1813349020)),
    kb31_t(int(1393941056)),

};


__constant__ constexpr const kb31_t A_EC_LOGUP[7] = {
    kb31_t(int(0x31415926)),
    kb31_t(int(0x53589793)),
    kb31_t(int(0x23846264)),
    kb31_t(int(0x33832795)),
    kb31_t(int(0x02884197)),
    kb31_t(int(0x16939937)),
    kb31_t(int(0x51058209))};

__constant__ constexpr const kb31_t B_EC_LOGUP[7] = {
    kb31_t(int(0x74944592)),
    kb31_t(int(0x30781640)),
    kb31_t(int(0x62862089)),
    kb31_t(int(0x9862803)),
    kb31_t(int(0x48253421)),
    kb31_t(int(0x17067982)),
    kb31_t(int(0x14808651))};

__constant__ constexpr const kb31_t dummy_x[7] = {
    kb31_t(int(0x2718281U + (1 << 24))),
    kb31_t(int(0x8284590U)),
    kb31_t(int(0x4523536U)),
    kb31_t(int(0x0287471U)),
    kb31_t(int(0x3526624U)),
    kb31_t(int(0x9775724U)),
    kb31_t(int(0x7093699U))};
__constant__ constexpr const kb31_t dummy_y[7] = {
    kb31_t(int(1250555984U)),
    kb31_t(int(1592495468U)),
    kb31_t(int(656721246U)),
    kb31_t(int(420301347U)),
    kb31_t(int(2125819749U)),
    kb31_t(int(819876460U)),
    kb31_t(int(17687681U))};

__constant__ constexpr kb31_t start_x[7] = {
    kb31_t(int(0x1414213U)),
    kb31_t(int(0x5623730U)),
    kb31_t(int(0x9504880U)),
    kb31_t(int(0x1688724U)),
    kb31_t(int(0x2096980U)),
    kb31_t(int(0x7856967U)),
    kb31_t(int(0x1875376U))};
__constant__ constexpr kb31_t start_y[7] = {
    kb31_t(int(2020310104U)),
    kb31_t(int(1513506566U)),
    kb31_t(int(1843922297U)),
    kb31_t(int(2003644209U)),
    kb31_t(int(805967281U)),
    kb31_t(int(1882435203U)),
    kb31_t(int(1623804682U))};

#endif

// TODO: C++ constants.
#ifndef __CUDA_ARCH__
static constexpr const kb31_t frobenius_const[49] = {
    kb31_t(int(1)),          kb31_t(int(0)),          kb31_t(int(0)),
    kb31_t(int(0)),          kb31_t(int(0)),          kb31_t(int(0)),
    kb31_t(int(0)),          kb31_t(int(1272123317)), kb31_t(int(1950759909)),
    kb31_t(int(1879852731)), kb31_t(int(746569225)),  kb31_t(int(180350946)),
    kb31_t(int(1600835585)), kb31_t(int(333893434)),  kb31_t(int(129050189)),
    kb31_t(int(1749509219)), kb31_t(int(983995729)),  kb31_t(int(711096547)),
    kb31_t(int(1505254548)), kb31_t(int(639452798)),  kb31_t(int(68186395)),
    kb31_t(int(1911662442)), kb31_t(int(1095215454)), kb31_t(int(1794102427)),
    kb31_t(int(1173566779)), kb31_t(int(140526665)),  kb31_t(int(110899104)),
    kb31_t(int(1387282150)), kb31_t(int(1366416596)), kb31_t(int(1212861)),
    kb31_t(int(2104391040)), kb31_t(int(1447859676)), kb31_t(int(308944373)),
    kb31_t(int(106444152)),  kb31_t(int(1362577042)), kb31_t(int(1411781189)),
    kb31_t(int(1580508159)), kb31_t(int(1332301780)), kb31_t(int(1528790701)),
    kb31_t(int(380217034)),  kb31_t(int(1752756730)), kb31_t(int(989817517)),
    kb31_t(int(37669840)),   kb31_t(int(439102875)),  kb31_t(int(410223214)),
    kb31_t(int(964813232)),  kb31_t(int(1250258104)), kb31_t(int(877333757)),
    kb31_t(int(222095778)),
};

static constexpr const kb31_t double_frobenius_const[49] = {
    kb31_t(int(1)),          kb31_t(int(0)),          kb31_t(int(0)),
    kb31_t(int(0)),          kb31_t(int(0)),          kb31_t(int(0)),
    kb31_t(int(0)),          kb31_t(int(1330073564)), kb31_t(int(1724372201)),
    kb31_t(int(942213154)),  kb31_t(int(258987814)),  kb31_t(int(1836986639)),
    kb31_t(int(566030553)),  kb31_t(int(2086945921)), kb31_t(int(473977877)),
    kb31_t(int(99096011)),   kb31_t(int(1919717963)), kb31_t(int(733784355)),
    kb31_t(int(1167998744)), kb31_t(int(19619652)),   kb31_t(int(1354518805)),
    kb31_t(int(1040563478)), kb31_t(int(1866766699)), kb31_t(int(1875293643)),
    kb31_t(int(846885082)),  kb31_t(int(1921678452)), kb31_t(int(2127718474)),
    kb31_t(int(1489297699)), kb31_t(int(1350284585)), kb31_t(int(1583164394)),
    kb31_t(int(512913106)),  kb31_t(int(1818487640)), kb31_t(int(2116891899)),
    kb31_t(int(318922921)),  kb31_t(int(1013732863)), kb31_t(int(887772098)),
    kb31_t(int(1971095075)), kb31_t(int(843183752)),  kb31_t(int(711838602)),
    kb31_t(int(1717807390)), kb31_t(int(521017530)),  kb31_t(int(1548716569)),
    kb31_t(int(372606377)),  kb31_t(int(357514301)),  kb31_t(int(335089633)),
    kb31_t(int(330400379)),  kb31_t(int(1545190367)), kb31_t(int(1813349020)),
    kb31_t(int(1393941056)),
};

static constexpr const kb31_t A_EC_LOGUP[7] = {
    kb31_t(int(0x31415926)),
    kb31_t(int(0x53589793)),
    kb31_t(int(0x23846264)),
    kb31_t(int(0x33832795)),
    kb31_t(int(0x02884197)),
    kb31_t(int(0x16939937)),
    kb31_t(int(0x51058209))};
static constexpr const kb31_t B_EC_LOGUP[7] = {
    kb31_t(int(0x74944592)),
    kb31_t(int(0x30781640)),
    kb31_t(int(0x62862089)),
    kb31_t(int(0x9862803)),
    kb31_t(int(0x48253421)),
    kb31_t(int(0x17067982)),
    kb31_t(int(0x14808651))};

static constexpr kb31_t dummy_x[7] = {
    kb31_t(int(0x2718281U + (1 << 24))),
    kb31_t(int(0x8284590)),
    kb31_t(int(0x4523536)),
    kb31_t(int(0x0287471)),
    kb31_t(int(0x3526624)),
    kb31_t(int(0x9775724)),
    kb31_t(int(0x7093699))};
static constexpr kb31_t dummy_y[7] = {
    kb31_t(int(1250555984)),
    kb31_t(int(1592495468)),
    kb31_t(int(656721246)),
    kb31_t(int(420301347)),
    kb31_t(int(2125819749)),
    kb31_t(int(819876460)),
    kb31_t(int(17687681))};

static constexpr kb31_t start_x[7] = {
    kb31_t(int(0x1414213)),
    kb31_t(int(0x5623730)),
    kb31_t(int(0x9504880)),
    kb31_t(int(0x1688724)),
    kb31_t(int(0x2096980)),
    kb31_t(int(0x7856967)),
    kb31_t(int(0x1875376))};
static constexpr kb31_t start_y[7] = {
    kb31_t(int(2020310104)),
    kb31_t(int(1513506566)),
    kb31_t(int(1843922297)),
    kb31_t(int(2003644209)),
    kb31_t(int(805967281)),
    kb31_t(int(1882435203)),
    kb31_t(int(1623804682))};

#endif
} // namespace constants

class kb31_septic_extension_t {
    // The value of KoalaBear septic extension element.
  public:
    kb31_t value[7];
    static constexpr const kb31_t* frobenius_const = constants::frobenius_const;
    static constexpr const kb31_t* double_frobenius_const = constants::double_frobenius_const;
    static constexpr const kb31_t* A_EC_LOGUP = constants::A_EC_LOGUP;
    static constexpr const kb31_t* B_EC_LOGUP = constants::B_EC_LOGUP;

    FUN kb31_septic_extension_t() {
        for (uintptr_t i = 0; i < 7; i++) {
            this->value[i] = kb31_t(0);
        }
    }

    FUN kb31_septic_extension_t(kb31_t value) {
        this->value[0] = value;
        for (uintptr_t i = 1; i < 7; i++) {
            this->value[i] = kb31_t(0);
        }
    }

    FUN kb31_septic_extension_t(kb31_t value[7]) {
        for (uintptr_t i = 0; i < 7; i++) {
            this->value[i] = value[i];
        }
    }

    FUN kb31_septic_extension_t(const kb31_t value[7]) {
        for (uintptr_t i = 0; i < 7; i++) {
            this->value[i] = value[i];
        }
    }

    static FUN kb31_septic_extension_t zero() { return kb31_septic_extension_t(); }

    static FUN kb31_septic_extension_t one() { return kb31_septic_extension_t(kb31_t::one()); }

    static FUN kb31_septic_extension_t two() { return kb31_septic_extension_t(kb31_t::two()); }

    static FUN kb31_septic_extension_t from_canonical_u32(uint32_t n) {
        return kb31_septic_extension_t(kb31_t::from_canonical_u32(n));
    }

    FUN kb31_septic_extension_t& operator+=(const kb31_t b) {
        value[0] += b;
        return *this;
    }

    friend FUN kb31_septic_extension_t operator+(kb31_septic_extension_t a, const kb31_t b) {
        return a += b;
    }

    FUN kb31_septic_extension_t& operator+=(const kb31_septic_extension_t b) {
        for (uintptr_t i = 0; i < 7; i++) {
            value[i] += b.value[i];
        }
        return *this;
    }

    friend FUN kb31_septic_extension_t
    operator+(kb31_septic_extension_t a, const kb31_septic_extension_t b) {
        return a += b;
    }

    FUN kb31_septic_extension_t& operator-=(const kb31_t b) {
        value[0] -= b;
        return *this;
    }

    friend FUN kb31_septic_extension_t operator-(kb31_septic_extension_t a, const kb31_t b) {
        return a -= b;
    }

    FUN kb31_septic_extension_t& operator-=(const kb31_septic_extension_t b) {
        for (uintptr_t i = 0; i < 7; i++) {
            value[i] -= b.value[i];
        }
        return *this;
    }

    friend FUN kb31_septic_extension_t
    operator-(kb31_septic_extension_t a, const kb31_septic_extension_t b) {
        return a -= b;
    }

    FUN kb31_septic_extension_t& operator*=(const kb31_t b) {
        for (uintptr_t i = 0; i < 7; i++) {
            value[i] *= b;
        }
        return *this;
    }

    friend FUN kb31_septic_extension_t operator*(kb31_septic_extension_t a, const kb31_t b) {
        return a *= b;
    }

    FUN kb31_septic_extension_t& operator*=(const kb31_septic_extension_t b) {
        {
            kb31_t res[13] = {};
            for (uintptr_t i = 0; i < 13; i++) {
                res[i] = kb31_t::zero();
            }
            for (uintptr_t i = 0; i < 7; i++) {
                for (uintptr_t j = 0; j < 7; j++) {
                    res[i + j] += value[i] * b.value[j];
                }
            }
            for (uintptr_t i = 7; i < 13; i++) {
                res[i - 7] += res[i] * kb31_t::from_canonical_u32(5);
                res[i - 6] += res[i] * kb31_t::from_canonical_u32(3);
            }
            for (uintptr_t i = 0; i < 7; i++) {
                value[i] = res[i];
            }
        }
        return *this;
    }

    friend FUN kb31_septic_extension_t
    operator*(kb31_septic_extension_t a, const kb31_septic_extension_t b) {
        return a *= b;
    }

    FUN bool operator==(const kb31_septic_extension_t rhs) const {
        for (uintptr_t i = 0; i < 7; i++) {
            if (value[i] != rhs.value[i]) {
                return false;
            }
        }
        return true;
    }

    FUN kb31_septic_extension_t frobenius() const {
        kb31_t res[7] = {};
        res[0] = value[0];
        for (uintptr_t i = 1; i < 7; i++) {
            res[i] = kb31_t::zero();
        }
        for (uintptr_t i = 1; i < 7; i++) {
            for (uintptr_t j = 0; j < 7; j++) {
                res[j] += value[i] * frobenius_const[7 * i + j];
            }
        }
        return kb31_septic_extension_t(res);
    }

    FUN kb31_septic_extension_t double_frobenius() const {
        kb31_t res[7] = {};
        res[0] = value[0];
        for (uintptr_t i = 1; i < 7; i++) {
            res[i] = kb31_t::zero();
        }
        for (uintptr_t i = 1; i < 7; i++) {
            for (uintptr_t j = 0; j < 7; j++) {
                res[j] += value[i] * double_frobenius_const[7 * i + j];
            }
        }
        return kb31_septic_extension_t(res);
    }

    FUN kb31_septic_extension_t pow_r_1() const {
        kb31_septic_extension_t base = frobenius();
        base *= double_frobenius();
        kb31_septic_extension_t base_p2 = base.double_frobenius();
        kb31_septic_extension_t base_p4 = base_p2.double_frobenius();
        return base * base_p2 * base_p4;
    }

    FUN kb31_t pow_r() const {
        kb31_septic_extension_t pow_r1 = pow_r_1();
        kb31_septic_extension_t pow_r = pow_r1 * *this;
        return pow_r.value[0];
    }

    FUN kb31_septic_extension_t reciprocal() const {
        kb31_septic_extension_t pow_r1 = pow_r_1();
        kb31_septic_extension_t pow_r = pow_r1 * *this;
        return pow_r1 * pow_r.value[0].reciprocal();
    }

    friend FUN kb31_septic_extension_t
    operator/(kb31_septic_extension_t a, kb31_septic_extension_t b) {
        return a * b.reciprocal();
    }

    FUN kb31_septic_extension_t& operator/=(const kb31_septic_extension_t a) {
        return *this *= a.reciprocal();
    }

    FUN kb31_septic_extension_t sqrt(kb31_t pow_r) const {
        if (*this == kb31_septic_extension_t::zero()) {
            return *this;
        }

        kb31_septic_extension_t n_iter = *this;
        kb31_septic_extension_t n_power = *this;
        for (uintptr_t i = 1; i < 30; i++) {
            n_iter *= n_iter;
            if (i >= 23) {
                n_power *= n_iter;
            }
        }

        kb31_septic_extension_t n_frobenius = n_power.frobenius();
        kb31_septic_extension_t denominator = n_frobenius;

        n_frobenius = n_frobenius.double_frobenius();
        denominator *= n_frobenius;
        n_frobenius = n_frobenius.double_frobenius();
        denominator *= n_frobenius;
        denominator *= *this;

        kb31_t base = pow_r.reciprocal();
        kb31_t g = kb31_t::from_canonical_u32(3);
        kb31_t a = kb31_t::one();
        kb31_t nonresidue = kb31_t::one() - base;

        while (true) {
            // The hard-coded constant is (p-1)/2.
            kb31_t is_square = nonresidue ^ ((kb31_t::MOD - 1) >> 1);
            if (is_square != kb31_t::one()) {
                break;
            }
            a *= g;
            nonresidue = a.square() - base;
        }

        bb31_cipolla_t x = bb31_cipolla_t(a, kb31_t::one());
        x = x.pow((kb31_t::MOD + 1) >> 1, nonresidue);

        kb31_septic_extension_t result = denominator * x.real;

        // assert(result*result == *this);

        return result;
    }

    FUN kb31_septic_extension_t universal_hash() const {
        return *this * kb31_septic_extension_t(A_EC_LOGUP) + kb31_septic_extension_t(B_EC_LOGUP);
    }

    FUN kb31_septic_extension_t curve_formula() const {
        kb31_septic_extension_t result = *this * *this * *this;
        result += *this * kb31_t::from_canonical_u32(45);
        result.value[3] += kb31_t::from_canonical_u32(41);
        return result;
    }

    FUN bool is_receive() const {
        uint32_t limb = value[6].as_canonical_u32();
        return 1 <= limb && limb <= 63 * (1 << 24);
    }

    FUN bool is_send() const {
        uint32_t limb = value[6].as_canonical_u32();
        return kb31_t::MOD - 63 * (1 << 24) <= limb && limb <= (kb31_t::MOD - 1);
    }

    FUN bool is_exception() const { 
        uint32_t limb = value[6].as_canonical_u32();
        return limb == 0 || (63 * (1 << 24) < limb && limb < kb31_t::MOD - 63 * (1 << 24)); 
    }
};

class bb31_septic_curve_t {
  public:
    kb31_septic_extension_t x;
    kb31_septic_extension_t y;

    static constexpr const kb31_t* dummy_x = constants::dummy_x;
    static constexpr const kb31_t* dummy_y = constants::dummy_y;
    static constexpr const kb31_t* start_x = constants::start_x;
    static constexpr const kb31_t* start_y = constants::start_y;

    FUN bb31_septic_curve_t() {
        this->x = kb31_septic_extension_t::zero();
        this->y = kb31_septic_extension_t::zero();
    }

    FUN bb31_septic_curve_t(kb31_septic_extension_t x, kb31_septic_extension_t y) {
        this->x = x;
        this->y = y;
    }

    FUN bb31_septic_curve_t(kb31_t value[14]) {
        for (uintptr_t i = 0; i < 7; i++) {
            this->x.value[i] = value[i];
        }
        for (uintptr_t i = 0; i < 7; i++) {
            this->y.value[i] = value[i + 7];
        }
    }

    FUN bb31_septic_curve_t(kb31_t value_x[7], kb31_t value_y[7]) {
        for (uintptr_t i = 0; i < 7; i++) {
            this->x.value[i] = value_x[i];
            this->y.value[i] = value_y[i];
        }
    }

    static FUN bb31_septic_curve_t dummy_point() {
        kb31_septic_extension_t x;
        kb31_septic_extension_t y;
        for (uintptr_t i = 0; i < 7; i++) {
            x.value[i] = dummy_x[i];
            y.value[i] = dummy_y[i];
        }
        return bb31_septic_curve_t(x, y);
    }

    static FUN bb31_septic_curve_t start_point() {
        kb31_septic_extension_t x;
        kb31_septic_extension_t y;
        for (uintptr_t i = 0; i < 7; i++) {
            x.value[i] = start_x[i];
            y.value[i] = start_y[i];
        }
        return bb31_septic_curve_t(x, y);
    }

    FUN bool is_infinity() const {
        return x == kb31_septic_extension_t::zero() && y == kb31_septic_extension_t::zero();
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

        kb31_septic_extension_t x_diff = b.x - x;
        if (x_diff == kb31_septic_extension_t::zero()) {
            if (y == b.y) {
                kb31_septic_extension_t y2 = y + y;
                kb31_septic_extension_t x2 = x * x;
                kb31_septic_extension_t slope =
                    (x2 + x2 + x2 + kb31_t::from_canonical_u16(45)) / y2;
                kb31_septic_extension_t result_x = slope * slope - x - x;
                kb31_septic_extension_t result_y = slope * (x - result_x) - y;
                x = result_x;
                y = result_y;
                return *this;
            } else {
                x = kb31_septic_extension_t::zero();
                y = kb31_septic_extension_t::zero();
                return *this;
            }
        } else {
            kb31_septic_extension_t slope = (b.y - y) / x_diff;
            kb31_septic_extension_t new_x = slope * slope - x - b.x;
            y = slope * (x - new_x) - y;
            x = new_x;
            return *this;
        }
    }

    friend FUN bb31_septic_curve_t operator+(bb31_septic_curve_t a, const bb31_septic_curve_t b) {
        return a += b;
    }

    static FUN kb31_septic_extension_t sum_checker_x(
        const bb31_septic_curve_t& p1,
        const bb31_septic_curve_t& p2,
        const bb31_septic_curve_t& p3) {
        kb31_septic_extension_t x_diff = p2.x - p1.x;
        kb31_septic_extension_t y_diff = p2.y - p1.y;
        return (p1.x + p2.x + p3.x) * x_diff * x_diff - y_diff * y_diff;
    }
};

class bb31_septic_digest_t {
  public:
    bb31_septic_curve_t point;

    FUN bb31_septic_digest_t() { this->point = bb31_septic_curve_t(); }

    FUN bb31_septic_digest_t(kb31_t value[14]) { this->point = bb31_septic_curve_t(value); }

    FUN bb31_septic_digest_t(kb31_septic_extension_t x, kb31_septic_extension_t y) {
        this->point = bb31_septic_curve_t(x, y);
    }

    FUN bb31_septic_digest_t(bb31_septic_curve_t point) { this->point = point; }
};
