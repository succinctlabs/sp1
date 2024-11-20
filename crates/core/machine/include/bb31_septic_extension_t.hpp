#pragma once

#include "prelude.hpp"
#include "bb31_t.hpp"

namespace sp1_core_machine_sys {
    struct bb31_septic_extension_t {
        // The value of BabyBear septic extension element, in Montgomery form. 
        bb31_t value[7];

        static constexpr bb31_t frobenius_const[7][7] = {
            {bb31_t(int(1)), bb31_t(int(0)), bb31_t(int(0)), bb31_t(int(0)), bb31_t(int(0)), bb31_t(int(0)), bb31_t(int(0))},
            {bb31_t(int(954599710)), bb31_t(int(1359279693)), bb31_t(int(566669999)), bb31_t(int(1982781815)), bb31_t(int(1735718361)), bb31_t(int(1174868538)), bb31_t(int(1120871770))},
            {bb31_t(int(862825265)), bb31_t(int(597046311)), bb31_t(int(978840770)), bb31_t(int(1790138282)), bb31_t(int(1044777201)), bb31_t(int(835869808)), bb31_t(int(1342179023))},
            {bb31_t(int(596273169)), bb31_t(int(658837454)), bb31_t(int(1515468261)), bb31_t(int(367059247)), bb31_t(int(781278880)), bb31_t(int(1544222616)), bb31_t(int(155490465)) },
            {bb31_t(int(557608863)), bb31_t(int(1173670028)), bb31_t(int(1749546888)), bb31_t(int(1086464137)), bb31_t(int(803900099)), bb31_t(int(1288818584)), bb31_t(int(1184677604))},
            {bb31_t(int(763416381)), bb31_t(int(1252567168)), bb31_t(int(628856225)), bb31_t(int(1771903394)), bb31_t(int(650712211)), bb31_t(int(19417363)), bb31_t(int(57990258))},
            {bb31_t(int(1734711039)), bb31_t(int(1749813853)), bb31_t(int(1227235221)), bb31_t(int(1707730636)), bb31_t(int(424560395)), bb31_t(int(1007029514)), bb31_t(int(498034669))}
        };

        static constexpr bb31_t double_frobenius_const[7][7] = {
            {bb31_t(int(1)), bb31_t(int(0)), bb31_t(int(0)), bb31_t(int(0)), bb31_t(int(0)), bb31_t(int(0)), bb31_t(int(0))},
            {bb31_t(int(1013489358)), bb31_t(int(1619071628)), bb31_t(int(304593143)), bb31_t(int(1949397349)), bb31_t(int(1564307636)), bb31_t(int(327761151)), bb31_t(int(415430835))},
            {bb31_t(int(209824426)), bb31_t(int(1313900768)), bb31_t(int(38410482)), bb31_t(int(256593180)), bb31_t(int(1708830551)), bb31_t(int(1244995038)), bb31_t(int(1555324019))},
            {bb31_t(int(1475628651)), bb31_t(int(777565847)), bb31_t(int(704492386)), bb31_t(int(1218528120)), bb31_t(int(1245363405)), bb31_t(int(475884575)), bb31_t(int(649166061))},
            {bb31_t(int(550038364)), bb31_t(int(948935655)), bb31_t(int(68722023)), bb31_t(int(1251345762)), bb31_t(int(1692456177)), bb31_t(int(1177958698)), bb31_t(int(350232928))},
            {bb31_t(int(882720258)), bb31_t(int(821925756)), bb31_t(int(199955840)), bb31_t(int(812002876)), bb31_t(int(1484951277)), bb31_t(int(1063138035)), bb31_t(int(491712810))},
            {bb31_t(int(738287111)), bb31_t(int(1955364991)), bb31_t(int(552724293)), bb31_t(int(1175775744)), bb31_t(int(341623997)), bb31_t(int(1454022463)), bb31_t(int(408193320))}
        };

        static constexpr bb31_t A_EC_LOGUP[7] = {bb31_t(int(0x31415926)), bb31_t(int(0x53589793)), bb31_t(int(0x23846264)), bb31_t(int(0x33832795)), bb31_t(int(0x02884197)), bb31_t(int(0x16939937)), bb31_t(int(0x51058209))};

        static constexpr bb31_t B_EC_LOGUP[7] = {bb31_t(int(0x74944592)), bb31_t(int(0x30781640)), bb31_t(int(0x62862089)), bb31_t(int(0x9862803)), bb31_t(int(0x48253421)), bb31_t(int(0x17067982)), bb31_t(int(0x14808651))};
        
        __SP1_INLINE__ bb31_septic_extension_t() {} 

        __SP1_INLINE__ bb31_septic_extension_t(bb31_t value) {
            this->value[0] = value;
            for (uintptr_t i = 1 ; i < 7 ; i++) {
                this->value[i] = bb31_t(0);
            }
        }

        __SP1_INLINE__ bb31_septic_extension_t(bb31_t value[7]) {
            for (uintptr_t i = 0 ; i < 7 ; i++) {
                this->value[i] = value[i];
            }
        }

        __SP1_INLINE__ bb31_septic_extension_t(const bb31_t value[7]) {
            for (uintptr_t i = 0 ; i < 7 ; i++) {
                this->value[i] = value[i];
            }
        }

        static bb31_septic_extension_t zero();

        static bb31_septic_extension_t one();

        static bb31_septic_extension_t two();

        static bb31_septic_extension_t from_canonical_u32(uint32_t n);

        bb31_septic_extension_t& operator+=(const bb31_t b);

        friend __SP1_INLINE__ bb31_septic_extension_t operator+(bb31_septic_extension_t a, const bb31_t b) {
            return a += b;
        }

        bb31_septic_extension_t& operator+=(const bb31_septic_extension_t b);

        friend __SP1_INLINE__ bb31_septic_extension_t operator+(bb31_septic_extension_t a, const bb31_septic_extension_t b) {
            return a += b;
        }

        bb31_septic_extension_t& operator-=(const bb31_t b);

        friend __SP1_INLINE__ bb31_septic_extension_t operator-(bb31_septic_extension_t a, const bb31_t b) {
            return a -= b;
        }

        bb31_septic_extension_t& operator-=(const bb31_septic_extension_t b);

        friend __SP1_INLINE__ bb31_septic_extension_t operator-(bb31_septic_extension_t a, const bb31_septic_extension_t b) {
            return a -= b;
        }

        bb31_septic_extension_t& operator*=(const bb31_t b);

        friend __SP1_INLINE__ bb31_septic_extension_t operator*(bb31_septic_extension_t a, const bb31_t b) {
            return a *= b;
        }

        bb31_septic_extension_t& operator*=(const bb31_septic_extension_t b);

        friend __SP1_INLINE__ bb31_septic_extension_t operator*(bb31_septic_extension_t a, const bb31_septic_extension_t b) {
            return a *= b;
        }

        bool operator==(const bb31_septic_extension_t rhs) const;

        bb31_septic_extension_t frobenius() const;

        bb31_septic_extension_t double_frobenius() const;

        bb31_septic_extension_t pow_r_1() const;

        bb31_t pow_r() const;

        /// Inverts a bb31_t septic extension field element.
        bb31_septic_extension_t reciprocal() const;

        /// Divides one bb31_t field element by another.
        friend __SP1_INLINE__ bb31_septic_extension_t operator/(bb31_septic_extension_t a, bb31_septic_extension_t b) {
            return a * b.reciprocal();
        }

        __SP1_INLINE__ bb31_septic_extension_t& operator/=(const bb31_septic_extension_t a) {
            return *this *= a.reciprocal();
        }

        bb31_septic_extension_t sqrt(bb31_t pow_r) const;

        bb31_septic_extension_t universal_hash() const;

        bb31_septic_extension_t curve_formula() const;

        bool is_receive() const;

        bool is_send() const;

        bool is_exception() const;
    };

    struct bb31_septic_curve_t {
        bb31_septic_extension_t x;
        bb31_septic_extension_t y;

        __SP1_INLINE__ bb31_septic_curve_t() {}

        __SP1_INLINE__ bb31_septic_curve_t(bb31_septic_extension_t x, bb31_septic_extension_t y) {
            this->x = x;
            this->y = y;
        }
    };

    struct bb31_septic_curve_complete_t {
        bool is_affine;
        bb31_septic_curve_t point;

        __SP1_INLINE__ bb31_septic_curve_complete_t(bb31_septic_extension_t x, bb31_septic_extension_t y) {
            this->is_affine = true;
            this->point = bb31_septic_curve_t(x, y);
        }

        __SP1_INLINE__ bb31_septic_curve_complete_t() {
            this->is_affine = false;
        }

        bb31_septic_curve_complete_t& operator+=(const bb31_septic_curve_complete_t b);

        friend __SP1_INLINE__ bb31_septic_curve_complete_t operator+(bb31_septic_curve_complete_t a, const bb31_septic_curve_complete_t b) {
            return a += b;
        }
    };

    struct bb31_cipolla_t {
        bb31_t real;
        bb31_t imag;

         __SP1_INLINE__ bb31_cipolla_t(bb31_t real, bb31_t imag) {
            this->real = bb31_t(real);
            this->imag = bb31_t(imag);
        }

        static bb31_cipolla_t one();

        bb31_cipolla_t mul_ext(bb31_cipolla_t other, bb31_t nonresidue);

        bb31_cipolla_t pow(uint32_t exponent, bb31_t nonresidue);
    };
}
