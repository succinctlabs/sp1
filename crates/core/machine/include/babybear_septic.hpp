#pragma once

#include "prelude.hpp"
#include "babybear.hpp"

namespace sp1_core_machine_sys {
    struct BabyBearSeptic {
        // The value of BabyBear septic extension element, in Montgomery form. 
        BabyBear value[7];

        static constexpr BabyBear frobenius_const[7][7] = {
            {BabyBear(int(1)), BabyBear(int(0)), BabyBear(int(0)), BabyBear(int(0)), BabyBear(int(0)), BabyBear(int(0)), BabyBear(int(0))},
            {BabyBear(int(954599710)), BabyBear(int(1359279693)), BabyBear(int(566669999)), BabyBear(int(1982781815)), BabyBear(int(1735718361)), BabyBear(int(1174868538)), BabyBear(int(1120871770))},
            {BabyBear(int(862825265)), BabyBear(int(597046311)), BabyBear(int(978840770)), BabyBear(int(1790138282)), BabyBear(int(1044777201)), BabyBear(int(835869808)), BabyBear(int(1342179023))},
            {BabyBear(int(596273169)), BabyBear(int(658837454)), BabyBear(int(1515468261)), BabyBear(int(367059247)), BabyBear(int(781278880)), BabyBear(int(1544222616)), BabyBear(int(155490465)) },
            {BabyBear(int(557608863)), BabyBear(int(1173670028)), BabyBear(int(1749546888)), BabyBear(int(1086464137)), BabyBear(int(803900099)), BabyBear(int(1288818584)), BabyBear(int(1184677604))},
            {BabyBear(int(763416381)), BabyBear(int(1252567168)), BabyBear(int(628856225)), BabyBear(int(1771903394)), BabyBear(int(650712211)), BabyBear(int(19417363)), BabyBear(int(57990258))},
            {BabyBear(int(1734711039)), BabyBear(int(1749813853)), BabyBear(int(1227235221)), BabyBear(int(1707730636)), BabyBear(int(424560395)), BabyBear(int(1007029514)), BabyBear(int(498034669))}
        };

        static constexpr BabyBear double_frobenius_const[7][7] = {
            {BabyBear(int(1)), BabyBear(int(0)), BabyBear(int(0)), BabyBear(int(0)), BabyBear(int(0)), BabyBear(int(0)), BabyBear(int(0))},
            {BabyBear(int(1013489358)), BabyBear(int(1619071628)), BabyBear(int(304593143)), BabyBear(int(1949397349)), BabyBear(int(1564307636)), BabyBear(int(327761151)), BabyBear(int(415430835))},
            {BabyBear(int(209824426)), BabyBear(int(1313900768)), BabyBear(int(38410482)), BabyBear(int(256593180)), BabyBear(int(1708830551)), BabyBear(int(1244995038)), BabyBear(int(1555324019))},
            {BabyBear(int(1475628651)), BabyBear(int(777565847)), BabyBear(int(704492386)), BabyBear(int(1218528120)), BabyBear(int(1245363405)), BabyBear(int(475884575)), BabyBear(int(649166061))},
            {BabyBear(int(550038364)), BabyBear(int(948935655)), BabyBear(int(68722023)), BabyBear(int(1251345762)), BabyBear(int(1692456177)), BabyBear(int(1177958698)), BabyBear(int(350232928))},
            {BabyBear(int(882720258)), BabyBear(int(821925756)), BabyBear(int(199955840)), BabyBear(int(812002876)), BabyBear(int(1484951277)), BabyBear(int(1063138035)), BabyBear(int(491712810))},
            {BabyBear(int(738287111)), BabyBear(int(1955364991)), BabyBear(int(552724293)), BabyBear(int(1175775744)), BabyBear(int(341623997)), BabyBear(int(1454022463)), BabyBear(int(408193320))}
        };

        static constexpr BabyBear A_EC_LOGUP[7] = {BabyBear(int(0x31415926)), BabyBear(int(0x53589793)), BabyBear(int(0x23846264)), BabyBear(int(0x33832795)), BabyBear(int(0x02884197)), BabyBear(int(0x16939937)), BabyBear(int(0x51058209))};

        static constexpr BabyBear B_EC_LOGUP[7] = {BabyBear(int(0x74944592)), BabyBear(int(0x30781640)), BabyBear(int(0x62862089)), BabyBear(int(0x9862803)), BabyBear(int(0x48253421)), BabyBear(int(0x17067982)), BabyBear(int(0x14808651))};
        
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

        __SP1_INLINE__ BabyBearSeptic(const BabyBear value[7]) {
            for (uintptr_t i = 0 ; i < 7 ; i++) {
                this->value[i] = value[i];
            }
        }

        __SP1_INLINE__ BabyBearSeptic(SepticExtension<BabyBearP3> value) {
            for (uintptr_t i = 0 ; i < 7 ; i++) {
                this->value[i] = BabyBear(value._0[i]);
            }
        }

        static BabyBearSeptic zero();

        static BabyBearSeptic one();

        static BabyBearSeptic two();

        static BabyBearSeptic from_canonical_u32(uint32_t n);

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

        bool operator==(const BabyBearSeptic rhs) const;

        BabyBearSeptic frobenius() const;

        BabyBearSeptic double_frobenius() const;

        BabyBearSeptic pow_r_1() const;

        BabyBear pow_r() const;

        /// Inverts a BabyBear septic extension field element.
        BabyBearSeptic reciprocal() const;

        /// Divides one BabyBear field element by another.
        friend __SP1_INLINE__ BabyBearSeptic operator/(BabyBearSeptic a, BabyBearSeptic b) {
            return a * b.reciprocal();
        }

        __SP1_INLINE__ BabyBearSeptic& operator/=(const BabyBearSeptic a) {
            return *this *= a.reciprocal();
        }

        BabyBearSeptic sqrt(BabyBear pow_r) const;

        BabyBearSeptic universal_hash() const;

        BabyBearSeptic curve_formula() const;

        bool is_receive() const;

        bool is_send() const;

        bool is_exception() const;
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

        static BabyBearCipolla one();

        BabyBearCipolla mul_ext(BabyBearCipolla other, BabyBear nonresidue);

        BabyBearCipolla pow(uint32_t exponent, BabyBear nonresidue);
    };
}
