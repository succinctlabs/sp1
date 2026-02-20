#pragma once

#include "fields/kb31_t.cuh"

namespace poseidon2_kb31_16 {

namespace constants {

constexpr const int DIGEST_WIDTH = 8;
constexpr const int RATE = 8;
constexpr const int WIDTH = 16;
constexpr const int ROUNDS_P = 20;
constexpr const int ROUNDS_F = 8;
constexpr const int D = 3;

__constant__ constexpr const kb31_t INTERNAL_ROUND_CONSTANTS[ROUNDS_P] = {
    kb31_t(1423960925), kb31_t(2101391318), kb31_t(1915532054), kb31_t(275400051),
    kb31_t(1168624859), kb31_t(1141248885), kb31_t(356546469),  kb31_t(1165250474),
    kb31_t(1320543726), kb31_t(932505663),  kb31_t(1204226364), kb31_t(1452576828),
    kb31_t(1774936729), kb31_t(926808140),  kb31_t(1184948056), kb31_t(1186493834),
    kb31_t(843181003),  kb31_t(185193011),  kb31_t(452207447),  kb31_t(510054082)};

__constant__ constexpr const kb31_t EXTERNAL_ROUND_CONSTANTS[ROUNDS_F * WIDTH] = {
    kb31_t(2128964168), kb31_t(288780357),  kb31_t(316938561),  kb31_t(2126233899),
    kb31_t(426817493),  kb31_t(1714118888), kb31_t(1045008582), kb31_t(1738510837),
    kb31_t(889721787),  kb31_t(8866516),    kb31_t(681576474),  kb31_t(419059826),
    kb31_t(1596305521), kb31_t(1583176088), kb31_t(1584387047), kb31_t(1529751136),
    kb31_t(1863858111), kb31_t(1072044075), kb31_t(517831365),  kb31_t(1464274176),
    kb31_t(1138001621), kb31_t(428001039),  kb31_t(245709561),  kb31_t(1641420379),
    kb31_t(1365482496), kb31_t(770454828),  kb31_t(693167409),  kb31_t(757905735),
    kb31_t(136670447),  kb31_t(436275702),  kb31_t(525466355),  kb31_t(1559174242),
    kb31_t(1030087950), kb31_t(869864998),  kb31_t(322787870),  kb31_t(267688717),
    kb31_t(948964561),  kb31_t(740478015),  kb31_t(679816114),  kb31_t(113662466),
    kb31_t(2066544572), kb31_t(1744924186), kb31_t(367094720),  kb31_t(1380455578),
    kb31_t(1842483872), kb31_t(416711434),  kb31_t(1342291586), kb31_t(1692058446),
    kb31_t(1493348999), kb31_t(1113949088), kb31_t(210900530),  kb31_t(1071655077),
    kb31_t(610242121),  kb31_t(1136339326), kb31_t(2020858841), kb31_t(1019840479),
    kb31_t(678147278),  kb31_t(1678413261), kb31_t(1361743414), kb31_t(61132629),
    kb31_t(1209546658), kb31_t(64412292),   kb31_t(1936878279), kb31_t(1980661727),
    kb31_t(1139268644), kb31_t(630873441),  kb31_t(669538875),  kb31_t(462500858),
    kb31_t(876500520),  kb31_t(1214043330), kb31_t(383937013),  kb31_t(375087302),
    kb31_t(636912601),  kb31_t(307200505),  kb31_t(390279673),  kb31_t(1999916485),
    kb31_t(1518476730), kb31_t(1606686591), kb31_t(1410677749), kb31_t(1581191572),
    kb31_t(1004269969), kb31_t(143426723),  kb31_t(1747283099), kb31_t(1016118214),
    kb31_t(1749423722), kb31_t(66331533),   kb31_t(1177761275), kb31_t(1581069649),
    kb31_t(1851371119), kb31_t(852520128),  kb31_t(1499632627), kb31_t(1820847538),
    kb31_t(150757557),  kb31_t(884787840),  kb31_t(619710451),  kb31_t(1651711087),
    kb31_t(505263814),  kb31_t(212076987),  kb31_t(1482432120), kb31_t(1458130652),
    kb31_t(382871348),  kb31_t(417404007),  kb31_t(2066495280), kb31_t(1996518884),
    kb31_t(902934924),  kb31_t(582892981),  kb31_t(1337064375), kb31_t(1199354861),
    kb31_t(2102596038), kb31_t(1533193853), kb31_t(1436311464), kb31_t(2012303432),
    kb31_t(839997195),  kb31_t(1225781098), kb31_t(2011967775), kb31_t(575084315),
    kb31_t(1309329169), kb31_t(786393545),  kb31_t(995788880),  kb31_t(1702925345),
    kb31_t(1444525226), kb31_t(908073383),  kb31_t(1811535085), kb31_t(1531002367),
    kb31_t(1635653662), kb31_t(1585100155), kb31_t(867006515),  kb31_t(879151050)};
#if 1
__constant__ constexpr const kb31_t MAT_INTERNAL_DIAG_M1[WIDTH] = {
    kb31_t(16646145),
    kb31_t(1057030144),
    kb31_t(2114060288),
    kb31_t(2097414143),
    kb31_t(2064121853),
    kb31_t(1997537273),
    kb31_t(1864368113),
    kb31_t(1598029793),
    kb31_t(1065353153),
    kb31_t(2130706306),
    kb31_t(2130706179),
    kb31_t(2130705925),
    kb31_t(2130705417),
    kb31_t(2130704401),
    kb31_t(2130702369),
    kb31_t(2130690177)};
#else
__constant__ constexpr const kb31_t MAT_INTERNAL_DIAG_M1[WIDTH] = {
    kb31_t(2130706431),
    kb31_t(1),
    kb31_t(2),
    kb31_t(4),
    kb31_t(8),
    kb31_t(16),
    kb31_t(32),
    kb31_t(64),
    kb31_t(128),
    kb31_t(256),
    kb31_t(512),
    kb31_t(1024),
    kb31_t(2048),
    kb31_t(4096),
    kb31_t(8192),
    kb31_t(32768)};
#endif
__constant__ constexpr const kb31_t MONTY_INVERSE = kb31_t(1057030144);

} // namespace constants

class KoalaBear {
  public:
    using F_t = kb31_t;
    using pF_t = const F_t;

    static constexpr const int DIGEST_WIDTH = constants::DIGEST_WIDTH;
    static constexpr const int RATE = constants::RATE;
    static constexpr const int WIDTH = constants::WIDTH;
    static constexpr const int ROUNDS_F = constants::ROUNDS_F;
    static constexpr const int ROUNDS_P = constants::ROUNDS_P;
    static constexpr const int D = constants::D;

    static constexpr pF_t* INTERNAL_ROUND_CONSTANTS = constants::INTERNAL_ROUND_CONSTANTS;
    static constexpr pF_t* EXTERNAL_ROUND_CONSTANTS = constants::EXTERNAL_ROUND_CONSTANTS;
    static constexpr pF_t* MAT_INTERNAL_DIAG_M1 = constants::MAT_INTERNAL_DIAG_M1;
    static constexpr pF_t MONTY_INVERSE = constants::MONTY_INVERSE;

    __device__ static void internalLinearLayer(F_t state[WIDTH], pF_t*, F_t) {
        uint64_t sum64 = 0;
        for (int i = 0; i < WIDTH; i++) {
            sum64 += static_cast<uint64_t>(state[i].val);
        }
        const F_t sum = kb31_t(static_cast<uint32_t>(sum64 % kb31_t::MOD)) * MONTY_INVERSE;
        for (int i = 0; i < WIDTH; i++) {
            state[i] *= MAT_INTERNAL_DIAG_M1[i];
            state[i] += sum;
        }
    }

    __device__ static void externalLinearLayer(F_t state[WIDTH]) {
        for (int i = 0; i < WIDTH; i += 4) {
            mdsLightPermutation4x4(state + i);
        }
        F_t sums[4] = {state[0], state[1], state[2], state[3]};
        for (int i = 4; i < WIDTH; i += 4) {
            sums[0] += state[i];
            sums[1] += state[i + 1];
            sums[2] += state[i + 2];
            sums[3] += state[i + 3];
        }
        for (int i = 0; i < WIDTH; i++) {
            state[i] += sums[i & 3];
        }
    }

    __device__ static void mdsLightPermutation4x4(F_t state[4]) {
        F_t t01 = state[0] + state[1];
        F_t t23 = state[2] + state[3];
        F_t t0123 = t01 + t23;
        F_t t01123 = t0123 + state[1];
        F_t t01233 = t0123 + state[3];
        state[3] = t01233 + operator<<(state[0], 1);
        state[1] = t01123 + operator<<(state[2], 1);
        state[0] = t01123 + t01;
        state[2] = t01233 + t23;
    }
};

template <typename Hasher_t, typename HasherState_t>
__device__ void absorbRow(
    Hasher_t hasher,
    kb31_t* in,
    int rowIdx,
    size_t width,
    size_t height,
    HasherState_t* state) {
    for (int j = 0; j < width; j++) {
        kb31_t* row = &in[j * height + rowIdx];
        (*state).absorb(hasher, row, 1);
    }
}

} // namespace poseidon2_kb31_16
