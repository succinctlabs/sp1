// Copyright Supranational LLC 2024

// Values in Montgomery form

const fr_t group_gen = fr_t(0x5fffffau);
const fr_t group_gen_inverse = fr_t(0xaaaaaau);

const int S = 24;

const fr_t forward_roots_of_unity[S + 1] = {
        fr_t(0x1fffffeu),
        fr_t(0x7d000003u),
        fr_t(0x7b020407u),
        fr_t(0x60f5ef4du),
        fr_t(0x6d249c01u),
        fr_t(0x788529f3u),
        fr_t(0x7f7373eu),
        fr_t(0x6fe91d3cu),
        fr_t(0x3fd49211u),
        fr_t(0x1e056392u),
        fr_t(0x6d969babu),
        fr_t(0x439600ccu),
        fr_t(0x150276fcu),
        fr_t(0x68cacc36u),
        fr_t(0x42336c40u),
        fr_t(0x19b1972u),
        fr_t(0x34e52f6du),
        fr_t(0x1c2eb437u),
        fr_t(0x7cb65829u),
        fr_t(0x29306faeu),
        fr_t(0x351c7fa7u),
        fr_t(0x6e3e9a00u),
        fr_t(0x47c2bdf7u),
        fr_t(0xc895820u),
        fr_t(0x13c85195u)
};

const fr_t inverse_roots_of_unity[S + 1] = {
    fr_t(0x1fffffeu),
    fr_t(0x7d000003u),
    fr_t(0x3fdfbfau),
    fr_t(0x4bfa6163u),
    fr_t(0x52605cfeu),
    fr_t(0x19b8de8du),
    fr_t(0x29a9eda0u),
    fr_t(0x7c319486u),
    fr_t(0x6be0a64fu),
    fr_t(0x119f6035u),
    fr_t(0x78c55038u),
    fr_t(0x5c627d99u),
    fr_t(0x498aeddeu),
    fr_t(0x27052f97u),
    fr_t(0x7bf75488u),
    fr_t(0x2f8a590cu),
    fr_t(0x1dac17b7u),
    fr_t(0x4678e204u),
    fr_t(0x157bdbf0u),
    fr_t(0x74ca2cd0u),
    fr_t(0x6ee8434u),
    fr_t(0x16c4aa06u),
    fr_t(0x4aee72abu),
    fr_t(0x77640e35u),
    fr_t(0x452f7763u)
};

const fr_t domain_size_inverse[S + 1] = {
    fr_t(0x1fffffeu),
    fr_t(0xffffffu),
    fr_t(0x40000000u),
    fr_t(0x20000000u),
    fr_t(0x10000000u),
    fr_t(0x08000000u),
    fr_t(0x04000000u),
    fr_t(0x02000000u),
    fr_t(0x01000000u),
    fr_t(0x00800000u),
    fr_t(0x00400000u),
    fr_t(0x00200000u),
    fr_t(0x00100000u),
    fr_t(0x00080000u),
    fr_t(0x00040000u),
    fr_t(0x00020000u),
    fr_t(0x00010000u),
    fr_t(0x00008000u),
    fr_t(0x00004000u),
    fr_t(0x00002000u),
    fr_t(0x00001000u),
    fr_t(0x00000800u),
    fr_t(0x00000400u),
    fr_t(0x00000200u),
    fr_t(0x00000100u)
};