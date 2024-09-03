#include <cstdint>
#include <cstdbool>
// make the function available to Rust

//C++ version of populate_c function

#include <cstdint>

extern "C" {
    uint32_t populate_c(
        uint32_t a_u32,
        uint32_t b_u32,
        uint8_t* carry_out,
        uint8_t* overflow_out
    ) {
        uint32_t expected = a_u32 + b_u32;
        uint8_t a[4], b[4];
        
        for (int i = 0; i < 4; i++) {
            a[i] = static_cast<uint8_t>((a_u32 >> (i * 8)) & 0xFF);
            b[i] = static_cast<uint8_t>((b_u32 >> (i * 8)) & 0xFF);
        }
        
        carry_out[0] = (static_cast<uint32_t>(a[0]) + static_cast<uint32_t>(b[0])) > 255 ? 1 : 0;
        carry_out[1] = (static_cast<uint32_t>(a[1]) + static_cast<uint32_t>(b[1]) + carry_out[0]) > 255 ? 1 : 0;
        carry_out[2] = (static_cast<uint32_t>(a[2]) + static_cast<uint32_t>(b[2]) + carry_out[1]) > 255 ? 1 : 0;
        
        *overflow_out = static_cast<uint8_t>((a[0] + b[0]) - (expected & 0xFF));
        
        return expected;
    }
}

typedef struct {
    uint32_t shard;
    uint8_t channel;
    bool is_add;
    bool is_sub;
    uint32_t operand_1;
    uint32_t operand_2;
    uint8_t carry_out[3];
    uint8_t overflow_out;
    uint32_t result;
} AddSubColsC;

void event_to_row_alt_c(
    uint32_t shard,
    uint8_t channel,
    bool is_add,
    uint32_t a,
    uint32_t b,
    uint32_t c,
    AddSubColsC* cols
) {
    cols->shard = shard;
    cols->channel = channel;
    cols->is_add = is_add;
    cols->is_sub = !is_add;

    uint32_t operand_1 = is_add ? b : a;
    uint32_t operand_2 = c;

    cols->operand_1 = operand_1;
    cols->operand_2 = operand_2;

    // Call populate_c and store the result
    cols->result = populate_c(operand_1, operand_2, cols->carry_out, &cols->overflow_out);

    // Convert operands to uint32_t for populate_c
    uint32_t operand_1_u32 = (uint32_t)operand_1;
    uint32_t operand_2_u32 = (uint32_t)operand_2;

}




