#include <cstdint>
#include <cstdbool>
// make the function available to Rust

//C++ version of populate_c function


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

#define WORD_SIZE  4// Define this based on the value used in your Rust code

typedef struct{
}AddSubChip;

typedef struct {
    uint32_t data[WORD_SIZE];
} Word;

typedef struct {
    Word value;          // The result of `a + b`
    uint32_t carry[3];   // Trace
} AddOperation;

typedef struct {
    uint32_t shard;
    uint32_t channel;
    uint32_t nonce;
    AddOperation add_operation;
    Word operand_1;
    Word operand_2;
    uint32_t is_add;
    uint32_t is_sub;
} AddSubCols;

typedef struct {
    uint8_t value; // Replace with actual definition of Opcode
} Opcode;

typedef struct {
    uint32_t a;
    uint32_t b;
    uint32_t c;
    uint32_t d;
} LookupId;


typedef struct {
    LookupId lookup_id; // Requires implementation-specific type for 128-bit integers
    uint32_t shard;
    uint8_t channel;
    uint32_t clk;
    Opcode opcode;
    uint32_t a;
    uint32_t b;
    uint32_t c;
    LookupId sub_lookups[6];// Requires implementation-specific type for 128-bit integers
} AluEvent;

enum ByteOpcode {
    /// Bitwise AND.
    AND = 0,
    /// Bitwise OR.
    OR = 1,
    /// Bitwise XOR.
    XOR = 2,
    /// Shift Left Logical.
    SLL = 3,
    /// Unsigned 8-bit Range Check.
    U8Range = 4,
    /// Shift Right with Carry.
    ShrCarry = 5,
    /// Unsigned Less Than.
    LTU = 6,
    /// Most Significant Bit.
    MSB = 7,
    /// Unsigned 16-bit Range Check.
    U16Range = 8,
}



