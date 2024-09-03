#include <stdint.h>
#include <stdbool.h>

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