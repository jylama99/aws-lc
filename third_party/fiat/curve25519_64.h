/* Autogenerated: src/ExtractionOCaml/unsaturated_solinas --static 25519 5 '2^255 - 19' 64 carry_mul carry_square carry add sub opp selectznz to_bytes from_bytes carry_scmul121666 */
/* curve description: 25519 */
/* requested operations: carry_mul, carry_square, carry, add, sub, opp, selectznz, to_bytes, from_bytes, carry_scmul121666 */
/* n = 5 (from "5") */
/* s-c = 2^255 - [(1, 19)] (from "2^255 - 19") */
/* machine_wordsize = 64 (from "64") */

/* Computed values: */
/* carry_chain = [0, 1, 2, 3, 4, 0, 1] */

#include <stdint.h>
typedef unsigned char fiat_25519_uint1;
typedef signed char fiat_25519_int1;
// Pedantic warnings can be disabled by adding prefix __extension__.
__extension__ typedef __int128_t fiat_25519_int128;
__extension__ typedef __uint128_t fiat_25519_uint128;

#if (-1 & 3) != 3
#error "This code only works on a two's complement system"
#endif


/*
 * The function fiat_25519_addcarryx_u51 is an addition with carry.
 * Postconditions:
 *   out1 = (arg1 + arg2 + arg3) mod 2^51
 *   out2 = ⌊(arg1 + arg2 + arg3) / 2^51⌋
 *
 * Input Bounds:
 *   arg1: [0x0 ~> 0x1]
 *   arg2: [0x0 ~> 0x7ffffffffffff]
 *   arg3: [0x0 ~> 0x7ffffffffffff]
 * Output Bounds:
 *   out1: [0x0 ~> 0x7ffffffffffff]
 *   out2: [0x0 ~> 0x1]
 */
static void fiat_25519_addcarryx_u51(uint64_t* out1, fiat_25519_uint1* out2, fiat_25519_uint1 arg1, uint64_t arg2, uint64_t arg3) {
  uint64_t x1 = ((arg1 + arg2) + arg3);
  uint64_t x2 = (x1 & UINT64_C(0x7ffffffffffff));
  fiat_25519_uint1 x3 = (fiat_25519_uint1)(x1 >> 51);
  *out1 = x2;
  *out2 = x3;
}

/*
 * The function fiat_25519_subborrowx_u51 is a subtraction with borrow.
 * Postconditions:
 *   out1 = (-arg1 + arg2 + -arg3) mod 2^51
 *   out2 = -⌊(-arg1 + arg2 + -arg3) / 2^51⌋
 *
 * Input Bounds:
 *   arg1: [0x0 ~> 0x1]
 *   arg2: [0x0 ~> 0x7ffffffffffff]
 *   arg3: [0x0 ~> 0x7ffffffffffff]
 * Output Bounds:
 *   out1: [0x0 ~> 0x7ffffffffffff]
 *   out2: [0x0 ~> 0x1]
 */
static void fiat_25519_subborrowx_u51(uint64_t* out1, fiat_25519_uint1* out2, fiat_25519_uint1 arg1, uint64_t arg2, uint64_t arg3) {
  int64_t x1 = ((int64_t)(arg2 - (int64_t)arg1) - (int64_t)arg3);
  fiat_25519_int1 x2 = (fiat_25519_int1)(x1 >> 51);
  uint64_t x3 = (x1 & UINT64_C(0x7ffffffffffff));
  *out1 = x3;
  *out2 = (fiat_25519_uint1)(0x0 - x2);
}

/*
 * The function fiat_25519_cmovznz_u64 is a single-word conditional move.
 * Postconditions:
 *   out1 = (if arg1 = 0 then arg2 else arg3)
 *
 * Input Bounds:
 *   arg1: [0x0 ~> 0x1]
 *   arg2: [0x0 ~> 0xffffffffffffffff]
 *   arg3: [0x0 ~> 0xffffffffffffffff]
 * Output Bounds:
 *   out1: [0x0 ~> 0xffffffffffffffff]
 */
static void fiat_25519_cmovznz_u64(uint64_t* out1, fiat_25519_uint1 arg1, uint64_t arg2, uint64_t arg3) {
  fiat_25519_uint1 x1 = (!(!arg1));
  uint64_t x2 = ((fiat_25519_int1)(0x0 - x1) & UINT64_C(0xffffffffffffffff));
  // Note this line has been patched from the synthesized code to add value
  // barriers.
  //
  // Clang recognizes this pattern as a select. While it usually transforms it
  // to a cmov, it sometimes further transforms it into a branch, which we do
  // not want.
  uint64_t x3 = ((value_barrier_u64(x2) & arg3) | (value_barrier_u64(~x2) & arg2));
  *out1 = x3;
}

/*
 * The function fiat_25519_carry_mul multiplies two field elements and reduces the result.
 * Postconditions:
 *   eval out1 mod m = (eval arg1 * eval arg2) mod m
 *
 * Input Bounds:
 *   arg1: [[0x0 ~> 0x1a666666666664], [0x0 ~> 0x1a666666666664], [0x0 ~> 0x1a666666666664], [0x0 ~> 0x1a666666666664], [0x0 ~> 0x1a666666666664]]
 *   arg2: [[0x0 ~> 0x1a666666666664], [0x0 ~> 0x1a666666666664], [0x0 ~> 0x1a666666666664], [0x0 ~> 0x1a666666666664], [0x0 ~> 0x1a666666666664]]
 * Output Bounds:
 *   out1: [[0x0 ~> 0x8cccccccccccc], [0x0 ~> 0x8cccccccccccc], [0x0 ~> 0x8cccccccccccc], [0x0 ~> 0x8cccccccccccc], [0x0 ~> 0x8cccccccccccc]]
 */
static void fiat_25519_carry_mul(uint64_t out1[5], const uint64_t arg1[5], const uint64_t arg2[5]) {
  fiat_25519_uint128 x1 = ((fiat_25519_uint128)(arg1[4]) * ((arg2[4]) * UINT8_C(0x13)));
  fiat_25519_uint128 x2 = ((fiat_25519_uint128)(arg1[4]) * ((arg2[3]) * UINT8_C(0x13)));
  fiat_25519_uint128 x3 = ((fiat_25519_uint128)(arg1[4]) * ((arg2[2]) * UINT8_C(0x13)));
  fiat_25519_uint128 x4 = ((fiat_25519_uint128)(arg1[4]) * ((arg2[1]) * UINT8_C(0x13)));
  fiat_25519_uint128 x5 = ((fiat_25519_uint128)(arg1[3]) * ((arg2[4]) * UINT8_C(0x13)));
  fiat_25519_uint128 x6 = ((fiat_25519_uint128)(arg1[3]) * ((arg2[3]) * UINT8_C(0x13)));
  fiat_25519_uint128 x7 = ((fiat_25519_uint128)(arg1[3]) * ((arg2[2]) * UINT8_C(0x13)));
  fiat_25519_uint128 x8 = ((fiat_25519_uint128)(arg1[2]) * ((arg2[4]) * UINT8_C(0x13)));
  fiat_25519_uint128 x9 = ((fiat_25519_uint128)(arg1[2]) * ((arg2[3]) * UINT8_C(0x13)));
  fiat_25519_uint128 x10 = ((fiat_25519_uint128)(arg1[1]) * ((arg2[4]) * UINT8_C(0x13)));
  fiat_25519_uint128 x11 = ((fiat_25519_uint128)(arg1[4]) * (arg2[0]));
  fiat_25519_uint128 x12 = ((fiat_25519_uint128)(arg1[3]) * (arg2[1]));
  fiat_25519_uint128 x13 = ((fiat_25519_uint128)(arg1[3]) * (arg2[0]));
  fiat_25519_uint128 x14 = ((fiat_25519_uint128)(arg1[2]) * (arg2[2]));
  fiat_25519_uint128 x15 = ((fiat_25519_uint128)(arg1[2]) * (arg2[1]));
  fiat_25519_uint128 x16 = ((fiat_25519_uint128)(arg1[2]) * (arg2[0]));
  fiat_25519_uint128 x17 = ((fiat_25519_uint128)(arg1[1]) * (arg2[3]));
  fiat_25519_uint128 x18 = ((fiat_25519_uint128)(arg1[1]) * (arg2[2]));
  fiat_25519_uint128 x19 = ((fiat_25519_uint128)(arg1[1]) * (arg2[1]));
  fiat_25519_uint128 x20 = ((fiat_25519_uint128)(arg1[1]) * (arg2[0]));
  fiat_25519_uint128 x21 = ((fiat_25519_uint128)(arg1[0]) * (arg2[4]));
  fiat_25519_uint128 x22 = ((fiat_25519_uint128)(arg1[0]) * (arg2[3]));
  fiat_25519_uint128 x23 = ((fiat_25519_uint128)(arg1[0]) * (arg2[2]));
  fiat_25519_uint128 x24 = ((fiat_25519_uint128)(arg1[0]) * (arg2[1]));
  fiat_25519_uint128 x25 = ((fiat_25519_uint128)(arg1[0]) * (arg2[0]));
  fiat_25519_uint128 x26 = (x25 + (x10 + (x9 + (x7 + x4))));
  uint64_t x27 = (uint64_t)(x26 >> 51);
  uint64_t x28 = (uint64_t)(x26 & UINT64_C(0x7ffffffffffff));
  fiat_25519_uint128 x29 = (x21 + (x17 + (x14 + (x12 + x11))));
  fiat_25519_uint128 x30 = (x22 + (x18 + (x15 + (x13 + x1))));
  fiat_25519_uint128 x31 = (x23 + (x19 + (x16 + (x5 + x2))));
  fiat_25519_uint128 x32 = (x24 + (x20 + (x8 + (x6 + x3))));
  fiat_25519_uint128 x33 = (x27 + x32);
  uint64_t x34 = (uint64_t)(x33 >> 51);
  uint64_t x35 = (uint64_t)(x33 & UINT64_C(0x7ffffffffffff));
  fiat_25519_uint128 x36 = (x34 + x31);
  uint64_t x37 = (uint64_t)(x36 >> 51);
  uint64_t x38 = (uint64_t)(x36 & UINT64_C(0x7ffffffffffff));
  fiat_25519_uint128 x39 = (x37 + x30);
  uint64_t x40 = (uint64_t)(x39 >> 51);
  uint64_t x41 = (uint64_t)(x39 & UINT64_C(0x7ffffffffffff));
  fiat_25519_uint128 x42 = (x40 + x29);
  uint64_t x43 = (uint64_t)(x42 >> 51);
  uint64_t x44 = (uint64_t)(x42 & UINT64_C(0x7ffffffffffff));
  uint64_t x45 = (x43 * UINT8_C(0x13));
  uint64_t x46 = (x28 + x45);
  uint64_t x47 = (x46 >> 51);
  uint64_t x48 = (x46 & UINT64_C(0x7ffffffffffff));
  uint64_t x49 = (x47 + x35);
  fiat_25519_uint1 x50 = (fiat_25519_uint1)(x49 >> 51);
  uint64_t x51 = (x49 & UINT64_C(0x7ffffffffffff));
  uint64_t x52 = (x50 + x38);
  out1[0] = x48;
  out1[1] = x51;
  out1[2] = x52;
  out1[3] = x41;
  out1[4] = x44;
}

/*
 * The function fiat_25519_carry_square squares a field element and reduces the result.
 * Postconditions:
 *   eval out1 mod m = (eval arg1 * eval arg1) mod m
 *
 * Input Bounds:
 *   arg1: [[0x0 ~> 0x1a666666666664], [0x0 ~> 0x1a666666666664], [0x0 ~> 0x1a666666666664], [0x0 ~> 0x1a666666666664], [0x0 ~> 0x1a666666666664]]
 * Output Bounds:
 *   out1: [[0x0 ~> 0x8cccccccccccc], [0x0 ~> 0x8cccccccccccc], [0x0 ~> 0x8cccccccccccc], [0x0 ~> 0x8cccccccccccc], [0x0 ~> 0x8cccccccccccc]]
 */
static void fiat_25519_carry_square(uint64_t out1[5], const uint64_t arg1[5]) {
  uint64_t x1 = ((arg1[4]) * UINT8_C(0x13));
  uint64_t x2 = (x1 * 0x2);
  uint64_t x3 = ((arg1[4]) * 0x2);
  uint64_t x4 = ((arg1[3]) * UINT8_C(0x13));
  uint64_t x5 = (x4 * 0x2);
  uint64_t x6 = ((arg1[3]) * 0x2);
  uint64_t x7 = ((arg1[2]) * 0x2);
  uint64_t x8 = ((arg1[1]) * 0x2);
  fiat_25519_uint128 x9 = ((fiat_25519_uint128)(arg1[4]) * x1);
  fiat_25519_uint128 x10 = ((fiat_25519_uint128)(arg1[3]) * x2);
  fiat_25519_uint128 x11 = ((fiat_25519_uint128)(arg1[3]) * x4);
  fiat_25519_uint128 x12 = ((fiat_25519_uint128)(arg1[2]) * x2);
  fiat_25519_uint128 x13 = ((fiat_25519_uint128)(arg1[2]) * x5);
  fiat_25519_uint128 x14 = ((fiat_25519_uint128)(arg1[2]) * (arg1[2]));
  fiat_25519_uint128 x15 = ((fiat_25519_uint128)(arg1[1]) * x2);
  fiat_25519_uint128 x16 = ((fiat_25519_uint128)(arg1[1]) * x6);
  fiat_25519_uint128 x17 = ((fiat_25519_uint128)(arg1[1]) * x7);
  fiat_25519_uint128 x18 = ((fiat_25519_uint128)(arg1[1]) * (arg1[1]));
  fiat_25519_uint128 x19 = ((fiat_25519_uint128)(arg1[0]) * x3);
  fiat_25519_uint128 x20 = ((fiat_25519_uint128)(arg1[0]) * x6);
  fiat_25519_uint128 x21 = ((fiat_25519_uint128)(arg1[0]) * x7);
  fiat_25519_uint128 x22 = ((fiat_25519_uint128)(arg1[0]) * x8);
  fiat_25519_uint128 x23 = ((fiat_25519_uint128)(arg1[0]) * (arg1[0]));
  fiat_25519_uint128 x24 = (x23 + (x15 + x13));
  uint64_t x25 = (uint64_t)(x24 >> 51);
  uint64_t x26 = (uint64_t)(x24 & UINT64_C(0x7ffffffffffff));
  fiat_25519_uint128 x27 = (x19 + (x16 + x14));
  fiat_25519_uint128 x28 = (x20 + (x17 + x9));
  fiat_25519_uint128 x29 = (x21 + (x18 + x10));
  fiat_25519_uint128 x30 = (x22 + (x12 + x11));
  fiat_25519_uint128 x31 = (x25 + x30);
  uint64_t x32 = (uint64_t)(x31 >> 51);
  uint64_t x33 = (uint64_t)(x31 & UINT64_C(0x7ffffffffffff));
  fiat_25519_uint128 x34 = (x32 + x29);
  uint64_t x35 = (uint64_t)(x34 >> 51);
  uint64_t x36 = (uint64_t)(x34 & UINT64_C(0x7ffffffffffff));
  fiat_25519_uint128 x37 = (x35 + x28);
  uint64_t x38 = (uint64_t)(x37 >> 51);
  uint64_t x39 = (uint64_t)(x37 & UINT64_C(0x7ffffffffffff));
  fiat_25519_uint128 x40 = (x38 + x27);
  uint64_t x41 = (uint64_t)(x40 >> 51);
  uint64_t x42 = (uint64_t)(x40 & UINT64_C(0x7ffffffffffff));
  uint64_t x43 = (x41 * UINT8_C(0x13));
  uint64_t x44 = (x26 + x43);
  uint64_t x45 = (x44 >> 51);
  uint64_t x46 = (x44 & UINT64_C(0x7ffffffffffff));
  uint64_t x47 = (x45 + x33);
  fiat_25519_uint1 x48 = (fiat_25519_uint1)(x47 >> 51);
  uint64_t x49 = (x47 & UINT64_C(0x7ffffffffffff));
  uint64_t x50 = (x48 + x36);
  out1[0] = x46;
  out1[1] = x49;
  out1[2] = x50;
  out1[3] = x39;
  out1[4] = x42;
}

/*
 * The function fiat_25519_carry reduces a field element.
 * Postconditions:
 *   eval out1 mod m = eval arg1 mod m
 *
 * Input Bounds:
 *   arg1: [[0x0 ~> 0x1a666666666664], [0x0 ~> 0x1a666666666664], [0x0 ~> 0x1a666666666664], [0x0 ~> 0x1a666666666664], [0x0 ~> 0x1a666666666664]]
 * Output Bounds:
 *   out1: [[0x0 ~> 0x8cccccccccccc], [0x0 ~> 0x8cccccccccccc], [0x0 ~> 0x8cccccccccccc], [0x0 ~> 0x8cccccccccccc], [0x0 ~> 0x8cccccccccccc]]
 */
static void fiat_25519_carry(uint64_t out1[5], const uint64_t arg1[5]) {
  uint64_t x1 = (arg1[0]);
  uint64_t x2 = ((x1 >> 51) + (arg1[1]));
  uint64_t x3 = ((x2 >> 51) + (arg1[2]));
  uint64_t x4 = ((x3 >> 51) + (arg1[3]));
  uint64_t x5 = ((x4 >> 51) + (arg1[4]));
  uint64_t x6 = ((x1 & UINT64_C(0x7ffffffffffff)) + ((x5 >> 51) * UINT8_C(0x13)));
  uint64_t x7 = ((fiat_25519_uint1)(x6 >> 51) + (x2 & UINT64_C(0x7ffffffffffff)));
  uint64_t x8 = (x6 & UINT64_C(0x7ffffffffffff));
  uint64_t x9 = (x7 & UINT64_C(0x7ffffffffffff));
  uint64_t x10 = ((fiat_25519_uint1)(x7 >> 51) + (x3 & UINT64_C(0x7ffffffffffff)));
  uint64_t x11 = (x4 & UINT64_C(0x7ffffffffffff));
  uint64_t x12 = (x5 & UINT64_C(0x7ffffffffffff));
  out1[0] = x8;
  out1[1] = x9;
  out1[2] = x10;
  out1[3] = x11;
  out1[4] = x12;
}

/*
 * The function fiat_25519_add adds two field elements.
 * Postconditions:
 *   eval out1 mod m = (eval arg1 + eval arg2) mod m
 *
 * Input Bounds:
 *   arg1: [[0x0 ~> 0x8cccccccccccc], [0x0 ~> 0x8cccccccccccc], [0x0 ~> 0x8cccccccccccc], [0x0 ~> 0x8cccccccccccc], [0x0 ~> 0x8cccccccccccc]]
 *   arg2: [[0x0 ~> 0x8cccccccccccc], [0x0 ~> 0x8cccccccccccc], [0x0 ~> 0x8cccccccccccc], [0x0 ~> 0x8cccccccccccc], [0x0 ~> 0x8cccccccccccc]]
 * Output Bounds:
 *   out1: [[0x0 ~> 0x1a666666666664], [0x0 ~> 0x1a666666666664], [0x0 ~> 0x1a666666666664], [0x0 ~> 0x1a666666666664], [0x0 ~> 0x1a666666666664]]
 */
static void fiat_25519_add(uint64_t out1[5], const uint64_t arg1[5], const uint64_t arg2[5]) {
  uint64_t x1 = ((arg1[0]) + (arg2[0]));
  uint64_t x2 = ((arg1[1]) + (arg2[1]));
  uint64_t x3 = ((arg1[2]) + (arg2[2]));
  uint64_t x4 = ((arg1[3]) + (arg2[3]));
  uint64_t x5 = ((arg1[4]) + (arg2[4]));
  out1[0] = x1;
  out1[1] = x2;
  out1[2] = x3;
  out1[3] = x4;
  out1[4] = x5;
}

/*
 * The function fiat_25519_sub subtracts two field elements.
 * Postconditions:
 *   eval out1 mod m = (eval arg1 - eval arg2) mod m
 *
 * Input Bounds:
 *   arg1: [[0x0 ~> 0x8cccccccccccc], [0x0 ~> 0x8cccccccccccc], [0x0 ~> 0x8cccccccccccc], [0x0 ~> 0x8cccccccccccc], [0x0 ~> 0x8cccccccccccc]]
 *   arg2: [[0x0 ~> 0x8cccccccccccc], [0x0 ~> 0x8cccccccccccc], [0x0 ~> 0x8cccccccccccc], [0x0 ~> 0x8cccccccccccc], [0x0 ~> 0x8cccccccccccc]]
 * Output Bounds:
 *   out1: [[0x0 ~> 0x1a666666666664], [0x0 ~> 0x1a666666666664], [0x0 ~> 0x1a666666666664], [0x0 ~> 0x1a666666666664], [0x0 ~> 0x1a666666666664]]
 */
static void fiat_25519_sub(uint64_t out1[5], const uint64_t arg1[5], const uint64_t arg2[5]) {
  uint64_t x1 = ((UINT64_C(0xfffffffffffda) + (arg1[0])) - (arg2[0]));
  uint64_t x2 = ((UINT64_C(0xffffffffffffe) + (arg1[1])) - (arg2[1]));
  uint64_t x3 = ((UINT64_C(0xffffffffffffe) + (arg1[2])) - (arg2[2]));
  uint64_t x4 = ((UINT64_C(0xffffffffffffe) + (arg1[3])) - (arg2[3]));
  uint64_t x5 = ((UINT64_C(0xffffffffffffe) + (arg1[4])) - (arg2[4]));
  out1[0] = x1;
  out1[1] = x2;
  out1[2] = x3;
  out1[3] = x4;
  out1[4] = x5;
}

/*
 * The function fiat_25519_opp negates a field element.
 * Postconditions:
 *   eval out1 mod m = -eval arg1 mod m
 *
 * Input Bounds:
 *   arg1: [[0x0 ~> 0x8cccccccccccc], [0x0 ~> 0x8cccccccccccc], [0x0 ~> 0x8cccccccccccc], [0x0 ~> 0x8cccccccccccc], [0x0 ~> 0x8cccccccccccc]]
 * Output Bounds:
 *   out1: [[0x0 ~> 0x1a666666666664], [0x0 ~> 0x1a666666666664], [0x0 ~> 0x1a666666666664], [0x0 ~> 0x1a666666666664], [0x0 ~> 0x1a666666666664]]
 */
static void fiat_25519_opp(uint64_t out1[5], const uint64_t arg1[5]) {
  uint64_t x1 = (UINT64_C(0xfffffffffffda) - (arg1[0]));
  uint64_t x2 = (UINT64_C(0xffffffffffffe) - (arg1[1]));
  uint64_t x3 = (UINT64_C(0xffffffffffffe) - (arg1[2]));
  uint64_t x4 = (UINT64_C(0xffffffffffffe) - (arg1[3]));
  uint64_t x5 = (UINT64_C(0xffffffffffffe) - (arg1[4]));
  out1[0] = x1;
  out1[1] = x2;
  out1[2] = x3;
  out1[3] = x4;
  out1[4] = x5;
}

/*
 * The function fiat_25519_selectznz is a multi-limb conditional select.
 * Postconditions:
 *   eval out1 = (if arg1 = 0 then eval arg2 else eval arg3)
 *
 * Input Bounds:
 *   arg1: [0x0 ~> 0x1]
 *   arg2: [[0x0 ~> 0xffffffffffffffff], [0x0 ~> 0xffffffffffffffff], [0x0 ~> 0xffffffffffffffff], [0x0 ~> 0xffffffffffffffff], [0x0 ~> 0xffffffffffffffff]]
 *   arg3: [[0x0 ~> 0xffffffffffffffff], [0x0 ~> 0xffffffffffffffff], [0x0 ~> 0xffffffffffffffff], [0x0 ~> 0xffffffffffffffff], [0x0 ~> 0xffffffffffffffff]]
 * Output Bounds:
 *   out1: [[0x0 ~> 0xffffffffffffffff], [0x0 ~> 0xffffffffffffffff], [0x0 ~> 0xffffffffffffffff], [0x0 ~> 0xffffffffffffffff], [0x0 ~> 0xffffffffffffffff]]
 */
static void fiat_25519_selectznz(uint64_t out1[5], fiat_25519_uint1 arg1, const uint64_t arg2[5], const uint64_t arg3[5]) {
  uint64_t x1;
  fiat_25519_cmovznz_u64(&x1, arg1, (arg2[0]), (arg3[0]));
  uint64_t x2;
  fiat_25519_cmovznz_u64(&x2, arg1, (arg2[1]), (arg3[1]));
  uint64_t x3;
  fiat_25519_cmovznz_u64(&x3, arg1, (arg2[2]), (arg3[2]));
  uint64_t x4;
  fiat_25519_cmovznz_u64(&x4, arg1, (arg2[3]), (arg3[3]));
  uint64_t x5;
  fiat_25519_cmovznz_u64(&x5, arg1, (arg2[4]), (arg3[4]));
  out1[0] = x1;
  out1[1] = x2;
  out1[2] = x3;
  out1[3] = x4;
  out1[4] = x5;
}

/*
 * The function fiat_25519_to_bytes serializes a field element to bytes in little-endian order.
 * Postconditions:
 *   out1 = map (λ x, ⌊((eval arg1 mod m) mod 2^(8 * (x + 1))) / 2^(8 * x)⌋) [0..31]
 *
 * Input Bounds:
 *   arg1: [[0x0 ~> 0x8cccccccccccc], [0x0 ~> 0x8cccccccccccc], [0x0 ~> 0x8cccccccccccc], [0x0 ~> 0x8cccccccccccc], [0x0 ~> 0x8cccccccccccc]]
 * Output Bounds:
 *   out1: [[0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0x7f]]
 */
static void fiat_25519_to_bytes(uint8_t out1[32], const uint64_t arg1[5]) {
  uint64_t x1;
  fiat_25519_uint1 x2;
  fiat_25519_subborrowx_u51(&x1, &x2, 0x0, (arg1[0]), UINT64_C(0x7ffffffffffed));
  uint64_t x3;
  fiat_25519_uint1 x4;
  fiat_25519_subborrowx_u51(&x3, &x4, x2, (arg1[1]), UINT64_C(0x7ffffffffffff));
  uint64_t x5;
  fiat_25519_uint1 x6;
  fiat_25519_subborrowx_u51(&x5, &x6, x4, (arg1[2]), UINT64_C(0x7ffffffffffff));
  uint64_t x7;
  fiat_25519_uint1 x8;
  fiat_25519_subborrowx_u51(&x7, &x8, x6, (arg1[3]), UINT64_C(0x7ffffffffffff));
  uint64_t x9;
  fiat_25519_uint1 x10;
  fiat_25519_subborrowx_u51(&x9, &x10, x8, (arg1[4]), UINT64_C(0x7ffffffffffff));
  uint64_t x11;
  fiat_25519_cmovznz_u64(&x11, x10, 0x0, UINT64_C(0xffffffffffffffff));
  uint64_t x12;
  fiat_25519_uint1 x13;
  fiat_25519_addcarryx_u51(&x12, &x13, 0x0, x1, (x11 & UINT64_C(0x7ffffffffffed)));
  uint64_t x14;
  fiat_25519_uint1 x15;
  fiat_25519_addcarryx_u51(&x14, &x15, x13, x3, (x11 & UINT64_C(0x7ffffffffffff)));
  uint64_t x16;
  fiat_25519_uint1 x17;
  fiat_25519_addcarryx_u51(&x16, &x17, x15, x5, (x11 & UINT64_C(0x7ffffffffffff)));
  uint64_t x18;
  fiat_25519_uint1 x19;
  fiat_25519_addcarryx_u51(&x18, &x19, x17, x7, (x11 & UINT64_C(0x7ffffffffffff)));
  uint64_t x20;
  fiat_25519_uint1 x21;
  fiat_25519_addcarryx_u51(&x20, &x21, x19, x9, (x11 & UINT64_C(0x7ffffffffffff)));
  uint64_t x22 = (x20 << 4);
  uint64_t x23 = (x18 * (uint64_t)0x2);
  uint64_t x24 = (x16 << 6);
  uint64_t x25 = (x14 << 3);
  uint64_t x26 = (x12 >> 8);
  uint8_t x27 = (uint8_t)(x12 & UINT8_C(0xff));
  uint64_t x28 = (x26 >> 8);
  uint8_t x29 = (uint8_t)(x26 & UINT8_C(0xff));
  uint64_t x30 = (x28 >> 8);
  uint8_t x31 = (uint8_t)(x28 & UINT8_C(0xff));
  uint64_t x32 = (x30 >> 8);
  uint8_t x33 = (uint8_t)(x30 & UINT8_C(0xff));
  uint64_t x34 = (x32 >> 8);
  uint8_t x35 = (uint8_t)(x32 & UINT8_C(0xff));
  uint8_t x36 = (uint8_t)(x34 >> 8);
  uint8_t x37 = (uint8_t)(x34 & UINT8_C(0xff));
  uint64_t x38 = (x36 + x25);
  uint64_t x39 = (x38 >> 8);
  uint8_t x40 = (uint8_t)(x38 & UINT8_C(0xff));
  uint64_t x41 = (x39 >> 8);
  uint8_t x42 = (uint8_t)(x39 & UINT8_C(0xff));
  uint64_t x43 = (x41 >> 8);
  uint8_t x44 = (uint8_t)(x41 & UINT8_C(0xff));
  uint64_t x45 = (x43 >> 8);
  uint8_t x46 = (uint8_t)(x43 & UINT8_C(0xff));
  uint64_t x47 = (x45 >> 8);
  uint8_t x48 = (uint8_t)(x45 & UINT8_C(0xff));
  uint8_t x49 = (uint8_t)(x47 >> 8);
  uint8_t x50 = (uint8_t)(x47 & UINT8_C(0xff));
  uint64_t x51 = (x49 + x24);
  uint64_t x52 = (x51 >> 8);
  uint8_t x53 = (uint8_t)(x51 & UINT8_C(0xff));
  uint64_t x54 = (x52 >> 8);
  uint8_t x55 = (uint8_t)(x52 & UINT8_C(0xff));
  uint64_t x56 = (x54 >> 8);
  uint8_t x57 = (uint8_t)(x54 & UINT8_C(0xff));
  uint64_t x58 = (x56 >> 8);
  uint8_t x59 = (uint8_t)(x56 & UINT8_C(0xff));
  uint64_t x60 = (x58 >> 8);
  uint8_t x61 = (uint8_t)(x58 & UINT8_C(0xff));
  uint64_t x62 = (x60 >> 8);
  uint8_t x63 = (uint8_t)(x60 & UINT8_C(0xff));
  fiat_25519_uint1 x64 = (fiat_25519_uint1)(x62 >> 8);
  uint8_t x65 = (uint8_t)(x62 & UINT8_C(0xff));
  uint64_t x66 = (x64 + x23);
  uint64_t x67 = (x66 >> 8);
  uint8_t x68 = (uint8_t)(x66 & UINT8_C(0xff));
  uint64_t x69 = (x67 >> 8);
  uint8_t x70 = (uint8_t)(x67 & UINT8_C(0xff));
  uint64_t x71 = (x69 >> 8);
  uint8_t x72 = (uint8_t)(x69 & UINT8_C(0xff));
  uint64_t x73 = (x71 >> 8);
  uint8_t x74 = (uint8_t)(x71 & UINT8_C(0xff));
  uint64_t x75 = (x73 >> 8);
  uint8_t x76 = (uint8_t)(x73 & UINT8_C(0xff));
  uint8_t x77 = (uint8_t)(x75 >> 8);
  uint8_t x78 = (uint8_t)(x75 & UINT8_C(0xff));
  uint64_t x79 = (x77 + x22);
  uint64_t x80 = (x79 >> 8);
  uint8_t x81 = (uint8_t)(x79 & UINT8_C(0xff));
  uint64_t x82 = (x80 >> 8);
  uint8_t x83 = (uint8_t)(x80 & UINT8_C(0xff));
  uint64_t x84 = (x82 >> 8);
  uint8_t x85 = (uint8_t)(x82 & UINT8_C(0xff));
  uint64_t x86 = (x84 >> 8);
  uint8_t x87 = (uint8_t)(x84 & UINT8_C(0xff));
  uint64_t x88 = (x86 >> 8);
  uint8_t x89 = (uint8_t)(x86 & UINT8_C(0xff));
  uint8_t x90 = (uint8_t)(x88 >> 8);
  uint8_t x91 = (uint8_t)(x88 & UINT8_C(0xff));
  out1[0] = x27;
  out1[1] = x29;
  out1[2] = x31;
  out1[3] = x33;
  out1[4] = x35;
  out1[5] = x37;
  out1[6] = x40;
  out1[7] = x42;
  out1[8] = x44;
  out1[9] = x46;
  out1[10] = x48;
  out1[11] = x50;
  out1[12] = x53;
  out1[13] = x55;
  out1[14] = x57;
  out1[15] = x59;
  out1[16] = x61;
  out1[17] = x63;
  out1[18] = x65;
  out1[19] = x68;
  out1[20] = x70;
  out1[21] = x72;
  out1[22] = x74;
  out1[23] = x76;
  out1[24] = x78;
  out1[25] = x81;
  out1[26] = x83;
  out1[27] = x85;
  out1[28] = x87;
  out1[29] = x89;
  out1[30] = x91;
  out1[31] = x90;
}

/*
 * The function fiat_25519_from_bytes deserializes a field element from bytes in little-endian order.
 * Postconditions:
 *   eval out1 mod m = bytes_eval arg1 mod m
 *
 * Input Bounds:
 *   arg1: [[0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0x7f]]
 * Output Bounds:
 *   out1: [[0x0 ~> 0x8cccccccccccc], [0x0 ~> 0x8cccccccccccc], [0x0 ~> 0x8cccccccccccc], [0x0 ~> 0x8cccccccccccc], [0x0 ~> 0x8cccccccccccc]]
 */
static void fiat_25519_from_bytes(uint64_t out1[5], const uint8_t arg1[32]) {
  uint64_t x1 = ((uint64_t)(arg1[31]) << 44);
  uint64_t x2 = ((uint64_t)(arg1[30]) << 36);
  uint64_t x3 = ((uint64_t)(arg1[29]) << 28);
  uint64_t x4 = ((uint64_t)(arg1[28]) << 20);
  uint64_t x5 = ((uint64_t)(arg1[27]) << 12);
  uint64_t x6 = ((uint64_t)(arg1[26]) << 4);
  uint64_t x7 = ((uint64_t)(arg1[25]) << 47);
  uint64_t x8 = ((uint64_t)(arg1[24]) << 39);
  uint64_t x9 = ((uint64_t)(arg1[23]) << 31);
  uint64_t x10 = ((uint64_t)(arg1[22]) << 23);
  uint64_t x11 = ((uint64_t)(arg1[21]) << 15);
  uint64_t x12 = ((uint64_t)(arg1[20]) << 7);
  uint64_t x13 = ((uint64_t)(arg1[19]) << 50);
  uint64_t x14 = ((uint64_t)(arg1[18]) << 42);
  uint64_t x15 = ((uint64_t)(arg1[17]) << 34);
  uint64_t x16 = ((uint64_t)(arg1[16]) << 26);
  uint64_t x17 = ((uint64_t)(arg1[15]) << 18);
  uint64_t x18 = ((uint64_t)(arg1[14]) << 10);
  uint64_t x19 = ((uint64_t)(arg1[13]) << 2);
  uint64_t x20 = ((uint64_t)(arg1[12]) << 45);
  uint64_t x21 = ((uint64_t)(arg1[11]) << 37);
  uint64_t x22 = ((uint64_t)(arg1[10]) << 29);
  uint64_t x23 = ((uint64_t)(arg1[9]) << 21);
  uint64_t x24 = ((uint64_t)(arg1[8]) << 13);
  uint64_t x25 = ((uint64_t)(arg1[7]) << 5);
  uint64_t x26 = ((uint64_t)(arg1[6]) << 48);
  uint64_t x27 = ((uint64_t)(arg1[5]) << 40);
  uint64_t x28 = ((uint64_t)(arg1[4]) << 32);
  uint64_t x29 = ((uint64_t)(arg1[3]) << 24);
  uint64_t x30 = ((uint64_t)(arg1[2]) << 16);
  uint64_t x31 = ((uint64_t)(arg1[1]) << 8);
  uint8_t x32 = (arg1[0]);
  uint64_t x33 = (x32 + (x31 + (x30 + (x29 + (x28 + (x27 + x26))))));
  uint8_t x34 = (uint8_t)(x33 >> 51);
  uint64_t x35 = (x33 & UINT64_C(0x7ffffffffffff));
  uint64_t x36 = (x6 + (x5 + (x4 + (x3 + (x2 + x1)))));
  uint64_t x37 = (x12 + (x11 + (x10 + (x9 + (x8 + x7)))));
  uint64_t x38 = (x19 + (x18 + (x17 + (x16 + (x15 + (x14 + x13))))));
  uint64_t x39 = (x25 + (x24 + (x23 + (x22 + (x21 + x20)))));
  uint64_t x40 = (x34 + x39);
  uint8_t x41 = (uint8_t)(x40 >> 51);
  uint64_t x42 = (x40 & UINT64_C(0x7ffffffffffff));
  uint64_t x43 = (x41 + x38);
  uint8_t x44 = (uint8_t)(x43 >> 51);
  uint64_t x45 = (x43 & UINT64_C(0x7ffffffffffff));
  uint64_t x46 = (x44 + x37);
  uint8_t x47 = (uint8_t)(x46 >> 51);
  uint64_t x48 = (x46 & UINT64_C(0x7ffffffffffff));
  uint64_t x49 = (x47 + x36);
  out1[0] = x35;
  out1[1] = x42;
  out1[2] = x45;
  out1[3] = x48;
  out1[4] = x49;
}

/*
 * The function fiat_25519_carry_scmul_121666 multiplies a field element by 121666 and reduces the result.
 * Postconditions:
 *   eval out1 mod m = (121666 * eval arg1) mod m
 *
 * Input Bounds:
 *   arg1: [[0x0 ~> 0x1a666666666664], [0x0 ~> 0x1a666666666664], [0x0 ~> 0x1a666666666664], [0x0 ~> 0x1a666666666664], [0x0 ~> 0x1a666666666664]]
 * Output Bounds:
 *   out1: [[0x0 ~> 0x8cccccccccccc], [0x0 ~> 0x8cccccccccccc], [0x0 ~> 0x8cccccccccccc], [0x0 ~> 0x8cccccccccccc], [0x0 ~> 0x8cccccccccccc]]
 */
static void fiat_25519_carry_scmul_121666(uint64_t out1[5], const uint64_t arg1[5]) {
  fiat_25519_uint128 x1 = ((fiat_25519_uint128)UINT32_C(0x1db42) * (arg1[4]));
  fiat_25519_uint128 x2 = ((fiat_25519_uint128)UINT32_C(0x1db42) * (arg1[3]));
  fiat_25519_uint128 x3 = ((fiat_25519_uint128)UINT32_C(0x1db42) * (arg1[2]));
  fiat_25519_uint128 x4 = ((fiat_25519_uint128)UINT32_C(0x1db42) * (arg1[1]));
  fiat_25519_uint128 x5 = ((fiat_25519_uint128)UINT32_C(0x1db42) * (arg1[0]));
  uint64_t x6 = (uint64_t)(x5 >> 51);
  uint64_t x7 = (uint64_t)(x5 & UINT64_C(0x7ffffffffffff));
  fiat_25519_uint128 x8 = (x6 + x4);
  uint64_t x9 = (uint64_t)(x8 >> 51);
  uint64_t x10 = (uint64_t)(x8 & UINT64_C(0x7ffffffffffff));
  fiat_25519_uint128 x11 = (x9 + x3);
  uint64_t x12 = (uint64_t)(x11 >> 51);
  uint64_t x13 = (uint64_t)(x11 & UINT64_C(0x7ffffffffffff));
  fiat_25519_uint128 x14 = (x12 + x2);
  uint64_t x15 = (uint64_t)(x14 >> 51);
  uint64_t x16 = (uint64_t)(x14 & UINT64_C(0x7ffffffffffff));
  fiat_25519_uint128 x17 = (x15 + x1);
  uint64_t x18 = (uint64_t)(x17 >> 51);
  uint64_t x19 = (uint64_t)(x17 & UINT64_C(0x7ffffffffffff));
  uint64_t x20 = (x18 * UINT8_C(0x13));
  uint64_t x21 = (x7 + x20);
  fiat_25519_uint1 x22 = (fiat_25519_uint1)(x21 >> 51);
  uint64_t x23 = (x21 & UINT64_C(0x7ffffffffffff));
  uint64_t x24 = (x22 + x10);
  fiat_25519_uint1 x25 = (fiat_25519_uint1)(x24 >> 51);
  uint64_t x26 = (x24 & UINT64_C(0x7ffffffffffff));
  uint64_t x27 = (x25 + x13);
  out1[0] = x23;
  out1[1] = x26;
  out1[2] = x27;
  out1[3] = x16;
  out1[4] = x19;
}

