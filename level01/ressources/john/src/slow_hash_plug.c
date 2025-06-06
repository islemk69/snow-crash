// Copyright (c) 2012-2013 The Cryptonote developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
//
// Changes from Cryptonote's (AES-NI usage and other optimizations) are
// Copyright (c) 2025 by Solar Designer
// Same license as above, or alternatively (for the changes only):
// Redistribution and use in source and binary forms, with or without
// modification, are permitted.

#include <stdint.h>
#include <string.h>

#include "mbedtls/aesni.h"
#if MBEDTLS_AESNI_HAVE_CODE == 2
#include <immintrin.h>
#endif

#include "arch.h"
#include "memory.h"
#include "int-util.h"
#include "oaes_lib.h"
#include "blake256.h"
#include "groestl.h"
#include "jh.h"
#include "keccak.h"
#include "sph_skein.h"
#include "slow_hash.h"

#define MEMORY		(1 << 21) /* 2 MiB */
#define ITER		(1 << 20)
#define AES_BLOCK_SIZE	16
#define AES_KEY_SIZE	32
#define INIT_SIZE_BLK	8
#define INIT_SIZE_BYTE	(INIT_SIZE_BLK * AES_BLOCK_SIZE)

void hash_extra_blake(const void *data, size_t length, char *hash)
{
	blake256_hash((uint8_t *)hash, data, length);
}

void hash_extra_groestl(const void *data, size_t length, char *hash)
{
	groestl(data, length * 8, (uint8_t *)hash);
}

void hash_extra_jh(const void *data, size_t length, char *hash)
{
	jh_hash(256, data, 8 * length, (uint8_t *)hash);
}

void hash_extra_skein(const void *data, size_t length, char *hash)
{
	sph_skein256_context ctx;

	sph_skein256_init(&ctx);
	sph_skein256(&ctx, data, length);
	sph_skein256_close(&ctx, (unsigned char *)hash);
}

static void (*const extra_hashes[4])(const void *, size_t, char *) = {
	hash_extra_blake, hash_extra_groestl, hash_extra_jh, hash_extra_skein
};

typedef union {
	uint8_t b[AES_BLOCK_SIZE];
	uint32_t u32[AES_BLOCK_SIZE / 4];
	uint64_t u64[AES_BLOCK_SIZE / 8];
#if MBEDTLS_AESNI_HAVE_CODE == 2
	__m128i v;
#endif
} block;

#if 0 && MBEDTLS_AESNI_HAVE_CODE == 2
static inline size_t e2i(block *a, size_t count) { return ((uint32_t)_mm_cvtsi128_si32(a->v) / AES_BLOCK_SIZE) & (count - 1); }
#elif ARCH_LITTLE_ENDIAN && ARCH_BITS == 64
/* On 64-bit little-endian, it may be more optimal to use 64-bit here */
static inline size_t e2i(block *a, size_t count) { return (swap64le(a->u64[0]) / AES_BLOCK_SIZE) & (count - 1); }
#else
/* Otherwise, 32 bits is enough - no need to potentially swap 64 bits */
static inline size_t e2i(block *a, size_t count) { return (swap32le(a->u32[0]) / AES_BLOCK_SIZE) & (count - 1); }
#endif

static inline void mul(const block *a, const block *b, block *res) {
	uint64_t a0, b0;
	uint64_t hi, lo;

	a0 = SWAP64LE(a->u64[0]);
	b0 = SWAP64LE(b->u64[0]);
	lo = mul128(a0, b0, &hi);
	res->u64[0] = SWAP64LE(hi);
	res->u64[1] = SWAP64LE(lo);
}

static inline void sum_half_blocks(block *a, const block *b) {
#if 0 && MBEDTLS_AESNI_HAVE_CODE == 2
	a->v = _mm_add_epi64(a->v, b->v);
#else
	uint64_t a0, a1, b0, b1;

	a0 = SWAP64LE(a->u64[0]);
	a1 = SWAP64LE(a->u64[1]);
	b0 = SWAP64LE(b->u64[0]);
	b1 = SWAP64LE(b->u64[1]);
	a0 += b0;
	a1 += b1;
	a->u64[0] = SWAP64LE(a0);
	a->u64[1] = SWAP64LE(a1);
#endif
}

static inline void xor_blocks(block *a, const block *b) {
#if 1 && MBEDTLS_AESNI_HAVE_CODE == 2
	a->v = _mm_xor_si128(a->v, b->v);
#else
	a->u64[0] ^= b->u64[0];
	a->u64[1] ^= b->u64[1];
#endif
}

union hash_state {
	uint8_t b[200];
	uint64_t w[25];
	struct {
		uint64_t k[8];
		uint8_t init[INIT_SIZE_BYTE];
	};
};

void hash_permutation(union hash_state *state)
{
	mem_inplace_swap64le(state->w, 25);
	keccakf(state->w, 24);
	mem_inplace_swap64le(state->w, 25);
}

void hash_process(union hash_state *state, const uint8_t *buf, size_t count)
{
	keccak1600(buf, count, (uint8_t*)state);
}

#if MBEDTLS_AESNI_HAVE_CODE == 2
static inline void aesni_pseudo_encrypt_ecb(const uint8_t * restrict exp_data, const block *in, block *out)
{
	const __m128i *dv = (const __m128i *)exp_data;
#define ENCRYPT_BLOCKS(key, in, out) \
	out[0].v = _mm_aesenc_si128(in[0].v, key); \
	out[1].v = _mm_aesenc_si128(in[1].v, key); \
	out[2].v = _mm_aesenc_si128(in[2].v, key); \
	out[3].v = _mm_aesenc_si128(in[3].v, key); \
	out[4].v = _mm_aesenc_si128(in[4].v, key); \
	out[5].v = _mm_aesenc_si128(in[5].v, key); \
	out[6].v = _mm_aesenc_si128(in[6].v, key); \
	out[7].v = _mm_aesenc_si128(in[7].v, key);
	ENCRYPT_BLOCKS(dv[0], in, out)
	ENCRYPT_BLOCKS(dv[1], out, out)
	ENCRYPT_BLOCKS(dv[2], out, out)
	ENCRYPT_BLOCKS(dv[3], out, out)
	ENCRYPT_BLOCKS(dv[4], out, out)
	ENCRYPT_BLOCKS(dv[5], out, out)
	ENCRYPT_BLOCKS(dv[6], out, out)
	ENCRYPT_BLOCKS(dv[7], out, out)
	ENCRYPT_BLOCKS(dv[8], out, out)
	ENCRYPT_BLOCKS(dv[9], out, out)
#undef ENCRYPT_BLOCKS
}
#endif

int cn_slow_hash(const void *data, size_t length, char *hash, void *memory)
{
#if MBEDTLS_AESNI_HAVE_CODE == 2
	const int have_aesni = mbedtls_aesni_has_support(MBEDTLS_AESNI_AES);
#endif
	block *long_state = memory; // This is 2 MiB, too large for stack
	union hash_state state;
	block text[INIT_SIZE_BLK];
	block a, b, c, d;
	size_t i, j;

	hash_process(&state, data, length);
	memcpy(text, state.init, INIT_SIZE_BYTE);

	OAES_CTX *aes_ctx = oaes_alloc();
	if (!aes_ctx || oaes_key_import_data(aes_ctx, state.b, AES_KEY_SIZE))
		goto fail;
#if MBEDTLS_AESNI_HAVE_CODE == 2
	const uint8_t *aes_exp_data = oaes_get_exp_data(aes_ctx);
	if (have_aesni) {
		aesni_pseudo_encrypt_ecb(aes_exp_data, text, long_state);
		for (i = 1; i < MEMORY / INIT_SIZE_BYTE; i++)
			aesni_pseudo_encrypt_ecb(aes_exp_data, &long_state[(i - 1) * INIT_SIZE_BLK], &long_state[i * INIT_SIZE_BLK]);
	} else
#endif
	for (i = 0; i < MEMORY / INIT_SIZE_BYTE; i++) {
		for (j = 0; j < INIT_SIZE_BLK; j++)
			oaes_pseudo_encrypt_ecb(aes_ctx, text[j].b);
		memcpy(&long_state[i * INIT_SIZE_BLK], text, INIT_SIZE_BYTE);
	}

	a.u64[0] = state.k[0] ^ state.k[4];
	a.u64[1] = state.k[1] ^ state.k[5];
	b.u64[0] = state.k[2] ^ state.k[6];
	b.u64[1] = state.k[3] ^ state.k[7];

	i = ITER / 2;
#if MBEDTLS_AESNI_HAVE_CODE == 2
	/* Dependency chain: address -> read value ------+
	 * written value <-+ hard function (AES or MUL) <+
	 * next address  <-+
	 */
	if (have_aesni)
#if 1 && __GNUC__ && __x86_64__ /* any asm */
	__asm__ __volatile__(
#if 1 && __AVX2__ /* or actually __AES__ && __AVX__ && __BMI__ */
		"vmovdqa %1,%%xmm0\n\t"
		"vmovdqa %2,%%xmm1\n\t"
		"vmovd %%xmm0,%%r8d\n\t"
		"andnl %%r8d,%4,%%edx\n\t"
		"1:\n\t"
		"vmovdqa (%%rbx,%%rdx),%%xmm2\n\t"
		"vaesenc %%xmm0,%%xmm2,%%xmm2\n\t"
		"vmovq %%xmm2,%%rax\n\t"
		"vpxor %%xmm2,%%xmm1,%%xmm1\n\t"
		"andnl %%eax,%4,%%ecx\n\t"
		"vmovdqa %%xmm1,(%%rbx,%%rdx)\n\t"
		"mulq (%%rbx,%%rcx)\n\t"
		"vmovq %%rdx,%%xmm3\n\t"
		"addl %%edx,%%r8d\n\t"
		"xorl (%%rbx,%%rcx),%%r8d\n\t"
		"andnl %%r8d,%4,%%edx\n\t"
		"vpinsrq $1,%%rax,%%xmm3,%%xmm3\n\t"
		"vpaddq %%xmm3,%%xmm0,%%xmm0\n\t"
		"vpxor (%%rbx,%%rcx),%%xmm0,%%xmm3\n\t"
		"vmovdqa %%xmm0,(%%rbx,%%rcx)\n\t"
		"vmovdqa (%%rbx,%%rdx),%%xmm1\n\t"
		"vaesenc %%xmm3,%%xmm1,%%xmm1\n\t"
		"vmovq %%xmm1,%%rax\n\t"
		"vpxor %%xmm1,%%xmm2,%%xmm2\n\t"
		"andnl %%eax,%4,%%ecx\n\t"
		"vmovdqa %%xmm2,(%%rbx,%%rdx)\n\t"
		"mulq (%%rbx,%%rcx)\n\t"
		"vmovq %%rdx,%%xmm0\n\t"
		"addl %%edx,%%r8d\n\t"
		"xorl (%%rbx,%%rcx),%%r8d\n\t"
		"andnl %%r8d,%4,%%edx\n\t"
		"vpinsrq $1,%%rax,%%xmm0,%%xmm0\n\t"
		"vpaddq %%xmm0,%%xmm3,%%xmm3\n\t"
		"vpxor (%%rbx,%%rcx),%%xmm3,%%xmm0\n\t"
		"vmovdqa %%xmm3,(%%rbx,%%rcx)\n\t"
		"subl $2,%%esi\n\t"
		"jnz 1b\n\t"
		: "+S" (i)
		: "m" (a), "m" (b), "b" (long_state), "D" (~(uint32_t)(MEMORY - AES_BLOCK_SIZE))
#else /* no BMI */
#if 1 && __AVX__ /* or actually __AES__ && __AVX__ */
		"vmovdqa %1,%%xmm0\n\t"
		"vmovdqa %2,%%xmm1\n\t"
		"vmovd %%xmm0,%%edx\n\t"
		"vmovd %%xmm0,%%r8d\n\t"
		"andl %4,%%edx\n\t"
		"1:\n\t"
		"vmovdqa (%%rbx,%%rdx),%%xmm2\n\t"
		"vaesenc %%xmm0,%%xmm2,%%xmm2\n\t"
		"vmovq %%xmm2,%%rcx\n\t"
		"vmovq %%xmm2,%%rax\n\t"
		"andl %4,%%ecx\n\t"
		"vpxor %%xmm2,%%xmm1,%%xmm1\n\t"
		"vmovdqa %%xmm1,(%%rbx,%%rdx)\n\t"
		"mulq (%%rbx,%%rcx)\n\t"
		"vmovq %%rdx,%%xmm3\n\t"
		"addl %%r8d,%%edx\n\t"
		"xorl (%%rbx,%%rcx),%%edx\n\t"
		"movl %%edx,%%r8d\n\t"
		"andl %4,%%edx\n\t"
		"vpinsrq $1,%%rax,%%xmm3,%%xmm3\n\t"
		"vpaddq %%xmm3,%%xmm0,%%xmm0\n\t"
		"vpxor (%%rbx,%%rcx),%%xmm0,%%xmm3\n\t"
		"vmovdqa %%xmm0,(%%rbx,%%rcx)\n\t"
		"vmovdqa (%%rbx,%%rdx),%%xmm1\n\t"
		"vaesenc %%xmm3,%%xmm1,%%xmm1\n\t"
		"vmovq %%xmm1,%%rcx\n\t"
		"vmovq %%xmm1,%%rax\n\t"
		"andl %4,%%ecx\n\t"
		"vpxor %%xmm1,%%xmm2,%%xmm2\n\t"
		"vmovdqa %%xmm2,(%%rbx,%%rdx)\n\t"
		"mulq (%%rbx,%%rcx)\n\t"
		"vmovq %%rdx,%%xmm0\n\t"
		"addl %%r8d,%%edx\n\t"
		"xorl (%%rbx,%%rcx),%%edx\n\t"
		"movl %%edx,%%r8d\n\t"
		"andl %4,%%edx\n\t"
		"vpinsrq $1,%%rax,%%xmm0,%%xmm0\n\t"
		"vpaddq %%xmm0,%%xmm3,%%xmm3\n\t"
		"vpxor (%%rbx,%%rcx),%%xmm3,%%xmm0\n\t"
		"vmovdqa %%xmm3,(%%rbx,%%rcx)\n\t"
#else /* __AES__ && __SSE4_1__ && !__AVX__ (assume runtime AES-NI implies SSE4.1+) */
		"movdqa %1,%%xmm0\n\t"
		"movdqa %2,%%xmm1\n\t"
		"movd %%xmm0,%%edx\n\t"
		"movd %%xmm0,%%r8d\n\t"
		"andl %4,%%edx\n\t"
		"1:\n\t"
		"movdqa (%%rbx,%%rdx),%%xmm2\n\t"
		"aesenc %%xmm0,%%xmm2\n\t"
		"movq %%xmm2,%%rcx\n\t"
		"movq %%xmm2,%%rax\n\t"
		"andl %4,%%ecx\n\t"
		"pxor %%xmm2,%%xmm1\n\t"
		"movdqa %%xmm1,(%%rbx,%%rdx)\n\t"
		"mulq (%%rbx,%%rcx)\n\t"
		"movdqa (%%rbx,%%rcx),%%xmm1\n\t"
		"movq %%rdx,%%xmm3\n\t"
		"addl %%r8d,%%edx\n\t"
		"xorl (%%rbx,%%rcx),%%edx\n\t"
		"movl %%edx,%%r8d\n\t"
		"andl %4,%%edx\n\t"
		"pinsrq $1,%%rax,%%xmm3\n\t"
		"paddq %%xmm3,%%xmm0\n\t"
		"movdqa %%xmm0,(%%rbx,%%rcx)\n\t"
		"pxor %%xmm1,%%xmm0\n\t"
		"vmovdqa (%%rbx,%%rdx),%%xmm1\n\t"
		"aesenc %%xmm0,%%xmm1\n\t"
		"movq %%xmm1,%%rcx\n\t"
		"movq %%xmm1,%%rax\n\t"
		"andl %4,%%ecx\n\t"
		"pxor %%xmm1,%%xmm2\n\t"
		"movdqa %%xmm2,(%%rbx,%%rdx)\n\t"
		"mulq (%%rbx,%%rcx)\n\t"
		"movdqa (%%rbx,%%rcx),%%xmm2\n\t"
		"movq %%rdx,%%xmm3\n\t"
		"addl %%r8d,%%edx\n\t"
		"xorl (%%rbx,%%rcx),%%edx\n\t"
		"movl %%edx,%%r8d\n\t"
		"andl %4,%%edx\n\t"
		"pinsrq $1,%%rax,%%xmm3\n\t"
		"paddq %%xmm3,%%xmm0\n\t"
		"movdqa %%xmm0,(%%rbx,%%rcx)\n\t"
		"pxor %%xmm2,%%xmm0\n\t"
#endif
		"subl $2,%%esi\n\t"
		"jnz 1b\n\t"
		: "+S" (i)
		: "m" (a), "m" (b), "b" (long_state), "D" (MEMORY - AES_BLOCK_SIZE)
#endif
		: "ax", "cx", "dx", "r8", "xmm0", "xmm1", "xmm2", "xmm3", "memory", "cc");
#else
	do {
		/* Iteration 1 */
		j = e2i(&a, MEMORY / AES_BLOCK_SIZE);
		c.v = _mm_aesenc_si128(long_state[j].v, a.v);
		xor_blocks(&b, &c);
		long_state[j].v = b.v;
		block e = a; a.v = c.v;
		/* Iteration 2 */
		j = e2i(&a, MEMORY / AES_BLOCK_SIZE);
		c.v = long_state[j].v;
		mul(&a, &c, &d);
		sum_half_blocks(&e, &d);
		long_state[j].v = e.v;
		b.v = a.v;
#if 0
		a.v = _mm_xor_si128(c.v, e.v);
#else
		a.u64[0] = c.u64[0] ^ e.u64[0];
		a.u64[1] = c.u64[1] ^ e.u64[1];
#endif
	} while (--i);
#endif
	else
#endif
	do {
		/* Iteration 1 */
		j = e2i(&a, MEMORY / AES_BLOCK_SIZE);
		c = long_state[j];
		oaes_encryption_round(a.b, c.b);
		xor_blocks(&b, &c);
		long_state[j] = b;
		/* Iteration 2 */
		j = e2i(&c, MEMORY / AES_BLOCK_SIZE);
		b = long_state[j];
		mul(&b, &c, &d);
		sum_half_blocks(&a, &d);
		long_state[j] = a;
		a.u64[0] ^= b.u64[0];
		a.u64[1] ^= b.u64[1];
		b = c;
	} while (--i);

	memcpy(text, state.init, INIT_SIZE_BYTE);
	if (oaes_key_import_data(aes_ctx, &state.b[32], AES_KEY_SIZE))
		goto fail;
#if MBEDTLS_AESNI_HAVE_CODE == 2
	aes_exp_data = oaes_get_exp_data(aes_ctx);
	if (have_aesni)
	for (i = 0; i < MEMORY / INIT_SIZE_BYTE; i++) {
		for (j = 0; j < INIT_SIZE_BLK; j++)
			xor_blocks(&text[j], &long_state[i * INIT_SIZE_BLK + j]);
		aesni_pseudo_encrypt_ecb(aes_exp_data, text, text);
	}
	else
#endif
	for (i = 0; i < MEMORY / INIT_SIZE_BYTE; i++) {
		for (j = 0; j < INIT_SIZE_BLK; j++) {
			xor_blocks(&text[j], &long_state[i * INIT_SIZE_BLK + j]);
			oaes_pseudo_encrypt_ecb(aes_ctx, text[j].b);
		}
	}
	memcpy(state.init, text, INIT_SIZE_BYTE);
	hash_permutation(&state);
	extra_hashes[state.b[0] & 3](&state, 200, hash);
	oaes_free(&aes_ctx);
	return 0;

fail:
	oaes_free(&aes_ctx);
	return -1;
}

int cn_slow_hash_aesni(void)
{
#if MBEDTLS_AESNI_HAVE_CODE == 2
	return mbedtls_aesni_has_support(MBEDTLS_AESNI_AES);
#else
	return 0;
#endif
}
