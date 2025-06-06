/*
 * This file contains the core of a bitslice DES implementation for x86/SSE2.
 * It is part of John the Ripper password cracker,
 * Copyright (c) 2000-2001,2005,2006,2008,2011,2012,2015 by Solar Designer
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.  (This is a heavily cut-down "BSD license".)
 *
 * Gate counts per S-box: 49 44 46 33 48 46 46 41
 * Average: 44.125
 *
 * The Boolean expressions corresponding to DES S-boxes have been generated
 * by Roman Rusakov <roman_rus at openwall.com> for use in Openwall's
 * John the Ripper password cracker: https://www.openwall.com/john/
 * Being mathematical formulas, they are not copyrighted and are free for reuse
 * by anyone.
 *
 * The x86/SSE2 code for the S-boxes was generated by Solar Designer using a
 * Perl script and then hand-optimized - originally for MMX, then converted to
 * SSE2.  Instruction scheduling was not re-done for SSE2-capable CPUs yet;
 * doing so may provide further speedup.
 *
 * The effort has been sponsored by Rapid7: https://www.rapid7.com
 *
 * Addition of single DES encryption with no salt by Deepika Dutta Mishra
 * <dipikadutta at gmail.com> in 2012, no rights reserved.
 */

#include "arch.h"

/*
 * Some broken systems don't offer section alignments larger than 4 bytes,
 * while for the SSE code we need at least a 16 byte alignment.  ALIGN_FIX
 * is here to work around this issue when we happen to get bad addresses.
 */
#ifndef ALIGN_FIX
#ifdef ALIGN_LOG
#define DO_ALIGN(log)			.align log
#else
#define DO_ALIGN(log)			.align 1 << log
#endif
#else
#ifdef ALIGN_LOG
#define DO_ALIGN(log)			.align log; .space ALIGN_FIX
#else
#define DO_ALIGN(log)			.align 1 << log; .space ALIGN_FIX
#endif
#endif

#if DES_BS_ASM

#ifdef UNDERSCORES
#define DES_bs_all			_DES_bs_all
#define DES_bs_init_asm			_DES_bs_init_asm
#define DES_bs_crypt			_DES_bs_crypt
#define DES_bs_crypt_25			_DES_bs_crypt_25
#define DES_bs_crypt_LM			_DES_bs_crypt_LM
#define DES_bs_crypt_plain		_DES_bs_crypt_plain
#define DES_bs_P			_DES_bs_P
#endif

#ifdef __sun
/* Sun's assembler doesn't recognize .space */
#define DO_SPACE(size)			.zero size
#else
/* Mac OS X assembler doesn't recognize .zero */
#define DO_SPACE(size)			.space size
#endif

/* Sun's assembler can't multiply, but at least it can add... */
#define nptr(n)				n+n+n+n
#define nvec(n)				n+n+n+n+n+n+n+n+n+n+n+n+n+n+n+n

#ifdef BSD
.data
#else
.bss
#endif

.globl DES_bs_P
DO_ALIGN(6)
DES_bs_P:
DO_SPACE(nvec(64))

.globl DES_bs_all
DO_ALIGN(6)
DES_bs_all:
DES_bs_all_KSp:
DO_SPACE(nptr(0x300))
DES_bs_all_KS_p:
DES_bs_all_KS_v:
DO_SPACE(nvec(0x300))
DES_bs_all_E:
DO_SPACE(nptr(96))
DES_bs_all_K:
DO_SPACE(nvec(56))
DES_bs_all_B:
DO_SPACE(nvec(64))
DES_bs_all_tmp:
DO_SPACE(nvec(16))
DES_bs_all_xkeys:
DO_SPACE(nvec(64))
DES_bs_all_pxkeys:
DO_SPACE(nptr(128))
DES_bs_all_keys_changed:
DO_SPACE(4)
DES_bs_all_salt:
DO_SPACE(4)
DES_bs_all_Ens:
DO_SPACE(nptr(48))

#define E(i)				DES_bs_all_E+nptr(i)
#define B(i)				DES_bs_all_B+nvec(i)
#define tmp_at(i)			DES_bs_all_tmp+nvec(i)
#define P(i)				DES_bs_P+nvec(i)
#define pnot				tmp_at(0)

#define S1(out1, out2, out3, out4) \
	movdqa %xmm0,tmp_at(1); \
	movdqa %xmm5,%xmm7; \
	movdqa %xmm4,tmp_at(4); \
	movdqa %xmm2,%xmm6; \
	movdqa %xmm1,tmp_at(2); \
	por %xmm2,%xmm7; \
	movdqa %xmm3,tmp_at(3); \
	pxor %xmm0,%xmm6; \
	movdqa %xmm7,tmp_at(5); \
	movdqa %xmm6,%xmm1; \
	pandn %xmm0,%xmm4; \
	pand %xmm7,%xmm1; \
	movdqa %xmm1,%xmm7; \
	por %xmm5,%xmm7; \
	pxor %xmm3,%xmm1; \
	pxor %xmm4,%xmm3; \
	movdqa %xmm1,tmp_at(6); \
	movdqa %xmm3,%xmm1; \
	pandn tmp_at(6),%xmm3; \
	movdqa %xmm3,tmp_at(7); \
	movdqa %xmm5,%xmm3; \
	por %xmm0,%xmm5; \
	pxor tmp_at(4),%xmm3; \
	movdqa %xmm3,tmp_at(8); \
	movdqa %xmm5,%xmm0; \
	pandn %xmm3,%xmm6; \
	pxor %xmm2,%xmm3; \
	pandn %xmm2,%xmm4; \
	pandn %xmm1,%xmm3; \
	pxor %xmm3,%xmm7; \
	movdqa tmp_at(7),%xmm3; \
	pandn tmp_at(3),%xmm5; \
	por %xmm7,%xmm0; \
	pandn %xmm7,%xmm3; \
	movdqa %xmm3,tmp_at(9); \
	pand tmp_at(5),%xmm7; \
	movdqa tmp_at(6),%xmm3; \
	movdqa %xmm0,%xmm2; \
	pxor %xmm1,%xmm2; \
	pandn tmp_at(4),%xmm3; \
	pandn %xmm2,%xmm4; \
	movdqa tmp_at(2),%xmm2; \
	pxor %xmm4,%xmm7; \
	pxor tmp_at(8),%xmm4; \
	pxor %xmm3,%xmm5; \
	por %xmm3,%xmm4; \
	pxor tmp_at(1),%xmm4; \
	pxor %xmm0,%xmm3; \
	pandn %xmm3,%xmm2; \
	pxor tmp_at(5),%xmm0; \
	movdqa tmp_at(7),%xmm3; \
	por tmp_at(2),%xmm3; \
	pxor pnot,%xmm7; \
	pxor out1,%xmm3; \
	pxor %xmm7,%xmm2; \
	pxor tmp_at(5),%xmm4; \
	pxor out3,%xmm2; \
	pxor %xmm4,%xmm7; \
	pxor %xmm7,%xmm3; \
	movdqa %xmm3,out1; \
	por %xmm6,%xmm5; \
	por tmp_at(8),%xmm7; \
	por %xmm5,%xmm0; \
	pxor out2,%xmm7; \
	pxor %xmm4,%xmm0; \
	pxor %xmm0,%xmm7; \
	por tmp_at(4),%xmm1; \
	movdqa tmp_at(2),%xmm3; \
	pand tmp_at(9),%xmm4; \
	pandn %xmm1,%xmm0; \
	pxor %xmm0,%xmm4; \
	por tmp_at(9),%xmm3; \
	por tmp_at(2),%xmm4; \
	movdqa %xmm2,out3; \
	pxor %xmm3,%xmm7; \
	pxor %xmm5,%xmm4; \
	pxor out4,%xmm4; \
	movdqa %xmm7,out2; \
	movdqa %xmm4,out4

#define S2(out1, out2, out3, out4) \
	movdqa %xmm2,tmp_at(2); \
	movdqa %xmm1,tmp_at(1); \
	movdqa %xmm5,%xmm2; \
	movdqa %xmm4,tmp_at(4); \
	pandn %xmm0,%xmm2; \
	movdqa %xmm3,tmp_at(3); \
	pandn %xmm4,%xmm2; \
	movdqa %xmm0,%xmm6; \
	movdqa %xmm2,%xmm7; \
	pxor pnot,%xmm0; \
	por %xmm1,%xmm7; \
	pxor %xmm4,%xmm1; \
	movdqa %xmm7,tmp_at(5); \
	pand %xmm1,%xmm6; \
	movdqa %xmm5,%xmm7; \
	pxor %xmm4,%xmm6; \
	pandn %xmm1,%xmm7; \
	movdqa %xmm3,%xmm4; \
	pxor %xmm7,%xmm2; \
	pandn %xmm6,%xmm7; \
	pxor %xmm5,%xmm1; \
	movdqa %xmm7,tmp_at(7); \
	movdqa %xmm5,%xmm7; \
	pand tmp_at(2),%xmm5; \
	pand tmp_at(5),%xmm2; \
	movdqa %xmm5,tmp_at(8); \
	pandn %xmm2,%xmm5; \
	pand tmp_at(2),%xmm2; \
	movdqa tmp_at(8),%xmm7; \
	pandn tmp_at(3),%xmm5; \
	pandn %xmm1,%xmm7; \
	pxor %xmm2,%xmm0; \
	movdqa %xmm7,%xmm3; \
	pxor %xmm0,%xmm3; \
	pxor out2,%xmm5; \
	pandn tmp_at(1),%xmm7; \
	pxor %xmm6,%xmm7; \
	pxor %xmm3,%xmm5; \
	movdqa %xmm7,%xmm6; \
	movdqa %xmm5,out2; \
	movdqa tmp_at(7),%xmm5; \
	pandn tmp_at(5),%xmm4; \
	pandn %xmm0,%xmm6; \
	pxor tmp_at(5),%xmm3; \
	movdqa %xmm1,%xmm0; \
	pxor %xmm4,%xmm6; \
	pxor tmp_at(2),%xmm0; \
	pxor %xmm0,%xmm6; \
	movdqa %xmm0,%xmm4; \
	pxor out1,%xmm6; \
	pandn tmp_at(1),%xmm0; \
	pxor tmp_at(4),%xmm2; \
	pxor %xmm3,%xmm0; \
	movdqa %xmm6,out1; \
	por %xmm1,%xmm3; \
	por tmp_at(8),%xmm0; \
	pxor %xmm4,%xmm0; \
	movdqa %xmm0,%xmm4; \
	pandn tmp_at(2),%xmm0; \
	movdqa tmp_at(3),%xmm6; \
	pxor tmp_at(7),%xmm0; \
	por %xmm7,%xmm0; \
	por %xmm6,%xmm5; \
	pxor %xmm0,%xmm2; \
	pandn %xmm2,%xmm7; \
	por %xmm2,%xmm6; \
	pxor out4,%xmm7; \
	pxor %xmm4,%xmm6; \
	pxor out3,%xmm6; \
	pxor %xmm5,%xmm7; \
	pxor %xmm3,%xmm7; \
	movdqa %xmm6,out3; \
	movdqa %xmm7,out4

#define S3(out1, out2, out3, out4) \
	movdqa %xmm0,tmp_at(1); \
	movdqa %xmm1,tmp_at(2); \
	movdqa %xmm0,%xmm7; \
	pandn %xmm0,%xmm1; \
	movdqa %xmm2,tmp_at(3); \
	movdqa %xmm5,%xmm0; \
	pxor %xmm2,%xmm0; \
	movdqa %xmm4,tmp_at(4); \
	movdqa %xmm5,%xmm2; \
	por %xmm0,%xmm1; \
	pxor %xmm3,%xmm2; \
	movdqa %xmm0,%xmm4; \
	movdqa %xmm5,%xmm6; \
	pandn %xmm2,%xmm7; \
	pxor tmp_at(2),%xmm4; \
	movdqa %xmm7,tmp_at(5); \
	pxor %xmm1,%xmm7; \
	pandn %xmm4,%xmm6; \
	movdqa %xmm7,tmp_at(6); \
	pxor %xmm6,%xmm1; \
	pand %xmm0,%xmm2; \
	movdqa %xmm1,%xmm6; \
	movdqa %xmm3,%xmm0; \
	pandn %xmm7,%xmm6; \
	pand %xmm5,%xmm7; \
	pand %xmm3,%xmm5; \
	por %xmm3,%xmm7; \
	pand tmp_at(1),%xmm7; \
	movdqa tmp_at(4),%xmm3; \
	pandn tmp_at(6),%xmm3; \
	pxor %xmm4,%xmm7; \
	pxor tmp_at(1),%xmm0; \
	movdqa %xmm7,tmp_at(7); \
	pxor %xmm3,%xmm7; \
	movdqa tmp_at(2),%xmm3; \
	pxor out4,%xmm7; \
	pxor %xmm0,%xmm1; \
	movdqa %xmm7,out4; \
	movdqa tmp_at(3),%xmm7; \
	por tmp_at(3),%xmm1; \
	pandn %xmm1,%xmm2; \
	por tmp_at(5),%xmm0; \
	movdqa %xmm0,%xmm1; \
	pandn %xmm5,%xmm3; \
	pandn tmp_at(7),%xmm1; \
	por %xmm4,%xmm5; \
	pxor %xmm3,%xmm1; \
	por tmp_at(2),%xmm7; \
	movdqa tmp_at(3),%xmm3; \
	pandn %xmm1,%xmm3; \
	pxor %xmm4,%xmm0; \
	pandn %xmm5,%xmm3; \
	movdqa tmp_at(4),%xmm5; \
	pxor tmp_at(1),%xmm3; \
	pand %xmm2,%xmm5; \
	pxor pnot,%xmm0; \
	pxor %xmm5,%xmm3; \
	movdqa %xmm7,%xmm5; \
	pxor out2,%xmm3; \
	pandn tmp_at(4),%xmm6; \
	pandn tmp_at(6),%xmm7; \
	pxor %xmm0,%xmm6; \
	movdqa %xmm3,out2; \
	pxor tmp_at(1),%xmm2; \
	por tmp_at(4),%xmm1; \
	por %xmm2,%xmm0; \
	pxor tmp_at(6),%xmm5; \
	pxor %xmm1,%xmm0; \
	pxor out1,%xmm6; \
	pxor out3,%xmm5; \
	pxor tmp_at(7),%xmm0; \
	pxor %xmm7,%xmm6; \
	pxor %xmm5,%xmm0; \
	movdqa %xmm6,out1; \
	movdqa %xmm0,out3

#define S4(out1, out2, out3, out4) \
	movdqa %xmm1,%xmm7; \
	pxor %xmm2,%xmm0; \
	por %xmm3,%xmm1; \
	pxor %xmm4,%xmm2; \
	movdqa %xmm5,tmp_at(2); \
	pxor %xmm4,%xmm1; \
	movdqa %xmm7,%xmm6; \
	movdqa %xmm7,%xmm5; \
	pandn %xmm2,%xmm7; \
	pandn %xmm2,%xmm1; \
	por %xmm7,%xmm4; \
	pxor %xmm3,%xmm7; \
	movdqa %xmm7,%xmm6; \
	por %xmm0,%xmm7; \
	pxor %xmm5,%xmm3; \
	movdqa %xmm1,tmp_at(3); \
	pandn %xmm7,%xmm1; \
	movdqa %xmm1,%xmm7; \
	pxor %xmm5,%xmm1; \
	pand %xmm1,%xmm6; \
	movdqa %xmm6,%xmm5; \
	pxor %xmm1,%xmm0; \
	pandn %xmm2,%xmm6; \
	pandn %xmm0,%xmm6; \
	pxor %xmm0,%xmm4; \
	movdqa %xmm3,%xmm0; \
	pandn %xmm4,%xmm3; \
	movdqa tmp_at(2),%xmm2; \
	pxor %xmm7,%xmm3; \
	pxor tmp_at(3),%xmm6; \
	movdqa %xmm6,%xmm7; \
	pandn %xmm2,%xmm6; \
	pxor out1,%xmm6; \
	pandn %xmm7,%xmm2; \
	pxor out2,%xmm2; \
	pxor %xmm3,%xmm6; \
	pxor pnot,%xmm3; \
	pxor %xmm3,%xmm2; \
	pxor %xmm7,%xmm3; \
	movdqa %xmm6,out1; \
	pandn %xmm3,%xmm0; \
	por %xmm5,%xmm0; \
	movdqa %xmm2,out2; \
	movdqa tmp_at(2),%xmm3; \
	por %xmm1,%xmm3; \
	pand tmp_at(2),%xmm1; \
	pxor %xmm4,%xmm0; \
	pxor %xmm0,%xmm3; \
	pxor out3,%xmm3; \
	pxor %xmm1,%xmm0; \
	movdqa %xmm3,out3; \
	pxor out4,%xmm0; \
	movdqa %xmm0,out4

#define S5(out1, out2, out3, out4) \
	movdqa %xmm2,tmp_at(3); \
	movdqa %xmm0,tmp_at(1); \
	por %xmm0,%xmm2; \
	movdqa %xmm5,%xmm6; \
	movdqa %xmm2,tmp_at(4); \
	pandn %xmm2,%xmm5; \
	movdqa %xmm2,%xmm7; \
	movdqa %xmm5,%xmm2; \
	pxor %xmm0,%xmm5; \
	movdqa %xmm3,%xmm7; \
	movdqa %xmm5,tmp_at(5); \
	pxor tmp_at(3),%xmm5; \
	movdqa %xmm1,tmp_at(2); \
	por %xmm5,%xmm0; \
	por %xmm3,%xmm5; \
	pandn %xmm2,%xmm3; \
	pxor tmp_at(3),%xmm3; \
	movdqa %xmm3,tmp_at(6); \
	movdqa %xmm0,%xmm1; \
	pand %xmm4,%xmm3; \
	pxor %xmm0,%xmm3; \
	pand %xmm7,%xmm0; \
	pxor %xmm7,%xmm3; \
	movdqa %xmm3,tmp_at(3); \
	pxor %xmm3,%xmm6; \
	movdqa %xmm6,%xmm2; \
	por tmp_at(5),%xmm6; \
	movdqa %xmm6,%xmm3; \
	pand %xmm4,%xmm6; \
	movdqa %xmm6,tmp_at(7); \
	pxor tmp_at(5),%xmm6; \
	pxor %xmm6,%xmm0; \
	movdqa tmp_at(1),%xmm6; \
	movdqa %xmm0,tmp_at(8); \
	pandn %xmm3,%xmm6; \
	movdqa tmp_at(2),%xmm0; \
	movdqa %xmm6,%xmm3; \
	pxor tmp_at(6),%xmm6; \
	pxor %xmm5,%xmm4; \
	pandn %xmm4,%xmm6; \
	pxor pnot,%xmm6; \
	pandn %xmm6,%xmm0; \
	pxor tmp_at(3),%xmm0; \
	movdqa tmp_at(7),%xmm6; \
	pandn tmp_at(6),%xmm6; \
	pxor out3,%xmm0; \
	pxor %xmm4,%xmm3; \
	movdqa %xmm0,out3; \
	por tmp_at(8),%xmm3; \
	movdqa tmp_at(6),%xmm0; \
	pandn %xmm3,%xmm6; \
	pand tmp_at(6),%xmm1; \
	pand %xmm6,%xmm2; \
	movdqa %xmm6,%xmm3; \
	pandn %xmm5,%xmm6; \
	pxor %xmm4,%xmm2; \
	por %xmm2,%xmm1; \
	pxor tmp_at(4),%xmm3; \
	pxor tmp_at(7),%xmm1; \
	pand %xmm2,%xmm7; \
	pand tmp_at(2),%xmm1; \
	pxor tmp_at(1),%xmm7; \
	pxor tmp_at(8),%xmm1; \
	pxor %xmm7,%xmm3; \
	por tmp_at(2),%xmm6; \
	pxor out4,%xmm1; \
	movdqa %xmm1,out4; \
	pxor %xmm5,%xmm0; \
	pxor tmp_at(5),%xmm2; \
	pxor %xmm3,%xmm6; \
	pandn %xmm0,%xmm3; \
	pand tmp_at(2),%xmm5; \
	pxor %xmm2,%xmm3; \
	pxor out2,%xmm5; \
	pxor %xmm5,%xmm3; \
	pxor out1,%xmm6; \
	movdqa %xmm3,out2; \
	movdqa %xmm6,out1

#define S6(out1, out2, out3, out4) \
	movdqa %xmm4,tmp_at(2); \
	pxor %xmm1,%xmm4; \
	movdqa %xmm5,tmp_at(3); \
	por %xmm1,%xmm5; \
	movdqa %xmm2,%xmm7; \
	pand %xmm0,%xmm5; \
	pxor %xmm0,%xmm2; \
	movdqa %xmm0,tmp_at(1); \
	pxor %xmm5,%xmm4; \
	movdqa %xmm4,tmp_at(4); \
	pxor tmp_at(3),%xmm4; \
	movdqa %xmm4,%xmm6; \
	pandn tmp_at(2),%xmm4; \
	pand %xmm0,%xmm6; \
	movdqa %xmm6,tmp_at(5); \
	pxor %xmm1,%xmm6; \
	movdqa %xmm6,tmp_at(6); \
	por %xmm2,%xmm6; \
	movdqa %xmm6,tmp_at(7); \
	pxor tmp_at(4),%xmm6; \
	movdqa %xmm6,%xmm0; \
	pand %xmm7,%xmm6; \
	movdqa %xmm6,tmp_at(8); \
	movdqa tmp_at(3),%xmm6; \
	por %xmm1,%xmm2; \
	pandn tmp_at(8),%xmm6; \
	movdqa %xmm6,tmp_at(9); \
	movdqa tmp_at(6),%xmm6; \
	por %xmm4,%xmm6; \
	movdqa %xmm6,tmp_at(6); \
	pxor tmp_at(9),%xmm6; \
	movdqa %xmm6,tmp_at(10); \
	pand %xmm3,%xmm6; \
	pxor out4,%xmm6; \
	pxor %xmm0,%xmm6; \
	por tmp_at(1),%xmm0; \
	movdqa %xmm6,out4; \
	movdqa tmp_at(7),%xmm6; \
	pxor %xmm1,%xmm6; \
	movdqa %xmm3,%xmm1; \
	movdqa %xmm6,tmp_at(7); \
	pandn tmp_at(3),%xmm6; \
	pxor %xmm7,%xmm6; \
	movdqa tmp_at(8),%xmm7; \
	movdqa %xmm6,tmp_at(12); \
	pandn tmp_at(2),%xmm7; \
	pand tmp_at(6),%xmm0; \
	por %xmm6,%xmm7; \
	pxor %xmm6,%xmm0; \
	movdqa tmp_at(9),%xmm6; \
	por %xmm3,%xmm4; \
	pandn %xmm0,%xmm6; \
	por %xmm7,%xmm5; \
	pxor %xmm4,%xmm6; \
	pxor tmp_at(4),%xmm0; \
	pxor out3,%xmm6; \
	pxor %xmm2,%xmm5; \
	movdqa %xmm6,out3; \
	movdqa tmp_at(5),%xmm6; \
	pandn tmp_at(2),%xmm0; \
	pxor pnot,%xmm2; \
	pxor tmp_at(7),%xmm2; \
	pxor tmp_at(3),%xmm6; \
	pxor out2,%xmm5; \
	movdqa tmp_at(12),%xmm4; \
	pxor %xmm2,%xmm0; \
	pxor tmp_at(1),%xmm4; \
	pxor tmp_at(10),%xmm5; \
	pand %xmm6,%xmm4; \
	pandn %xmm0,%xmm3; \
	pxor out1,%xmm4; \
	pandn %xmm7,%xmm1; \
	pxor tmp_at(8),%xmm4; \
	pxor %xmm2,%xmm1; \
	pxor %xmm3,%xmm5; \
	movdqa %xmm5,out2; \
	pxor %xmm1,%xmm4; \
	movdqa %xmm4,out1

#define S7(out1, out2, out3, out4) \
	movdqa %xmm0,tmp_at(1); \
	movdqa %xmm4,tmp_at(3); \
	movdqa %xmm4,%xmm0; \
	pxor %xmm3,%xmm4; \
	movdqa %xmm5,tmp_at(4); \
	movdqa %xmm4,%xmm7; \
	movdqa %xmm3,tmp_at(2); \
	pxor %xmm2,%xmm4; \
	movdqa %xmm4,tmp_at(5); \
	pand %xmm5,%xmm4; \
	movdqa %xmm7,%xmm5; \
	pxor tmp_at(4),%xmm5; \
	pand %xmm3,%xmm7; \
	movdqa %xmm7,tmp_at(6); \
	movdqa %xmm7,%xmm6; \
	pxor %xmm1,%xmm7; \
	pand tmp_at(4),%xmm6; \
	pxor %xmm2,%xmm6; \
	movdqa %xmm7,tmp_at(7); \
	movdqa tmp_at(1),%xmm3; \
	movdqa %xmm6,%xmm0; \
	por %xmm7,%xmm6; \
	pand %xmm4,%xmm7; \
	pxor %xmm5,%xmm6; \
	pandn %xmm3,%xmm7; \
	pxor %xmm4,%xmm0; \
	pxor out4,%xmm7; \
	pxor %xmm5,%xmm4; \
	pxor %xmm6,%xmm7; \
	movdqa %xmm7,out4; \
	pandn tmp_at(2),%xmm4; \
	por tmp_at(6),%xmm6; \
	movdqa tmp_at(5),%xmm7; \
	pandn tmp_at(3),%xmm7; \
	pandn tmp_at(7),%xmm4; \
	movdqa %xmm7,tmp_at(9); \
	por tmp_at(7),%xmm7; \
	pandn tmp_at(5),%xmm5; \
	pxor %xmm0,%xmm7; \
	pxor tmp_at(3),%xmm0; \
	pxor %xmm4,%xmm0; \
	movdqa tmp_at(1),%xmm4; \
	pand %xmm0,%xmm2; \
	por %xmm2,%xmm6; \
	pxor %xmm5,%xmm6; \
	pandn %xmm6,%xmm3; \
	movdqa %xmm6,%xmm5; \
	pxor %xmm7,%xmm3; \
	pxor %xmm6,%xmm7; \
	por %xmm0,%xmm6; \
	pxor out1,%xmm3; \
	pand tmp_at(4),%xmm6; \
	pxor pnot,%xmm5; \
	pand %xmm6,%xmm1; \
	pxor out3,%xmm0; \
	pxor %xmm7,%xmm1; \
	movdqa %xmm3,out1; \
	movdqa %xmm4,%xmm3; \
	pxor tmp_at(3),%xmm7; \
	por %xmm1,%xmm2; \
	pxor %xmm6,%xmm2; \
	por %xmm2,%xmm7; \
	pand %xmm7,%xmm4; \
	pxor %xmm6,%xmm7; \
	por tmp_at(9),%xmm7; \
	pxor %xmm5,%xmm7; \
	pxor out2,%xmm1; \
	pandn %xmm7,%xmm3; \
	pxor %xmm4,%xmm0; \
	movdqa %xmm0,out3; \
	pxor %xmm3,%xmm1; \
	movdqa %xmm1,out2

#define S8(out1, out2, out3, out4) \
	movdqa %xmm2,%xmm7; \
	movdqa %xmm1,tmp_at(1); \
	pandn %xmm2,%xmm1; \
	movdqa %xmm2,tmp_at(2); \
	pandn %xmm4,%xmm2; \
	movdqa %xmm3,tmp_at(3); \
	pxor %xmm3,%xmm2; \
	movdqa %xmm4,tmp_at(4); \
	movdqa %xmm1,%xmm3; \
	movdqa %xmm5,tmp_at(5); \
	movdqa %xmm2,%xmm4; \
	movdqa %xmm2,%xmm5; \
	pandn tmp_at(1),%xmm4; \
	pand %xmm0,%xmm2; \
	pandn tmp_at(1),%xmm7; \
	pandn %xmm2,%xmm1; \
	pxor tmp_at(4),%xmm7; \
	movdqa %xmm4,%xmm6; \
	por %xmm0,%xmm4; \
	movdqa %xmm7,tmp_at(6); \
	pand %xmm4,%xmm7; \
	pxor pnot,%xmm5; \
	por %xmm7,%xmm2; \
	pxor %xmm7,%xmm5; \
	pandn tmp_at(2),%xmm4; \
	movdqa tmp_at(5),%xmm7; \
	pxor %xmm4,%xmm5; \
	por %xmm1,%xmm7; \
	pxor %xmm5,%xmm3; \
	pxor %xmm3,%xmm7; \
	pxor %xmm0,%xmm3; \
	pxor out2,%xmm7; \
	movdqa %xmm7,out2; \
	pxor tmp_at(1),%xmm5; \
	movdqa %xmm3,%xmm4; \
	pand tmp_at(4),%xmm3; \
	pxor %xmm5,%xmm3; \
	por tmp_at(3),%xmm5; \
	pxor %xmm3,%xmm6; \
	pxor tmp_at(6),%xmm5; \
	pxor %xmm2,%xmm3; \
	pxor %xmm6,%xmm5; \
	por tmp_at(1),%xmm3; \
	pxor %xmm5,%xmm0; \
	pxor %xmm4,%xmm3; \
	por tmp_at(3),%xmm4; \
	pxor tmp_at(4),%xmm3; \
	pand tmp_at(5),%xmm2; \
	pandn %xmm3,%xmm4; \
	pand tmp_at(5),%xmm0; \
	pxor %xmm6,%xmm0; \
	por %xmm1,%xmm4; \
	pxor out4,%xmm0; \
	pxor %xmm4,%xmm5; \
	pxor out3,%xmm2; \
	por tmp_at(5),%xmm5; \
	pxor out1,%xmm5; \
	pxor %xmm3,%xmm2; \
	pxor %xmm6,%xmm5; \
	movdqa %xmm0,out4; \
	movdqa %xmm2,out3; \
	movdqa %xmm5,out1

#define a1				%xmm0
#define a2				%xmm1
#define a3				%xmm2
#define a4				%xmm3
#define a5				%xmm4
#define a6				%xmm5

#define zero				%xmm5

#define DES_bs_clear_block_8(i) \
	movdqa zero,B(i); \
	movdqa zero,B(i + 1); \
	movdqa zero,B(i + 2); \
	movdqa zero,B(i + 3); \
	movdqa zero,B(i + 4); \
	movdqa zero,B(i + 5); \
	movdqa zero,B(i + 6); \
	movdqa zero,B(i + 7)

#define DES_bs_clear_block \
	DES_bs_clear_block_8(0); \
	DES_bs_clear_block_8(8); \
	DES_bs_clear_block_8(16); \
	DES_bs_clear_block_8(24); \
	DES_bs_clear_block_8(32); \
	DES_bs_clear_block_8(40); \
	DES_bs_clear_block_8(48); \
	DES_bs_clear_block_8(56)

#define k_ptr				%edx
#define K(i)				nvec(i)(k_ptr)
#define k(i)				nptr(i)(k_ptr)

#define tmp1				%ecx
#define tmp2				%esi

#define xor_E(i) \
	movl E(i),tmp1; \
	movdqa K(i),a1; \
	movl E(i + 1),tmp2; \
	movdqa K(i + 1),a2; \
	pxor (tmp1),a1; \
	pxor (tmp2),a2; \
	movl E(i + 2),tmp1; \
	movdqa K(i + 2),a3; \
	movl E(i + 3),tmp2; \
	movdqa K(i + 3),a4; \
	pxor (tmp1),a3; \
	pxor (tmp2),a4; \
	movl E(i + 4),tmp1; \
	movdqa K(i + 4),a5; \
	movl E(i + 5),tmp2; \
	movdqa K(i + 5),a6; \
	pxor (tmp1),a5; \
	pxor (tmp2),a6

#define xor_B(b1, k1, b2, k2, b3, k3, b4, k4, b5, k5, b6, k6) \
	movdqa B(b1),a1; \
	movdqa B(b2),a2; \
	pxor K(k1),a1; \
	movdqa B(b3),a3; \
	pxor K(k2),a2; \
	movdqa B(b4),a4; \
	pxor K(k3),a3; \
	movdqa B(b5),a5; \
	pxor K(k4),a4; \
	movdqa B(b6),a6; \
	pxor K(k5),a5; \
	pxor K(k6),a6

#define xor_B_KS_p_prefix(b1, k1, b2, k2, b3, k3, b4, k4, k6) \
	movl k(k1),tmp1; \
	movl k(k2),tmp2; \
	movdqa B(b1),a1; \
	movdqa B(b2),a2; \
	pxor (tmp1),a1; \
	movl k(k3),tmp1; \
	pxor (tmp2),a2; \
	movl k(k4),tmp2; \
	movdqa B(b3),a3; \
	movdqa B(b4),a4; \
	pxor (tmp1),a3; \
	movl k(k6),tmp1; \
	pxor (tmp2),a4

#define xor_B_KS_p_suffix(b5, k5) \
	movl k(k5),tmp2; \
	movdqa B(b5),a5; \
	pxor (tmp1),a6; \
	pxor (tmp2),a5

#define xor_B_KS_p(b1, k1, b2, k2, b3, k3, b4, k4, b5, k5, b6, k6) \
	xor_B_KS_p_prefix(b1, k1, b2, k2, b3, k3, b4, k4, k6); \
	movdqa B(b6),a6; \
	xor_B_KS_p_suffix(b5, k5)

#define xor_B_KS_p_special(b1, k1, b2, k2, b3, k3, b4, k4, b5, k5, k6) \
	xor_B_KS_p_prefix(b1, k1, b2, k2, b3, k3, b4, k4, k6); \
	xor_B_KS_p_suffix(b5, k5)

#define mask01				tmp_at(15)

#define v_ptr				%eax
#define V(i)				nvec(i)(v_ptr)

#if 1
#define SHLB1(reg)			paddb reg,reg
#else
#define SHLB1(reg)			psllq $1,reg
#endif

#define FINALIZE_NEXT_KEY_BITS_0_6 \
	movdqa mask01,%xmm7; \
\
	movdqa V(0),%xmm0; \
	movdqa V(1),%xmm1; \
	movdqa V(2),%xmm2; \
	movdqa V(3),%xmm3; \
	pand %xmm7,%xmm0; \
	pand %xmm7,%xmm1; \
	pand %xmm7,%xmm2; \
	pand %xmm7,%xmm3; \
	SHLB1(%xmm1); \
	psllq $2,%xmm2; \
	psllq $3,%xmm3; \
	por %xmm0,%xmm1; \
	por %xmm2,%xmm3; \
	movdqa V(4),%xmm4; \
	movdqa V(5),%xmm5; \
	por %xmm1,%xmm3; \
	pand %xmm7,%xmm4; \
	pand %xmm7,%xmm5; \
	movdqa V(6),%xmm6; \
	movdqa V(7),%xmm0; \
	psllq $4,%xmm4; \
	pand %xmm7,%xmm6; \
	pand %xmm7,%xmm0; \
	psllq $5,%xmm5; \
	psllq $6,%xmm6; \
	psllq $7,%xmm0; \
	por %xmm4,%xmm5; \
	por %xmm6,%xmm3; \
	por %xmm5,%xmm0; \
	movdqa V(1),%xmm1; \
	por %xmm3,%xmm0; \
	SHLB1(%xmm7); \
	movdqa %xmm0,K(0); \
\
	movdqa V(0),%xmm0; \
	movdqa V(2),%xmm2; \
	movdqa V(3),%xmm3; \
	pand %xmm7,%xmm0; \
	pand %xmm7,%xmm1; \
	pand %xmm7,%xmm2; \
	pand %xmm7,%xmm3; \
	psrlq $1,%xmm0; \
	SHLB1(%xmm2); \
	psllq $2,%xmm3; \
	por %xmm0,%xmm1; \
	por %xmm2,%xmm3; \
	movdqa V(4),%xmm4; \
	movdqa V(5),%xmm5; \
	por %xmm1,%xmm3; \
	pand %xmm7,%xmm4; \
	pand %xmm7,%xmm5; \
	movdqa V(6),%xmm6; \
	movdqa V(7),%xmm0; \
	psllq $3,%xmm4; \
	pand %xmm7,%xmm6; \
	pand %xmm7,%xmm0; \
	psllq $4,%xmm5; \
	psllq $5,%xmm6; \
	psllq $6,%xmm0; \
	por %xmm4,%xmm5; \
	por %xmm6,%xmm3; \
	por %xmm5,%xmm0; \
	movdqa V(1),%xmm1; \
	por %xmm3,%xmm0; \
	SHLB1(%xmm7); \
	movdqa %xmm0,K(1); \
\
	movdqa V(0),%xmm0; \
	movdqa V(2),%xmm2; \
	movdqa V(3),%xmm3; \
	pand %xmm7,%xmm0; \
	pand %xmm7,%xmm1; \
	pand %xmm7,%xmm2; \
	pand %xmm7,%xmm3; \
	psrlq $2,%xmm0; \
	psrlq $1,%xmm1; \
	SHLB1(%xmm3); \
	por %xmm0,%xmm1; \
	por %xmm2,%xmm3; \
	movdqa V(4),%xmm4; \
	movdqa V(5),%xmm5; \
	por %xmm1,%xmm3; \
	pand %xmm7,%xmm4; \
	pand %xmm7,%xmm5; \
	movdqa V(6),%xmm6; \
	movdqa V(7),%xmm0; \
	psllq $2,%xmm4; \
	pand %xmm7,%xmm6; \
	pand %xmm7,%xmm0; \
	psllq $3,%xmm5; \
	psllq $4,%xmm6; \
	psllq $5,%xmm0; \
	por %xmm4,%xmm5; \
	por %xmm6,%xmm3; \
	por %xmm5,%xmm0; \
	movdqa V(1),%xmm1; \
	por %xmm3,%xmm0; \
	SHLB1(%xmm7); \
	movdqa %xmm0,K(2); \
\
	movdqa V(0),%xmm0; \
	movdqa V(2),%xmm2; \
	movdqa V(3),%xmm3; \
	pand %xmm7,%xmm0; \
	pand %xmm7,%xmm1; \
	pand %xmm7,%xmm2; \
	pand %xmm7,%xmm3; \
	psrlq $3,%xmm0; \
	psrlq $2,%xmm1; \
	psrlq $1,%xmm2; \
	por %xmm0,%xmm1; \
	por %xmm2,%xmm3; \
	movdqa V(4),%xmm4; \
	movdqa V(5),%xmm5; \
	por %xmm1,%xmm3; \
	pand %xmm7,%xmm4; \
	pand %xmm7,%xmm5; \
	movdqa V(6),%xmm6; \
	movdqa V(7),%xmm0; \
	SHLB1(%xmm4); \
	pand %xmm7,%xmm6; \
	pand %xmm7,%xmm0; \
	psllq $2,%xmm5; \
	psllq $3,%xmm6; \
	psllq $4,%xmm0; \
	por %xmm4,%xmm5; \
	por %xmm6,%xmm3; \
	por %xmm5,%xmm0; \
	movdqa V(1),%xmm1; \
	por %xmm3,%xmm0; \
	SHLB1(%xmm7); \
	movdqa %xmm0,K(3); \
\
	movdqa V(0),%xmm0; \
	movdqa V(2),%xmm2; \
	movdqa V(3),%xmm3; \
	pand %xmm7,%xmm0; \
	pand %xmm7,%xmm1; \
	pand %xmm7,%xmm2; \
	pand %xmm7,%xmm3; \
	psrlq $4,%xmm0; \
	psrlq $3,%xmm1; \
	psrlq $2,%xmm2; \
	psrlq $1,%xmm3; \
	por %xmm0,%xmm1; \
	por %xmm2,%xmm3; \
	movdqa V(4),%xmm4; \
	movdqa V(5),%xmm5; \
	por %xmm1,%xmm3; \
	pand %xmm7,%xmm4; \
	pand %xmm7,%xmm5; \
	movdqa V(6),%xmm6; \
	movdqa V(7),%xmm0; \
	pand %xmm7,%xmm6; \
	pand %xmm7,%xmm0; \
	SHLB1(%xmm5); \
	psllq $2,%xmm6; \
	psllq $3,%xmm0; \
	por %xmm4,%xmm5; \
	por %xmm6,%xmm3; \
	por %xmm5,%xmm0; \
	movdqa V(1),%xmm1; \
	por %xmm3,%xmm0; \
	SHLB1(%xmm7); \
	movdqa %xmm0,K(4); \
\
	movdqa V(0),%xmm0; \
	movdqa V(2),%xmm2; \
	movdqa V(3),%xmm3; \
	pand %xmm7,%xmm0; \
	pand %xmm7,%xmm1; \
	pand %xmm7,%xmm2; \
	pand %xmm7,%xmm3; \
	psrlq $5,%xmm0; \
	psrlq $4,%xmm1; \
	psrlq $3,%xmm2; \
	psrlq $2,%xmm3; \
	por %xmm0,%xmm1; \
	por %xmm2,%xmm3; \
	movdqa V(4),%xmm4; \
	movdqa V(5),%xmm5; \
	por %xmm1,%xmm3; \
	pand %xmm7,%xmm4; \
	pand %xmm7,%xmm5; \
	movdqa V(6),%xmm6; \
	movdqa V(7),%xmm0; \
	psrlq $1,%xmm4; \
	pand %xmm7,%xmm6; \
	pand %xmm7,%xmm0; \
	SHLB1(%xmm6); \
	psllq $2,%xmm0; \
	por %xmm4,%xmm5; \
	por %xmm6,%xmm3; \
	por %xmm5,%xmm0; \
	movdqa V(1),%xmm1; \
	por %xmm3,%xmm0; \
	SHLB1(%xmm7); \
	movdqa %xmm0,K(5); \
\
	movdqa V(0),%xmm0; \
	movdqa V(2),%xmm2; \
	movdqa V(3),%xmm3; \
	pand %xmm7,%xmm0; \
	pand %xmm7,%xmm1; \
	pand %xmm7,%xmm2; \
	pand %xmm7,%xmm3; \
	psrlq $6,%xmm0; \
	psrlq $5,%xmm1; \
	psrlq $4,%xmm2; \
	psrlq $3,%xmm3; \
	por %xmm0,%xmm1; \
	por %xmm2,%xmm3; \
	movdqa V(4),%xmm4; \
	movdqa V(5),%xmm5; \
	por %xmm1,%xmm3; \
	pand %xmm7,%xmm4; \
	pand %xmm7,%xmm5; \
	movdqa V(6),%xmm6; \
	movdqa V(7),%xmm0; \
	psrlq $2,%xmm4; \
	pand %xmm7,%xmm6; \
	pand %xmm7,%xmm0; \
	psrlq $1,%xmm5; \
	SHLB1(%xmm0); \
	por %xmm4,%xmm5; \
	por %xmm6,%xmm3; \
	por %xmm5,%xmm0; \
	por %xmm3,%xmm0; \
	movdqa %xmm0,K(6)

.text

DO_ALIGN(6)
.globl DES_bs_init_asm
DES_bs_init_asm:
	pcmpeqd %xmm0,%xmm0
	movdqa %xmm0,pnot
	paddb %xmm0,%xmm0
	pxor pnot,%xmm0
	movdqa %xmm0,mask01
	ret

#define rounds_and_swapped		%ebp
#define iterations			%eax

DO_ALIGN(6)
.globl DES_bs_crypt
DES_bs_crypt:
	cmpl $0,DES_bs_all_keys_changed
	jz DES_bs_crypt_body
	call DES_bs_finalize_keys
DES_bs_crypt_body:
	movl 4(%esp),iterations
	pxor zero,zero
	pushl %ebp
	pushl %esi
	movl $DES_bs_all_KS_v,k_ptr
	DES_bs_clear_block
	movl $8,rounds_and_swapped
DES_bs_crypt_start:
	xor_E(0)
	S1(B(40), B(48), B(54), B(62))
	xor_E(6)
	S2(B(44), B(59), B(33), B(49))
	xor_E(12)
	S3(B(55), B(47), B(61), B(37))
	xor_E(18)
	S4(B(57), B(51), B(41), B(32))
	xor_E(24)
	S5(B(39), B(45), B(56), B(34))
	xor_E(30)
	S6(B(35), B(60), B(42), B(50))
	xor_E(36)
	S7(B(63), B(43), B(53), B(38))
	xor_E(42)
	S8(B(36), B(58), B(46), B(52))
	cmpl $0x100,rounds_and_swapped
	je DES_bs_crypt_next
DES_bs_crypt_swap:
	xor_E(48)
	S1(B(8), B(16), B(22), B(30))
	xor_E(54)
	S2(B(12), B(27), B(1), B(17))
	xor_E(60)
	S3(B(23), B(15), B(29), B(5))
	xor_E(66)
	S4(B(25), B(19), B(9), B(0))
	xor_E(72)
	S5(B(7), B(13), B(24), B(2))
	xor_E(78)
	S6(B(3), B(28), B(10), B(18))
	xor_E(84)
	S7(B(31), B(11), B(21), B(6))
	xor_E(90)
	addl $nvec(96),k_ptr
	S8(B(4), B(26), B(14), B(20))
	decl rounds_and_swapped
	jnz DES_bs_crypt_start
	subl $nvec(0x300+48),k_ptr
	movl $0x108,rounds_and_swapped
	decl iterations
	jnz DES_bs_crypt_swap
	popl %esi
	popl %ebp
	ret
DES_bs_crypt_next:
	subl $nvec(0x300-48),k_ptr
	movl $8,rounds_and_swapped
	decl iterations
	jnz DES_bs_crypt_start
	popl %esi
	popl %ebp
	ret

DO_ALIGN(6)
.globl DES_bs_crypt_25
DES_bs_crypt_25:
	cmpl $0,DES_bs_all_keys_changed
	jnz DES_bs_finalize_keys_25
DES_bs_crypt_25_body:
	pxor zero,zero
	pushl %ebp
	pushl %esi
	movl $DES_bs_all_KS_v,k_ptr
	DES_bs_clear_block
	movl $8,rounds_and_swapped
	movl $25,iterations
DES_bs_crypt_25_start:
	xor_E(0)
	S1(B(40), B(48), B(54), B(62))
	xor_E(6)
	S2(B(44), B(59), B(33), B(49))
	xor_B(7, 12, 8, 13, 9, 14, 10, 15, 11, 16, 12, 17)
	S3(B(55), B(47), B(61), B(37))
	xor_B(11, 18, 12, 19, 13, 20, 14, 21, 15, 22, 16, 23)
	S4(B(57), B(51), B(41), B(32))
	xor_E(24)
	S5(B(39), B(45), B(56), B(34))
	xor_E(30)
	S6(B(35), B(60), B(42), B(50))
	xor_B(23, 36, 24, 37, 25, 38, 26, 39, 27, 40, 28, 41)
	S7(B(63), B(43), B(53), B(38))
	xor_B(27, 42, 28, 43, 29, 44, 30, 45, 31, 46, 0, 47)
	S8(B(36), B(58), B(46), B(52))
	cmpl $0x100,rounds_and_swapped
	je DES_bs_crypt_25_next
DES_bs_crypt_25_swap:
	xor_E(48)
	S1(B(8), B(16), B(22), B(30))
	xor_E(54)
	S2(B(12), B(27), B(1), B(17))
	xor_B(39, 60, 40, 61, 41, 62, 42, 63, 43, 64, 44, 65)
	S3(B(23), B(15), B(29), B(5))
	xor_B(43, 66, 44, 67, 45, 68, 46, 69, 47, 70, 48, 71)
	S4(B(25), B(19), B(9), B(0))
	xor_E(72)
	S5(B(7), B(13), B(24), B(2))
	xor_E(78)
	S6(B(3), B(28), B(10), B(18))
	xor_B(55, 84, 56, 85, 57, 86, 58, 87, 59, 88, 60, 89)
	S7(B(31), B(11), B(21), B(6))
	xor_B(59, 90, 60, 91, 61, 92, 62, 93, 63, 94, 32, 95)
	S8(B(4), B(26), B(14), B(20))
	addl $nvec(96),k_ptr
	decl rounds_and_swapped
	jnz DES_bs_crypt_25_start
	subl $nvec(0x300+48),k_ptr
	movl $0x108,rounds_and_swapped
	decl iterations
	jnz DES_bs_crypt_25_swap
	movl 12(%esp),%eax
	popl %esi
	popl %ebp
	movl (%eax),%eax
	ret
DES_bs_crypt_25_next:
	subl $nvec(0x300-48),k_ptr
	movl $8,rounds_and_swapped
	decl iterations
	jmp DES_bs_crypt_25_start

DES_bs_finalize_keys_25:
	pushl $DES_bs_crypt_25_body
DES_bs_finalize_keys:
	movl $DES_bs_all_xkeys,v_ptr
	movl $DES_bs_all_K,k_ptr
	movl $0,DES_bs_all_keys_changed
DES_bs_finalize_keys_main_loop:
	FINALIZE_NEXT_KEY_BITS_0_6
	addl $nvec(7),k_ptr
	addl $nvec(8),v_ptr
	cmpl $DES_bs_all_K+nvec(56),k_ptr
	jb DES_bs_finalize_keys_main_loop
	pushl %esi
	movl $DES_bs_all_KSp,k_ptr
	movl $DES_bs_all_KS_v,v_ptr
DES_bs_finalize_keys_expand_loop:
	movl k(0),tmp1
	movl k(1),tmp2
	movdqa (tmp1),%xmm0
	movdqa (tmp2),%xmm1
	movl k(2),tmp1
	movl k(3),tmp2
	movdqa %xmm0,V(0)
	movdqa %xmm1,V(1)
	movdqa (tmp1),%xmm0
	movdqa (tmp2),%xmm1
	movl k(4),tmp1
	movl k(5),tmp2
	movdqa %xmm0,V(2)
	movdqa %xmm1,V(3)
	movdqa (tmp1),%xmm0
	movdqa (tmp2),%xmm1
	movl k(6),tmp1
	movl k(7),tmp2
	movdqa %xmm0,V(4)
	movdqa %xmm1,V(5)
	movdqa (tmp1),%xmm0
	movdqa (tmp2),%xmm1
	addl $nptr(8),k_ptr
	movdqa %xmm0,V(6)
	movdqa %xmm1,V(7)
	addl $nvec(8),v_ptr
	cmpl $DES_bs_all_KSp+nptr(0x300),k_ptr
	jb DES_bs_finalize_keys_expand_loop
	popl %esi
	ret

#define ones				%xmm1

#define rounds				%eax

DO_ALIGN(6)
.globl DES_bs_crypt_LM
DES_bs_crypt_LM:
	movl $DES_bs_all_xkeys,v_ptr
	movl $DES_bs_all_K,k_ptr
DES_bs_finalize_keys_LM_loop:
	FINALIZE_NEXT_KEY_BITS_0_6
# bit 7
	SHLB1(%xmm7)
	movdqa V(0),%xmm0
	movdqa V(1),%xmm1
	movdqa V(2),%xmm2
	movdqa V(3),%xmm3
	pand %xmm7,%xmm0
	pand %xmm7,%xmm1
	pand %xmm7,%xmm2
	pand %xmm7,%xmm3
	psrlq $7,%xmm0
	psrlq $6,%xmm1
	psrlq $5,%xmm2
	psrlq $4,%xmm3
	por %xmm0,%xmm1
	por %xmm2,%xmm3
	movdqa V(4),%xmm4
	movdqa V(5),%xmm5
	por %xmm1,%xmm3
	pand %xmm7,%xmm4
	pand %xmm7,%xmm5
	movdqa V(6),%xmm6
	movdqa V(7),%xmm0
	psrlq $3,%xmm4
	pand %xmm7,%xmm6
	pand %xmm7,%xmm0
	psrlq $2,%xmm5
	psrlq $1,%xmm6
	por %xmm4,%xmm5
	por %xmm6,%xmm3
	por %xmm5,%xmm0
	addl $nvec(8),v_ptr
	por %xmm3,%xmm0
	movdqa %xmm0,K(7)
	addl $nvec(8),k_ptr
	cmpl $DES_bs_all_K+nvec(56),k_ptr
	jb DES_bs_finalize_keys_LM_loop

	pxor zero,zero
	pushl %esi
	pcmpeqd ones,ones
	movl $DES_bs_all_KS_p,k_ptr
	movdqa zero,B(0)
	movdqa zero,B(1)
	movdqa zero,B(2)
	movdqa zero,B(3)
	movdqa zero,B(4)
	movdqa zero,B(5)
	movdqa zero,B(6)
	movdqa zero,B(7)
	movdqa ones,B(8)
	movdqa ones,B(9)
	movdqa ones,B(10)
	movdqa zero,B(11)
	movdqa ones,B(12)
	movdqa zero,B(13)
	movdqa zero,B(14)
	movdqa zero,B(15)
	movdqa zero,B(16)
	movdqa zero,B(17)
	movdqa zero,B(18)
	movdqa zero,B(19)
	movdqa zero,B(20)
	movdqa zero,B(21)
	movdqa zero,B(22)
	movdqa ones,B(23)
	movdqa zero,B(24)
	movdqa zero,B(25)
	movdqa ones,B(26)
	movdqa zero,B(27)
	movdqa zero,B(28)
	movdqa ones,B(29)
	movdqa ones,B(30)
	movdqa ones,B(31)
	movdqa zero,B(32)
	movdqa zero,B(33)
	movdqa zero,B(34)
	movdqa ones,B(35)
	movdqa zero,B(36)
	movdqa ones,B(37)
	movdqa ones,B(38)
	movdqa ones,B(39)
	movdqa zero,B(40)
	movdqa zero,B(41)
	movdqa zero,B(42)
	movdqa zero,B(43)
	movdqa zero,B(44)
	movdqa ones,B(45)
	movdqa zero,B(46)
	movdqa zero,B(47)
	movdqa ones,B(48)
	movdqa ones,B(49)
	movdqa zero,B(50)
	movdqa zero,B(51)
	movdqa zero,B(52)
	movdqa zero,B(53)
	movdqa ones,B(54)
	movdqa zero,B(55)
	movdqa ones,B(56)
	movdqa zero,B(57)
	movdqa ones,B(58)
	movdqa zero,B(59)
	movdqa ones,B(60)
	movdqa ones,B(61)
	movdqa ones,B(62)
	movdqa ones,B(63)
	movl $8,rounds
DES_bs_crypt_LM_loop:
	xor_B_KS_p_special(31, 0, 0, 1, 1, 2, 2, 3, 3, 4, 5)
	S1(B(40), B(48), B(54), B(62))
	xor_B_KS_p(3, 6, 4, 7, 5, 8, 6, 9, 7, 10, 8, 11)
	S2(B(44), B(59), B(33), B(49))
	xor_B_KS_p(7, 12, 8, 13, 9, 14, 10, 15, 11, 16, 12, 17)
	S3(B(55), B(47), B(61), B(37))
	xor_B_KS_p(11, 18, 12, 19, 13, 20, 14, 21, 15, 22, 16, 23)
	S4(B(57), B(51), B(41), B(32))
	xor_B_KS_p(15, 24, 16, 25, 17, 26, 18, 27, 19, 28, 20, 29)
	S5(B(39), B(45), B(56), B(34))
	xor_B_KS_p(19, 30, 20, 31, 21, 32, 22, 33, 23, 34, 24, 35)
	S6(B(35), B(60), B(42), B(50))
	xor_B_KS_p(23, 36, 24, 37, 25, 38, 26, 39, 27, 40, 28, 41)
	S7(B(63), B(43), B(53), B(38))
	xor_B_KS_p(27, 42, 28, 43, 29, 44, 30, 45, 31, 46, 0, 47)
	S8(B(36), B(58), B(46), B(52))
	xor_B_KS_p_special(63, 48, 32, 49, 33, 50, 34, 51, 35, 52, 53)
	S1(B(8), B(16), B(22), B(30))
	xor_B_KS_p(35, 54, 36, 55, 37, 56, 38, 57, 39, 58, 40, 59)
	S2(B(12), B(27), B(1), B(17))
	xor_B_KS_p(39, 60, 40, 61, 41, 62, 42, 63, 43, 64, 44, 65)
	S3(B(23), B(15), B(29), B(5))
	xor_B_KS_p(43, 66, 44, 67, 45, 68, 46, 69, 47, 70, 48, 71)
	S4(B(25), B(19), B(9), B(0))
	xor_B_KS_p(47, 72, 48, 73, 49, 74, 50, 75, 51, 76, 52, 77)
	S5(B(7), B(13), B(24), B(2))
	xor_B_KS_p(51, 78, 52, 79, 53, 80, 54, 81, 55, 82, 56, 83)
	S6(B(3), B(28), B(10), B(18))
	xor_B_KS_p(55, 84, 56, 85, 57, 86, 58, 87, 59, 88, 60, 89)
	S7(B(31), B(11), B(21), B(6))
	xor_B_KS_p(59, 90, 60, 91, 61, 92, 62, 93, 63, 94, 32, 95)
	addl $nptr(96),k_ptr
	S8(B(4), B(26), B(14), B(20))
	decl rounds
	jnz DES_bs_crypt_LM_loop
	movl 8(%esp),%eax
	popl %esi
	movl (%eax),%eax
	ret

#define rounds				%eax

DO_ALIGN(6)
.globl DES_bs_crypt_plain
DES_bs_crypt_plain:
	movl $DES_bs_all_xkeys,v_ptr
	movl $DES_bs_all_K,k_ptr
	movdqa P(0),%xmm4
	movdqa %xmm4,B(0)
	movdqa P(1),%xmm4
	movdqa %xmm4,B(1)
	movdqa P(2),%xmm4
	movdqa %xmm4,B(2)
	movdqa P(3),%xmm4
	movdqa %xmm4,B(3)
	movdqa P(4),%xmm4
	movdqa %xmm4,B(4)
	movdqa P(5),%xmm4
	movdqa %xmm4,B(5)
	movdqa P(6),%xmm4
	movdqa %xmm4,B(6)
	movdqa P(7),%xmm4
	movdqa %xmm4,B(7)
	movdqa P(8),%xmm4
	movdqa %xmm4,B(8)
	movdqa P(9),%xmm4
	movdqa %xmm4,B(9)
	movdqa P(10),%xmm4
	movdqa %xmm4,B(10)
	movdqa P(11),%xmm4
	movdqa %xmm4,B(11)
	movdqa P(12),%xmm4
	movdqa %xmm4,B(12)
	movdqa P(13),%xmm4
	movdqa %xmm4,B(13)
	movdqa P(14),%xmm4
	movdqa %xmm4,B(14)
	movdqa P(15),%xmm4
	movdqa %xmm4,B(15)
	movdqa P(16),%xmm4
	movdqa %xmm4,B(16)
	movdqa P(17),%xmm4
	movdqa %xmm4,B(17)
	movdqa P(18),%xmm4
	movdqa %xmm4,B(18)
	movdqa P(19),%xmm4
	movdqa %xmm4,B(19)
	movdqa P(20),%xmm4
	movdqa %xmm4,B(20)
	movdqa P(21),%xmm4
	movdqa %xmm4,B(21)
	movdqa P(22),%xmm4
	movdqa %xmm4,B(22)
	movdqa P(23),%xmm4
	movdqa %xmm4,B(23)
	movdqa P(24),%xmm4
	movdqa %xmm4,B(24)
	movdqa P(25),%xmm4
	movdqa %xmm4,B(25)
	movdqa P(26),%xmm4
	movdqa %xmm4,B(26)
	movdqa P(27),%xmm4
	movdqa %xmm4,B(27)
	movdqa P(28),%xmm4
	movdqa %xmm4,B(28)
	movdqa P(29),%xmm4
	movdqa %xmm4,B(29)
	movdqa P(30),%xmm4
	movdqa %xmm4,B(30)
	movdqa P(31),%xmm4
	movdqa %xmm4,B(31)
	movdqa P(32),%xmm4
	movdqa %xmm4,B(32)
	movdqa P(33),%xmm4
	movdqa %xmm4,B(33)
	movdqa P(34),%xmm4
	movdqa %xmm4,B(34)
	movdqa P(35),%xmm4
	movdqa %xmm4,B(35)
	movdqa P(36),%xmm4
	movdqa %xmm4,B(36)
	movdqa P(37),%xmm4
	movdqa %xmm4,B(37)
	movdqa P(38),%xmm4
	movdqa %xmm4,B(38)
	movdqa P(39),%xmm4
	movdqa %xmm4,B(39)
	movdqa P(40),%xmm4
	movdqa %xmm4,B(40)
	movdqa P(41),%xmm4
	movdqa %xmm4,B(41)
	movdqa P(42),%xmm4
	movdqa %xmm4,B(42)
	movdqa P(43),%xmm4
	movdqa %xmm4,B(43)
	movdqa P(44),%xmm4
	movdqa %xmm4,B(44)
	movdqa P(45),%xmm4
	movdqa %xmm4,B(45)
	movdqa P(46),%xmm4
	movdqa %xmm4,B(46)
	movdqa P(47),%xmm4
	movdqa %xmm4,B(47)
	movdqa P(48),%xmm4
	movdqa %xmm4,B(48)
	movdqa P(49),%xmm4
	movdqa %xmm4,B(49)
	movdqa P(50),%xmm4
	movdqa %xmm4,B(50)
	movdqa P(51),%xmm4
	movdqa %xmm4,B(51)
	movdqa P(52),%xmm4
	movdqa %xmm4,B(52)
	movdqa P(53),%xmm4
	movdqa %xmm4,B(53)
	movdqa P(54),%xmm4
	movdqa %xmm4,B(54)
	movdqa P(55),%xmm4
	movdqa %xmm4,B(55)
	movdqa P(56),%xmm4
	movdqa %xmm4,B(56)
	movdqa P(57),%xmm4
	movdqa %xmm4,B(57)
	movdqa P(58),%xmm4
	movdqa %xmm4,B(58)
	movdqa P(59),%xmm4
	movdqa %xmm4,B(59)
	movdqa P(60),%xmm4
	movdqa %xmm4,B(60)
	movdqa P(61),%xmm4
	movdqa %xmm4,B(61)
	movdqa P(62),%xmm4
	movdqa %xmm4,B(62)
	movdqa P(63),%xmm4
	movdqa %xmm4,B(63)

DES_bs_finalize_keys_plain_loop:
	FINALIZE_NEXT_KEY_BITS_0_6
	addl $nvec(7),k_ptr
	addl $nvec(8),v_ptr
	cmpl $DES_bs_all_K+nvec(56),k_ptr
	jb DES_bs_finalize_keys_plain_loop
	pushl %esi
	movl $DES_bs_all_KS_p,k_ptr
	movl $DES_bs_all_KS_v,v_ptr
	movl $8,rounds
DES_bs_crypt_plain_loop:
	xor_B_KS_p(31, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5)
	S1(B(40), B(48), B(54), B(62))
	xor_B_KS_p(3, 6, 4, 7, 5, 8, 6, 9, 7, 10, 8, 11)
	S2(B(44), B(59), B(33), B(49))
	xor_B_KS_p(7, 12, 8, 13, 9, 14, 10, 15, 11, 16, 12, 17)
	S3(B(55), B(47), B(61), B(37))
	xor_B_KS_p(11, 18, 12, 19, 13, 20, 14, 21, 15, 22, 16, 23)
	S4(B(57), B(51), B(41), B(32))
	xor_B_KS_p(15, 24, 16, 25, 17, 26, 18, 27, 19, 28, 20, 29)
	S5(B(39), B(45), B(56), B(34))
	xor_B_KS_p(19, 30, 20, 31, 21, 32, 22, 33, 23, 34, 24, 35)
	S6(B(35), B(60), B(42), B(50))
	xor_B_KS_p(23, 36, 24, 37, 25, 38, 26, 39, 27, 40, 28, 41)
	S7(B(63), B(43), B(53), B(38))
	xor_B_KS_p(27, 42, 28, 43, 29, 44, 30, 45, 31, 46, 0, 47)
	S8(B(36), B(58), B(46), B(52))
	xor_B_KS_p(63, 48, 32, 49, 33, 50, 34, 51, 35, 52, 36, 53)
	S1(B(8), B(16), B(22), B(30))
	xor_B_KS_p(35, 54, 36, 55, 37, 56, 38, 57, 39, 58, 40, 59)
	S2(B(12), B(27), B(1), B(17))
	xor_B_KS_p(39, 60, 40, 61, 41, 62, 42, 63, 43, 64, 44, 65)
	S3(B(23), B(15), B(29), B(5))
	xor_B_KS_p(43, 66, 44, 67, 45, 68, 46, 69, 47, 70, 48, 71)
	S4(B(25), B(19), B(9), B(0))
	xor_B_KS_p(47, 72, 48, 73, 49, 74, 50, 75, 51, 76, 52, 77)
	S5(B(7), B(13), B(24), B(2))
	xor_B_KS_p(51, 78, 52, 79, 53, 80, 54, 81, 55, 82, 56, 83)
	S6(B(3), B(28), B(10), B(18))
	xor_B_KS_p(55, 84, 56, 85, 57, 86, 58, 87, 59, 88, 60, 89)
	S7(B(31), B(11), B(21), B(6))
	xor_B_KS_p(59, 90, 60, 91, 61, 92, 62, 93, 63, 94, 32, 95)
	addl $nptr(96),k_ptr
	S8(B(4), B(26), B(14), B(20))
	decl rounds
	jnz DES_bs_crypt_plain_loop
	popl %esi
	ret


#endif

#if defined(__ELF__) && defined(__linux__)
.section .note.GNU-stack,"",@progbits
#endif
