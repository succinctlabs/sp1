// musl as a whole is licensed under the following standard MIT license:
// 
// ----------------------------------------------------------------------
// Copyright © 2005-2020 Rich Felker, et al.
// 
// Permission is hereby granted, free of charge, to any person obtaining
// a copy of this software and associated documentation files (the
// "Software"), to deal in the Software without restriction, including
// without limitation the rights to use, copy, modify, merge, publish,
// distribute, sublicense, and/or sell copies of the Software, and to
// permit persons to whom the Software is furnished to do so, subject to
// the following conditions:
// 
// The above copyright notice and this permission notice shall be
// included in all copies or substantial portions of the Software.
// 
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
// EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
// MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
// IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
// CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
// TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
// SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
// ----------------------------------------------------------------------
// 
// Authors/contributors include:
// 
// A. Wilcox
// Ada Worcester
// Alex Dowad
// Alex Suykov
// Alexander Monakov
// Andre McCurdy
// Andrew Kelley
// Anthony G. Basile
// Aric Belsito
// Arvid Picciani
// Bartosz Brachaczek
// Benjamin Peterson
// Bobby Bingham
// Boris Brezillon
// Brent Cook
// Chris Spiegel
// Clément Vasseur
// Daniel Micay
// Daniel Sabogal
// Daurnimator
// David Carlier
// David Edelsohn
// Denys Vlasenko
// Dmitry Ivanov
// Dmitry V. Levin
// Drew DeVault
// Emil Renner Berthing
// Fangrui Song
// Felix Fietkau
// Felix Janda
// Gianluca Anzolin
// Hauke Mehrtens
// He X
// Hiltjo Posthuma
// Isaac Dunham
// Jaydeep Patil
// Jens Gustedt
// Jeremy Huntwork
// Jo-Philipp Wich
// Joakim Sindholt
// John Spencer
// Julien Ramseier
// Justin Cormack
// Kaarle Ritvanen
// Khem Raj
// Kylie McClain
// Leah Neukirchen
// Luca Barbato
// Luka Perkov
// M Farkas-Dyck (Strake)
// Mahesh Bodapati
// Markus Wichmann
// Masanori Ogino
// Michael Clark
// Michael Forney
// Mikhail Kremnyov
// Natanael Copa
// Nicholas J. Kain
// orc
// Pascal Cuoq
// Patrick Oppenlander
// Petr Hosek
// Petr Skocik
// Pierre Carrier
// Reini Urban
// Rich Felker
// Richard Pennington
// Ryan Fairfax
// Samuel Holland
// Segev Finer
// Shiz
// sin
// Solar Designer
// Stefan Kristiansson
// Stefan O'Rear
// Szabolcs Nagy
// Timo Teräs
// Trutz Behn
// Valentin Ochs
// Will Dietz
// William Haddon
// William Pitcock
// 
// Portions of this software are derived from third-party works licensed
// under terms compatible with the above MIT license:
// 
// The TRE regular expression implementation (src/regex/reg* and
// src/regex/tre*) is Copyright © 2001-2008 Ville Laurikari and licensed
// under a 2-clause BSD license (license text in the source files). The
// included version has been heavily modified by Rich Felker in 2012, in
// the interests of size, simplicity, and namespace cleanliness.
// 
// Much of the math library code (src/math/* and src/complex/*) is
// Copyright © 1993,2004 Sun Microsystems or
// Copyright © 2003-2011 David Schultz or
// Copyright © 2003-2009 Steven G. Kargl or
// Copyright © 2003-2009 Bruce D. Evans or
// Copyright © 2008 Stephen L. Moshier or
// Copyright © 2017-2018 Arm Limited
// and labelled as such in comments in the individual source files. All
// have been licensed under extremely permissive terms.
// 
// The ARM memcpy code (src/string/arm/memcpy.S) is Copyright © 2008
// The Android Open Source Project and is licensed under a two-clause BSD
// license. It was taken from Bionic libc, used on Android.
// 
// The AArch64 memcpy and memset code (src/string/aarch64/*) are
// Copyright © 1999-2019, Arm Limited.
// 
// The implementation of DES for crypt (src/crypt/crypt_des.c) is
// Copyright © 1994 David Burren. It is licensed under a BSD license.
// 
// The implementation of blowfish crypt (src/crypt/crypt_blowfish.c) was
// originally written by Solar Designer and placed into the public
// domain. The code also comes with a fallback permissive license for use
// in jurisdictions that may not recognize the public domain.
// 
// The smoothsort implementation (src/stdlib/qsort.c) is Copyright © 2011
// Valentin Ochs and is licensed under an MIT-style license.
// 
// The x86_64 port was written by Nicholas J. Kain and is licensed under
// the standard MIT terms.
// 
// The mips and microblaze ports were originally written by Richard
// Pennington for use in the ellcc project. The original code was adapted
// by Rich Felker for build system and code conventions during upstream
// integration. It is licensed under the standard MIT terms.
// 
// The mips64 port was contributed by Imagination Technologies and is
// licensed under the standard MIT terms.
// 
// The powerpc port was also originally written by Richard Pennington,
// and later supplemented and integrated by John Spencer. It is licensed
// under the standard MIT terms.
// 
// All other files which have no copyright comments are original works
// produced specifically for use as part of this library, written either
// by Rich Felker, the main author of the library, or by one or more
// contibutors listed above. Details on authorship of individual files
// can be found in the git version control history of the project. The
// omission of copyright and license comments in each file is in the
// interest of source tree size.
// 
// In addition, permission is hereby granted for all public header files
// (include/* and arch/*/bits/*) and crt files intended to be linked into
// applications (crt/*, ldso/dlstart.c, and arch/*/crt_arch.h) to omit
// the copyright notice and permission notice otherwise required by the
// license, and to use these files without any requirement of
// attribution. These files include substantial contributions from:
// 
// Bobby Bingham
// John Spencer
// Nicholas J. Kain
// Rich Felker
// Richard Pennington
// Stefan Kristiansson
// Szabolcs Nagy
// 
// all of whom have explicitly granted such permission.
// 
// This file previously contained text expressing a belief that most of
// the files covered by the above exception were sufficiently trivial not
// to be subject to copyright, resulting in confusion over whether it
// negated the permissions granted in the license. In the spirit of
// permissive licensing, and of not having licensing issues being an
// obstacle to adoption, that text has been removed.
	.attribute	4, 16
	.attribute	5, "rv64i2p1_m2p0_zmmul1p0"
	.file	"memcpy.c"
	.text
	.globl	memcpy                          # -- Begin function memcpy
	.p2align	2
	.type	memcpy,@function
memcpy:                                 # @memcpy
# %bb.0:
	andi	a3, a1, 7
	beqz	a3, .LBBmemcpy0_16
# %bb.1:
	beqz	a2, .LBBmemcpy0_5
# %bb.2:
	addi	a4, a1, 1
	li	a5, 1
	mv	a3, a0
.LBBmemcpy0_3:                                # =>This Inner Loop Header: Depth=1
	lbu	a7, 0(a1)
	mv	a6, a2
	addi	a1, a1, 1
	andi	t0, a4, 7
	sb	a7, 0(a3)
	addi	a3, a3, 1
	addi	a2, a2, -1
	beqz	t0, .LBBmemcpy0_6
# %bb.4:                                #   in Loop: Header=BB0_3 Depth=1
	addi	a4, a4, 1
	bne	a6, a5, .LBBmemcpy0_3
	j	.LBBmemcpy0_6
.LBBmemcpy0_5:
	mv	a3, a0
.LBBmemcpy0_6:
	andi	a4, a3, 7
	beqz	a4, .LBBmemcpy0_17
.LBBmemcpy0_7:
	li	a5, 64
	bgeu	a2, a5, .LBBmemcpy0_12
# %bb.8:
	li	a4, 32
	bgeu	a2, a4, .LBBmemcpy0_44
.LBBmemcpy0_9:
	andi	a4, a2, 16
	bnez	a4, .LBBmemcpy0_45
.LBBmemcpy0_10:
	andi	a4, a2, 8
	bnez	a4, .LBBmemcpy0_46
.LBBmemcpy0_11:
	andi	a4, a2, 4
	bnez	a4, .LBBmemcpy0_47
	j	.LBBmemcpy0_48
.LBBmemcpy0_12:
	addi	a4, a4, -1
	slli	a4, a4, 2
1:
	auipc	a5, %pcrel_hi(.LJTI0_0)                # Use PC-relative addressing in 64-bit mode
	addi	a5, a5, %pcrel_lo(1b)
	add	a4, a4, a5
	lwu	a5, 0(a4)
	ld	a4, 0(a1)
	jr	a5
.LBBmemcpy0_13:
	srli	a5, a4, 8
	srli	a6, a4, 16
	srli	a7, a4, 24
	srli	t0, a4, 32
	srli	t1, a4, 40
	sb	a4, 0(a3)
	sb	a5, 1(a3)
	sb	a6, 2(a3)
	sb	a7, 3(a3)
	srli	a5, a4, 48
	addi	a2, a2, -7
	sb	t0, 4(a3)
	sb	t1, 5(a3)
	sb	a5, 6(a3)
	addi	a3, a3, 7
	addi	a1, a1, 32
	li	a5, 32
.LBBmemcpy0_14:                               # =>This Inner Loop Header: Depth=1
	srli	a6, a4, 56
	ld	a7, -24(a1)
	ld	t0, -16(a1)
	ld	t1, -8(a1)
	ld	a4, 0(a1)
	slli	t2, a7, 8
	srli	a7, a7, 56
	or	a6, t2, a6
	slli	t2, t0, 8
	srli	t0, t0, 56
	or	a7, t2, a7
	slli	t2, t1, 8
	srli	t1, t1, 56
	or	t0, t2, t0
	slli	t2, a4, 8
	or	t1, t2, t1
	addi	a2, a2, -32
	sd	a6, 0(a3)
	sd	a7, 8(a3)
	sd	t0, 16(a3)
	sd	t1, 24(a3)
	addi	a3, a3, 32
	addi	a1, a1, 32
	bltu	a5, a2, .LBBmemcpy0_14
# %bb.15:
	addi	a1, a1, -25
	li	a4, 32
	bltu	a2, a4, .LBBmemcpy0_9
	j	.LBBmemcpy0_44
.LBBmemcpy0_16:
	mv	a3, a0
	andi	a4, a0, 7
	bnez	a4, .LBBmemcpy0_7
.LBBmemcpy0_17:
	li	a4, 32
	bltu	a2, a4, .LBBmemcpy0_20
# %bb.18:
	li	a4, 31
.LBBmemcpy0_19:                               # =>This Inner Loop Header: Depth=1
	ld	a5, 0(a1)
	ld	a6, 8(a1)
	ld	a7, 16(a1)
	ld	t0, 24(a1)
	addi	a1, a1, 32
	addi	a2, a2, -32
	sd	a5, 0(a3)
	sd	a6, 8(a3)
	sd	a7, 16(a3)
	sd	t0, 24(a3)
	addi	a3, a3, 32
	bltu	a4, a2, .LBBmemcpy0_19
.LBBmemcpy0_20:
	li	a4, 16
	bgeu	a2, a4, .LBBmemcpy0_23
# %bb.21:
	andi	a4, a2, 8
	bnez	a4, .LBBmemcpy0_24
.LBBmemcpy0_22:
	andi	a4, a2, 4
	bnez	a4, .LBBmemcpy0_25
	j	.LBBmemcpy0_48
.LBBmemcpy0_23:
	ld	a4, 0(a1)
	ld	a5, 8(a1)
	sd	a4, 0(a3)
	sd	a5, 8(a3)
	addi	a3, a3, 16
	addi	a1, a1, 16
	andi	a4, a2, 8
	beqz	a4, .LBBmemcpy0_22
.LBBmemcpy0_24:
	ld	a4, 0(a1)
	addi	a1, a1, 8
	sd	a4, 0(a3)
	addi	a3, a3, 8
	andi	a4, a2, 4
	beqz	a4, .LBBmemcpy0_48
.LBBmemcpy0_25:
	lw	a4, 0(a1)
	addi	a1, a1, 4
	sw	a4, 0(a3)
	addi	a3, a3, 4
	j	.LBBmemcpy0_48
.LBBmemcpy0_26:
	srli	a5, a4, 8
	srli	a6, a4, 16
	addi	a2, a2, -3
	sb	a4, 0(a3)
	sb	a5, 1(a3)
	sb	a6, 2(a3)
	addi	a3, a3, 3
	addi	a1, a1, 32
	li	a5, 36
.LBBmemcpy0_27:                               # =>This Inner Loop Header: Depth=1
	srli	a6, a4, 24
	ld	a7, -24(a1)
	ld	t0, -16(a1)
	ld	t1, -8(a1)
	ld	a4, 0(a1)
	slli	t2, a7, 40
	srli	a7, a7, 24
	or	a6, t2, a6
	slli	t2, t0, 40
	srli	t0, t0, 24
	or	a7, t2, a7
	slli	t2, t1, 40
	srli	t1, t1, 24
	or	t0, t2, t0
	slli	t2, a4, 40
	or	t1, t2, t1
	addi	a2, a2, -32
	sd	a6, 0(a3)
	sd	a7, 8(a3)
	sd	t0, 16(a3)
	sd	t1, 24(a3)
	addi	a3, a3, 32
	addi	a1, a1, 32
	bltu	a5, a2, .LBBmemcpy0_27
# %bb.28:
	addi	a1, a1, -29
	li	a4, 32
	bltu	a2, a4, .LBBmemcpy0_9
	j	.LBBmemcpy0_44
.LBBmemcpy0_29:
	srli	a5, a4, 8
	srli	a6, a4, 16
	srli	a7, a4, 24
	srli	t0, a4, 32
	addi	a2, a2, -5
	sb	a4, 0(a3)
	sb	a5, 1(a3)
	sb	a6, 2(a3)
	sb	a7, 3(a3)
	sb	t0, 4(a3)
	addi	a3, a3, 5
	addi	a1, a1, 32
	li	a5, 34
.LBBmemcpy0_30:                               # =>This Inner Loop Header: Depth=1
	srli	a6, a4, 40
	ld	a7, -24(a1)
	ld	t0, -16(a1)
	ld	t1, -8(a1)
	ld	a4, 0(a1)
	slli	t2, a7, 24
	srli	a7, a7, 40
	or	a6, t2, a6
	slli	t2, t0, 24
	srli	t0, t0, 40
	or	a7, t2, a7
	slli	t2, t1, 24
	srli	t1, t1, 40
	or	t0, t2, t0
	slli	t2, a4, 24
	or	t1, t2, t1
	addi	a2, a2, -32
	sd	a6, 0(a3)
	sd	a7, 8(a3)
	sd	t0, 16(a3)
	sd	t1, 24(a3)
	addi	a3, a3, 32
	addi	a1, a1, 32
	bltu	a5, a2, .LBBmemcpy0_30
# %bb.31:
	addi	a1, a1, -27
	li	a4, 32
	bltu	a2, a4, .LBBmemcpy0_9
	j	.LBBmemcpy0_44
.LBBmemcpy0_32:
	srli	a5, a4, 8
	srli	a6, a4, 16
	srli	a7, a4, 24
	addi	a2, a2, -4
	sb	a4, 0(a3)
	sb	a5, 1(a3)
	sb	a6, 2(a3)
	sb	a7, 3(a3)
	addi	a3, a3, 4
	addi	a1, a1, 32
	li	a5, 35
.LBBmemcpy0_33:                               # =>This Inner Loop Header: Depth=1
	srli	a6, a4, 32
	ld	a7, -24(a1)
	ld	t0, -16(a1)
	ld	t1, -8(a1)
	ld	a4, 0(a1)
	slli	t2, a7, 32
	srli	a7, a7, 32
	or	a6, t2, a6
	slli	t2, t0, 32
	srli	t0, t0, 32
	or	a7, t2, a7
	slli	t2, t1, 32
	srli	t1, t1, 32
	or	t0, t2, t0
	slli	t2, a4, 32
	or	t1, t2, t1
	addi	a2, a2, -32
	sd	a6, 0(a3)
	sd	a7, 8(a3)
	sd	t0, 16(a3)
	sd	t1, 24(a3)
	addi	a3, a3, 32
	addi	a1, a1, 32
	bltu	a5, a2, .LBBmemcpy0_33
# %bb.34:
	addi	a1, a1, -28
	li	a4, 32
	bltu	a2, a4, .LBBmemcpy0_9
	j	.LBBmemcpy0_44
.LBBmemcpy0_35:
	srli	a5, a4, 8
	srli	a6, a4, 16
	srli	a7, a4, 24
	srli	t0, a4, 32
	sb	a4, 0(a3)
	sb	a5, 1(a3)
	sb	a6, 2(a3)
	sb	a7, 3(a3)
	srli	a5, a4, 40
	addi	a2, a2, -6
	sb	t0, 4(a3)
	sb	a5, 5(a3)
	addi	a3, a3, 6
	addi	a1, a1, 32
	li	a5, 33
.LBBmemcpy0_36:                               # =>This Inner Loop Header: Depth=1
	srli	a6, a4, 48
	ld	a7, -24(a1)
	ld	t0, -16(a1)
	ld	t1, -8(a1)
	ld	a4, 0(a1)
	slli	t2, a7, 16
	srli	a7, a7, 48
	or	a6, t2, a6
	slli	t2, t0, 16
	srli	t0, t0, 48
	or	a7, t2, a7
	slli	t2, t1, 16
	srli	t1, t1, 48
	or	t0, t2, t0
	slli	t2, a4, 16
	or	t1, t2, t1
	addi	a2, a2, -32
	sd	a6, 0(a3)
	sd	a7, 8(a3)
	sd	t0, 16(a3)
	sd	t1, 24(a3)
	addi	a3, a3, 32
	addi	a1, a1, 32
	bltu	a5, a2, .LBBmemcpy0_36
# %bb.37:
	addi	a1, a1, -26
	li	a4, 32
	bltu	a2, a4, .LBBmemcpy0_9
	j	.LBBmemcpy0_44
.LBBmemcpy0_38:
	srli	a5, a4, 8
	addi	a2, a2, -2
	sb	a4, 0(a3)
	sb	a5, 1(a3)
	addi	a3, a3, 2
	addi	a1, a1, 32
	li	a5, 37
.LBBmemcpy0_39:                               # =>This Inner Loop Header: Depth=1
	srli	a6, a4, 16
	ld	a7, -24(a1)
	ld	t0, -16(a1)
	ld	t1, -8(a1)
	ld	a4, 0(a1)
	slli	t2, a7, 48
	srli	a7, a7, 16
	or	a6, t2, a6
	slli	t2, t0, 48
	srli	t0, t0, 16
	or	a7, t2, a7
	slli	t2, t1, 48
	srli	t1, t1, 16
	or	t0, t2, t0
	slli	t2, a4, 48
	or	t1, t2, t1
	addi	a2, a2, -32
	sd	a6, 0(a3)
	sd	a7, 8(a3)
	sd	t0, 16(a3)
	sd	t1, 24(a3)
	addi	a3, a3, 32
	addi	a1, a1, 32
	bltu	a5, a2, .LBBmemcpy0_39
# %bb.40:
	addi	a1, a1, -30
	li	a4, 32
	bltu	a2, a4, .LBBmemcpy0_9
	j	.LBBmemcpy0_44
.LBBmemcpy0_41:
	sb	a4, 0(a3)
	addi	a3, a3, 1
	addi	a2, a2, -1
	addi	a1, a1, 32
	li	a5, 38
.LBBmemcpy0_42:                               # =>This Inner Loop Header: Depth=1
	srli	a6, a4, 8
	ld	a7, -24(a1)
	ld	t0, -16(a1)
	ld	t1, -8(a1)
	ld	a4, 0(a1)
	slli	t2, a7, 56
	srli	a7, a7, 8
	or	a6, t2, a6
	slli	t2, t0, 56
	srli	t0, t0, 8
	or	a7, t2, a7
	slli	t2, t1, 56
	srli	t1, t1, 8
	or	t0, t2, t0
	slli	t2, a4, 56
	or	t1, t2, t1
	addi	a2, a2, -32
	sd	a6, 0(a3)
	sd	a7, 8(a3)
	sd	t0, 16(a3)
	sd	t1, 24(a3)
	addi	a3, a3, 32
	addi	a1, a1, 32
	bltu	a5, a2, .LBBmemcpy0_42
# %bb.43:
	addi	a1, a1, -31
	li	a4, 32
	bltu	a2, a4, .LBBmemcpy0_9
.LBBmemcpy0_44:
	lbu	a4, 0(a1)
	lbu	a5, 1(a1)
	lbu	a6, 2(a1)
	lbu	a7, 3(a1)
	lbu	t0, 4(a1)
	lbu	t1, 5(a1)
	lbu	t2, 6(a1)
	lbu	t3, 7(a1)
	sb	a4, 0(a3)
	sb	a5, 1(a3)
	sb	a6, 2(a3)
	sb	a7, 3(a3)
	lbu	a4, 8(a1)
	lbu	a5, 9(a1)
	lbu	a6, 10(a1)
	lbu	a7, 11(a1)
	sb	t0, 4(a3)
	sb	t1, 5(a3)
	sb	t2, 6(a3)
	sb	t3, 7(a3)
	lbu	t0, 12(a1)
	lbu	t1, 13(a1)
	lbu	t2, 14(a1)
	lbu	t3, 15(a1)
	sb	a4, 8(a3)
	sb	a5, 9(a3)
	sb	a6, 10(a3)
	sb	a7, 11(a3)
	lbu	a4, 16(a1)
	lbu	a5, 17(a1)
	lbu	a6, 18(a1)
	lbu	a7, 19(a1)
	sb	t0, 12(a3)
	sb	t1, 13(a3)
	sb	t2, 14(a3)
	sb	t3, 15(a3)
	lbu	t0, 20(a1)
	lbu	t1, 21(a1)
	lbu	t2, 22(a1)
	lbu	t3, 23(a1)
	sb	a4, 16(a3)
	sb	a5, 17(a3)
	sb	a6, 18(a3)
	sb	a7, 19(a3)
	lbu	a4, 24(a1)
	lbu	a5, 25(a1)
	lbu	a6, 26(a1)
	lbu	a7, 27(a1)
	sb	t0, 20(a3)
	sb	t1, 21(a3)
	sb	t2, 22(a3)
	sb	t3, 23(a3)
	lbu	t0, 28(a1)
	lbu	t1, 29(a1)
	lbu	t2, 30(a1)
	lbu	t3, 31(a1)
	addi	a1, a1, 32
	sb	a4, 24(a3)
	sb	a5, 25(a3)
	sb	a6, 26(a3)
	sb	a7, 27(a3)
	addi	a4, a3, 32
	sb	t0, 28(a3)
	sb	t1, 29(a3)
	sb	t2, 30(a3)
	sb	t3, 31(a3)
	mv	a3, a4
	andi	a4, a2, 16
	beqz	a4, .LBBmemcpy0_10
.LBBmemcpy0_45:
	lbu	a4, 0(a1)
	lbu	a5, 1(a1)
	lbu	a6, 2(a1)
	lbu	a7, 3(a1)
	lbu	t0, 4(a1)
	lbu	t1, 5(a1)
	lbu	t2, 6(a1)
	lbu	t3, 7(a1)
	sb	a4, 0(a3)
	sb	a5, 1(a3)
	sb	a6, 2(a3)
	sb	a7, 3(a3)
	lbu	a4, 8(a1)
	lbu	a5, 9(a1)
	lbu	a6, 10(a1)
	lbu	a7, 11(a1)
	sb	t0, 4(a3)
	sb	t1, 5(a3)
	sb	t2, 6(a3)
	sb	t3, 7(a3)
	lbu	t0, 12(a1)
	lbu	t1, 13(a1)
	lbu	t2, 14(a1)
	lbu	t3, 15(a1)
	addi	a1, a1, 16
	sb	a4, 8(a3)
	sb	a5, 9(a3)
	sb	a6, 10(a3)
	sb	a7, 11(a3)
	addi	a4, a3, 16
	sb	t0, 12(a3)
	sb	t1, 13(a3)
	sb	t2, 14(a3)
	sb	t3, 15(a3)
	mv	a3, a4
	andi	a4, a2, 8
	beqz	a4, .LBBmemcpy0_11
.LBBmemcpy0_46:
	lbu	a4, 0(a1)
	lbu	a5, 1(a1)
	lbu	a6, 2(a1)
	lbu	a7, 3(a1)
	lbu	t0, 4(a1)
	lbu	t1, 5(a1)
	lbu	t2, 6(a1)
	lbu	t3, 7(a1)
	addi	a1, a1, 8
	sb	a4, 0(a3)
	sb	a5, 1(a3)
	sb	a6, 2(a3)
	sb	a7, 3(a3)
	addi	a4, a3, 8
	sb	t0, 4(a3)
	sb	t1, 5(a3)
	sb	t2, 6(a3)
	sb	t3, 7(a3)
	mv	a3, a4
	andi	a4, a2, 4
	beqz	a4, .LBBmemcpy0_48
.LBBmemcpy0_47:
	lbu	a4, 0(a1)
	lbu	a5, 1(a1)
	lbu	a6, 2(a1)
	lbu	a7, 3(a1)
	addi	a1, a1, 4
	addi	t0, a3, 4
	sb	a4, 0(a3)
	sb	a5, 1(a3)
	sb	a6, 2(a3)
	sb	a7, 3(a3)
	mv	a3, t0
.LBBmemcpy0_48:
	andi	a4, a2, 2
	bnez	a4, .LBBmemcpy0_51
# %bb.49:
	andi	a2, a2, 1
	bnez	a2, .LBBmemcpy0_52
.LBBmemcpy0_50:
	ret
.LBBmemcpy0_51:
	lbu	a4, 0(a1)
	lbu	a5, 1(a1)
	addi	a1, a1, 2
	addi	a6, a3, 2
	sb	a4, 0(a3)
	sb	a5, 1(a3)
	mv	a3, a6
	andi	a2, a2, 1
	beqz	a2, .LBBmemcpy0_50
.LBBmemcpy0_52:
	lbu	a1, 0(a1)
	sb	a1, 0(a3)
	ret
.Lfunc_end0:
	.size	memcpy, .Lfunc_end0-memcpy
	.section	.rodata,"a",@progbits
	.p2align	2, 0x0
.LJTI0_0:
	.word	.LBBmemcpy0_13
	.word	.LBBmemcpy0_35
	.word	.LBBmemcpy0_29
	.word	.LBBmemcpy0_32
	.word	.LBBmemcpy0_26
	.word	.LBBmemcpy0_38
	.word	.LBBmemcpy0_41
                                        # -- End function
	.ident	"Homebrew clang version 20.1.7"
	.section	".note.GNU-stack","",@progbits
	.addrsig
