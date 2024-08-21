// This is musl-libc commit 37e18b7bf307fa4a8c745feebfcba54a0ba74f30:
// 
// src/string/memcpy.c
// 
// This was compiled into assembly with:
// 
// clang-14 -target riscv32 -march=rv32im -O3 -S memcpy.c -nostdlib -fno-builtin -funroll-loops
// 
// and labels manually updated to not conflict.
// 
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
// (include/* and arch/* /bits/* ) and crt files intended to be linked into
// applications (crt/*, ldso/dlstart.c, and arch/* /crt_arch.h) to omit
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
	.file	"memcpy.c"
	.option nopic
	.attribute arch, "rv32im"
	.attribute unaligned_access, 0
	.attribute stack_align, 16
	.text
	.align	2
	.globl	memcpy
	.type	memcpy, @function
memcpy:
	andi	a4,a1,3
	addi	sp,sp,-32
	mv	a5,a1
	mv	a6,a0
	beq	a4,zero,.L27
	beq	a2,zero,.L40
	andi	a3,a2,7
	mv	a4,a0
	addi	a0,a2,-1
	beq	a3,zero,.L4
	li	a1,1
	beq	a3,a1,.L106
	li	t0,2
	beq	a3,t0,.L107
	li	t1,3
	beq	a3,t1,.L108
	li	t2,4
	beq	a3,t2,.L109
	li	a7,5
	beq	a3,a7,.L110
	li	t3,6
	bne	a3,t3,.L166
.L111:
	lbu	t5,0(a5)
	addi	a5,a5,1
	andi	t6,a5,3
	sb	t5,0(a4)
	addi	a2,a2,-1
	addi	a4,a4,1
	beq	t6,zero,.L2
.L110:
	lbu	a0,0(a5)
	addi	a5,a5,1
	andi	a3,a5,3
	sb	a0,0(a4)
	addi	a2,a2,-1
	addi	a4,a4,1
	beq	a3,zero,.L2
.L109:
	lbu	a1,0(a5)
	addi	a5,a5,1
	andi	t0,a5,3
	sb	a1,0(a4)
	addi	a2,a2,-1
	addi	a4,a4,1
	beq	t0,zero,.L2
.L108:
	lbu	t1,0(a5)
	addi	a5,a5,1
	andi	t2,a5,3
	sb	t1,0(a4)
	addi	a2,a2,-1
	addi	a4,a4,1
	beq	t2,zero,.L2
.L107:
	lbu	a7,0(a5)
	addi	a5,a5,1
	andi	t3,a5,3
	sb	a7,0(a4)
	addi	a2,a2,-1
	addi	a4,a4,1
	beq	t3,zero,.L2
.L106:
	lbu	t4,0(a5)
	addi	a5,a5,1
	andi	t5,a5,3
	sb	t4,0(a4)
	addi	a2,a2,-1
	addi	a4,a4,1
	beq	t5,zero,.L2
.L163:
	beq	a2,zero,.L167
.L4:
	lbu	a0,0(a5)
	addi	a5,a5,1
	addi	a4,a4,1
	addi	a2,a2,-1
	andi	t0,a5,3
	sb	a0,-1(a4)
	mv	a3,a5
	mv	a1,a4
	mv	t3,a2
	beq	t0,zero,.L2
	lbu	t1,0(a5)
	addi	a5,a5,1
	andi	a7,a5,3
	sb	t1,0(a4)
	addi	a2,a2,-1
	addi	a4,a4,1
	beq	a7,zero,.L2
	lbu	a4,1(a3)
	addi	a5,a3,2
	andi	t4,a5,3
	sb	a4,1(a1)
	addi	a2,t3,-2
	addi	a4,a1,2
	beq	t4,zero,.L2
	lbu	a2,2(a3)
	addi	a5,a3,3
	andi	t5,a5,3
	sb	a2,2(a1)
	addi	a4,a1,3
	addi	a2,t3,-3
	beq	t5,zero,.L2
	lbu	t6,3(a3)
	addi	a4,a1,4
	addi	a5,a3,4
	sb	t6,-1(a4)
	addi	a2,t3,-4
	beq	t0,zero,.L2
	lbu	a0,4(a3)
	addi	a5,a3,5
	andi	t0,a5,3
	sb	a0,4(a1)
	addi	a4,a1,5
	addi	a2,t3,-5
	beq	t0,zero,.L2
	lbu	t2,5(a3)
	addi	a5,a3,6
	andi	t1,a5,3
	sb	t2,5(a1)
	addi	a4,a1,6
	addi	a2,t3,-6
	beq	t1,zero,.L2
	lbu	a7,6(a3)
	addi	a5,a3,7
	andi	a3,a5,3
	sb	a7,6(a1)
	addi	a4,a1,7
	addi	a2,t3,-7
	bne	a3,zero,.L163
.L2:
	andi	a1,a4,3
	bne	a1,zero,.L8
	li	t5,63
	bleu	a2,t5,.L29
	addi	t4,a2,-64
	andi	t3,t4,-64
	addi	t2,t3,64
	addi	t1,t2,-64
	srli	a3,t1,6
	addi	a7,a3,1
	andi	a1,a7,7
	mv	a3,a5
	add	a7,a4,t2
	li	t6,305
	beq	a1,zero,.L10
	li	t0,1
	beq	a1,t0,.L112
	li	a0,2
	beq	a1,a0,.L113
	li	t5,3
	beq	a1,t5,.L114
	li	t4,4
	beq	a1,t4,.L115
	li	t3,5
	beq	a1,t3,.L116
	li	t1,6
	bne	a1,t1,.L168
.L117:
 #APP
# 23 "memcpy.c" 1
	mv t0, t6
mv a0, a3
mv a1, a4
ecall
# 0 "" 2
 #NO_APP
	addi	a3,a3,64
	addi	a4,a4,64
.L116:
 #APP
# 23 "memcpy.c" 1
	mv t0, t6
mv a0, a3
mv a1, a4
ecall
# 0 "" 2
 #NO_APP
	addi	a3,a3,64
	addi	a4,a4,64
.L115:
 #APP
# 23 "memcpy.c" 1
	mv t0, t6
mv a0, a3
mv a1, a4
ecall
# 0 "" 2
 #NO_APP
	addi	a3,a3,64
	addi	a4,a4,64
.L114:
 #APP
# 23 "memcpy.c" 1
	mv t0, t6
mv a0, a3
mv a1, a4
ecall
# 0 "" 2
 #NO_APP
	addi	a3,a3,64
	addi	a4,a4,64
.L113:
 #APP
# 23 "memcpy.c" 1
	mv t0, t6
mv a0, a3
mv a1, a4
ecall
# 0 "" 2
 #NO_APP
	addi	a3,a3,64
	addi	a4,a4,64
.L112:
 #APP
# 23 "memcpy.c" 1
	mv t0, t6
mv a0, a3
mv a1, a4
ecall
# 0 "" 2
 #NO_APP
	addi	a4,a4,64
	addi	a3,a3,64
	beq	a4,a7,.L153
.L10:
 #APP
# 23 "memcpy.c" 1
	mv t0, t6
mv a0, a3
mv a1, a4
ecall
# 0 "" 2
 #NO_APP
	addi	t4,a3,64
	addi	t5,a4,64
 #APP
# 23 "memcpy.c" 1
	mv t0, t6
mv a0, t4
mv a1, t5
ecall
# 0 "" 2
 #NO_APP
	addi	t3,a3,128
	addi	t1,a4,128
 #APP
# 23 "memcpy.c" 1
	mv t0, t6
mv a0, t3
mv a1, t1
ecall
# 0 "" 2
 #NO_APP
	addi	t4,a3,192
	addi	t5,a4,192
 #APP
# 23 "memcpy.c" 1
	mv t0, t6
mv a0, t4
mv a1, t5
ecall
# 0 "" 2
 #NO_APP
	addi	t3,a3,256
	addi	t1,a4,256
 #APP
# 23 "memcpy.c" 1
	mv t0, t6
mv a0, t3
mv a1, t1
ecall
# 0 "" 2
 #NO_APP
	addi	t4,a3,320
	addi	t5,a4,320
 #APP
# 23 "memcpy.c" 1
	mv t0, t6
mv a0, t4
mv a1, t5
ecall
# 0 "" 2
 #NO_APP
	addi	t3,a3,384
	addi	t1,a4,384
 #APP
# 23 "memcpy.c" 1
	mv t0, t6
mv a0, t3
mv a1, t1
ecall
# 0 "" 2
 #NO_APP
	addi	t4,a3,448
	addi	t5,a4,448
 #APP
# 23 "memcpy.c" 1
	mv t0, t6
mv a0, t4
mv a1, t5
ecall
# 0 "" 2
 #NO_APP
	addi	a4,a4,512
	addi	a3,a3,512
	bne	a4,a7,.L10
.L153:
	add	a5,a5,t2
	andi	t6,a2,63
.L9:
	li	a4,31
	bleu	t6,a4,.L11
	li	a2,304
 #APP
# 34 "memcpy.c" 1
	mv t0, a2
mv a0, a5
mv a1, a7
ecall
# 0 "" 2
 #NO_APP
	addi	a5,a5,32
	addi	a7,a7,32
	andi	t6,t6,31
.L11:
	li	t2,15
	bleu	t6,t2,.L12
	lw	t0,4(a5)
	lw	a1,8(a5)
	lw	a0,12(a5)
	lw	a3,0(a5)
	sw	t0,4(a7)
	sw	a1,8(a7)
	sw	a3,0(a7)
	sw	a0,12(a7)
	addi	a5,a5,16
	addi	a7,a7,16
	addi	t6,t6,-16
.L12:
	andi	t3,t6,8
	beq	t3,zero,.L13
	lw	t1,4(a5)
	lw	t4,0(a5)
	addi	a7,a7,8
	addi	a5,a5,8
	sw	t1,-4(a7)
	sw	t4,-8(a7)
.L13:
	andi	t5,t6,4
	beq	t5,zero,.L6
	lw	a4,0(a5)
	addi	a7,a7,4
	addi	a5,a5,4
	sw	a4,-4(a7)
.L6:
	andi	a2,t6,2
	beq	a2,zero,.L14
	lbu	t2,0(a5)
	lbu	t0,1(a5)
	addi	a7,a7,2
	sb	t2,-2(a7)
	sb	t0,-1(a7)
	addi	a5,a5,2
.L14:
	andi	t6,t6,1
	beq	t6,zero,.L40
	lbu	a5,0(a5)
	sb	a5,0(a7)
.L40:
	mv	a0,a6
	addi	sp,sp,32
	jr	ra
.L8:
	sw	s0,28(sp)
	sw	s1,24(sp)
	sw	s2,20(sp)
	li	s0,31
	bleu	a2,s0,.L159
	li	s1,2
	lbu	s2,0(a5)
	lw	a3,0(a5)
	beq	a1,s1,.L18
	addi	t4,a2,-20
	li	t6,3
	andi	t2,t4,-16
	beq	a1,t6,.L19
	addi	t0,t2,19
	addi	t6,a4,3
	add	t5,a4,t0
	lbu	a0,1(a5)
	lbu	a1,2(a5)
	sub	s1,t5,t6
	addi	s0,s1,-16
	srli	a7,s0,4
	addi	t0,a5,3
	sb	a0,1(a4)
	sb	a1,2(a4)
	sb	s2,0(a4)
	andi	t3,a7,1
	srli	t4,t4,4
	mv	a1,t0
	mv	a0,t6
	bne	t3,zero,.L160
	lw	s1,1(t0)
	lw	a0,5(t0)
	lw	a1,9(t0)
	srli	t1,a3,24
	lw	a3,13(t0)
	slli	s2,s1,8
	srli	a7,s1,24
	slli	s0,a1,8
	slli	s1,a0,8
	srli	a1,a1,24
	srli	a0,a0,24
	slli	t3,a3,8
	or	t1,t1,s2
	or	s2,a7,s1
	or	a7,a0,s0
	or	s1,a1,t3
	sw	t1,0(t6)
	sw	s2,4(t6)
	sw	a7,8(t6)
	sw	s1,12(t6)
	addi	a0,a4,19
	addi	a1,a5,19
	beq	a0,t5,.L154
.L160:
	sw	s3,16(sp)
	sw	s4,12(sp)
	sw	s5,8(sp)
	sw	s6,4(sp)
	sw	s7,0(sp)
.L20:
	lw	s6,1(a1)
	lw	s5,5(a1)
	lw	s4,9(a1)
	lw	s3,13(a1)
	lw	a7,17(a1)
	lw	a4,21(a1)
	lw	a5,25(a1)
	srli	s2,a3,24
	lw	a3,29(a1)
	slli	s7,s6,8
	srli	s1,s6,24
	srli	s0,s5,24
	slli	s6,s5,8
	srli	t3,s4,24
	slli	s5,s4,8
	slli	s4,s3,8
	srli	t1,s3,24
	or	s2,s2,s7
	slli	s3,a7,8
	or	s7,s1,s6
	srli	a7,a7,24
	or	s1,s0,s5
	or	s6,t3,s4
	slli	s5,a4,8
	slli	t3,a5,8
	srli	a4,a4,24
	srli	a5,a5,24
	slli	s4,a3,8
	or	s0,t1,s3
	sw	s2,0(a0)
	or	t1,a7,s5
	or	s3,a4,t3
	or	s2,a5,s4
	sw	s7,4(a0)
	sw	s1,8(a0)
	sw	s6,12(a0)
	sw	s0,16(a0)
	sw	t1,20(a0)
	sw	s3,24(a0)
	sw	s2,28(a0)
	addi	a0,a0,32
	addi	a1,a1,32
	bne	a0,t5,.L20
	lw	s3,16(sp)
	lw	s4,12(sp)
	lw	s5,8(sp)
	lw	s6,4(sp)
	lw	s7,0(sp)
.L154:
	addi	a3,t4,1
	slli	t5,a3,4
	addi	a2,a2,-19
	j	.L164
.L167:
	andi	t6,a4,3
	beq	t6,zero,.L169
.L17:
	andi	t2,a2,16
	andi	a3,a2,8
	andi	a7,a2,4
	andi	a0,a2,2
	andi	a2,a2,1
	beq	t2,zero,.L23
	sw	s0,28(sp)
	sw	s1,24(sp)
	sw	s2,20(sp)
	sw	s3,16(sp)
	sw	s4,12(sp)
	sw	s5,8(sp)
	sw	s6,4(sp)
	sw	s7,0(sp)
	lbu	s7,0(a5)
	lbu	s6,1(a5)
	lbu	s5,2(a5)
	lbu	s4,3(a5)
	lbu	s3,4(a5)
	lbu	s2,5(a5)
	lbu	s1,6(a5)
	lbu	s0,7(a5)
	lbu	t0,9(a5)
	lbu	t6,10(a5)
	lbu	t5,11(a5)
	lbu	t4,12(a5)
	lbu	t3,13(a5)
	lbu	t1,14(a5)
	lbu	a1,15(a5)
	lbu	t2,8(a5)
	sb	s7,0(a4)
	sb	s6,1(a4)
	sb	s5,2(a4)
	sb	s4,3(a4)
	sb	s3,4(a4)
	sb	s2,5(a4)
	sb	s1,6(a4)
	sb	s0,7(a4)
	sb	t2,8(a4)
	sb	t0,9(a4)
	sb	t6,10(a4)
	sb	t5,11(a4)
	sb	t4,12(a4)
	sb	t3,13(a4)
	sb	t1,14(a4)
	sb	a1,15(a4)
	lw	s0,28(sp)
	lw	s1,24(sp)
	lw	s2,20(sp)
	lw	s3,16(sp)
	lw	s4,12(sp)
	lw	s5,8(sp)
	lw	s6,4(sp)
	lw	s7,0(sp)
	addi	a5,a5,16
	addi	a4,a4,16
.L23:
	beq	a3,zero,.L24
	lbu	t2,0(a5)
	lbu	t0,1(a5)
	lbu	t6,2(a5)
	lbu	t5,3(a5)
	lbu	t4,4(a5)
	lbu	t3,5(a5)
	lbu	t1,6(a5)
	lbu	a3,7(a5)
	sb	t2,0(a4)
	sb	t0,1(a4)
	sb	t6,2(a4)
	sb	t5,3(a4)
	sb	t4,4(a4)
	sb	t3,5(a4)
	sb	t1,6(a4)
	sb	a3,7(a4)
	addi	a5,a5,8
	addi	a4,a4,8
.L24:
	beq	a7,zero,.L25
	lbu	t2,0(a5)
	lbu	a7,1(a5)
	lbu	a1,2(a5)
	lbu	t0,3(a5)
	sb	t2,0(a4)
	sb	a7,1(a4)
	sb	a1,2(a4)
	sb	t0,3(a4)
	addi	a5,a5,4
	addi	a4,a4,4
.L25:
	beq	a0,zero,.L7
	lbu	a0,0(a5)
	lbu	t6,1(a5)
	addi	a4,a4,2
	sb	a0,-2(a4)
	sb	t6,-1(a4)
	addi	a5,a5,2
.L7:
	beq	a2,zero,.L40
	lbu	a5,0(a5)
	mv	a0,a6
	sb	a5,0(a4)
	addi	sp,sp,32
	jr	ra
.L166:
	lbu	a2,0(a5)
	addi	a5,a5,1
	andi	t4,a5,3
	sb	a2,0(a6)
	addi	a4,a6,1
	mv	a2,a0
	bne	t4,zero,.L111
	j	.L2
.L19:
	addi	t0,t2,17
	addi	t6,a4,1
	add	t5,a4,t0
	sub	a0,t5,t6
	addi	a1,a0,-16
	srli	s1,a1,4
	addi	t0,a5,1
	sb	s2,0(a4)
	andi	s0,s1,1
	srli	t4,t4,4
	mv	a1,t0
	mv	a0,t6
	bne	s0,zero,.L161
	lw	t3,7(t0)
	lw	a7,3(t0)
	lw	a1,11(t0)
	srli	t1,a3,8
	lw	a3,15(t0)
	slli	s2,a7,24
	slli	s1,t3,24
	srli	a0,t3,8
	srli	a7,a7,8
	slli	s0,a1,24
	slli	t3,a3,24
	srli	a1,a1,8
	or	t1,t1,s2
	or	s2,a7,s1
	or	a7,a0,s0
	or	s1,a1,t3
	sw	t1,0(t6)
	sw	s2,4(t6)
	sw	a7,8(t6)
	sw	s1,12(t6)
	addi	a0,a4,17
	addi	a1,a5,17
	beq	a0,t5,.L155
.L161:
	sw	s3,16(sp)
	sw	s4,12(sp)
	sw	s5,8(sp)
	sw	s6,4(sp)
	sw	s7,0(sp)
.L22:
	lw	s6,3(a1)
	lw	s5,7(a1)
	lw	s4,11(a1)
	lw	s3,15(a1)
	lw	a7,19(a1)
	lw	a4,23(a1)
	lw	a5,27(a1)
	srli	s2,a3,8
	lw	a3,31(a1)
	slli	s7,s6,24
	srli	s1,s6,8
	srli	s0,s5,8
	slli	s6,s5,24
	srli	t3,s4,8
	slli	s5,s4,24
	slli	s4,s3,24
	srli	t1,s3,8
	or	s2,s2,s7
	slli	s3,a7,24
	or	s7,s1,s6
	srli	a7,a7,8
	or	s1,s0,s5
	or	s6,t3,s4
	slli	s5,a4,24
	slli	t3,a5,24
	srli	a4,a4,8
	srli	a5,a5,8
	slli	s4,a3,24
	or	s0,t1,s3
	sw	s2,0(a0)
	or	t1,a7,s5
	or	s3,a4,t3
	or	s2,a5,s4
	sw	s7,4(a0)
	sw	s1,8(a0)
	sw	s6,12(a0)
	sw	s0,16(a0)
	sw	t1,20(a0)
	sw	s3,24(a0)
	sw	s2,28(a0)
	addi	a0,a0,32
	addi	a1,a1,32
	bne	a0,t5,.L22
	lw	s3,16(sp)
	lw	s4,12(sp)
	lw	s5,8(sp)
	lw	s6,4(sp)
	lw	s7,0(sp)
.L155:
	addi	a3,t4,1
	slli	t5,a3,4
	addi	a2,a2,-17
.L164:
	lw	s0,28(sp)
	lw	s1,24(sp)
	lw	s2,20(sp)
	add	a5,t0,t5
	add	a4,t6,t5
	sub	a2,a2,t2
	j	.L17
.L18:
	addi	t3,a2,-20
	andi	t2,t3,-16
	addi	t4,t2,18
	addi	t6,a4,2
	add	t5,a4,t4
	lbu	a0,1(a5)
	sub	t0,t5,t6
	addi	t1,t0,-16
	srli	a7,t1,4
	addi	t0,a5,2
	sb	a0,1(a4)
	sb	s2,0(a4)
	andi	s0,a7,1
	srli	t4,t3,4
	mv	a1,t0
	mv	a0,t6
	bne	s0,zero,.L162
	lw	s1,2(t0)
	lw	t3,6(t0)
	lw	a1,10(t0)
	srli	t1,a3,16
	lw	a3,14(t0)
	slli	s2,s1,16
	srli	a7,s1,16
	srli	a0,t3,16
	slli	s1,t3,16
	slli	s0,a1,16
	slli	t3,a3,16
	srli	a1,a1,16
	or	t1,t1,s2
	or	s2,a7,s1
	or	a7,a0,s0
	or	s1,a1,t3
	sw	t1,0(t6)
	sw	s2,4(t6)
	sw	a7,8(t6)
	sw	s1,12(t6)
	addi	a0,a4,18
	addi	a1,a5,18
	beq	a0,t5,.L156
.L162:
	sw	s3,16(sp)
	sw	s4,12(sp)
	sw	s5,8(sp)
	sw	s6,4(sp)
	sw	s7,0(sp)
.L21:
	lw	s3,2(a1)
	lw	s4,6(a1)
	lw	t3,10(a1)
	lw	t1,14(a1)
	lw	a7,18(a1)
	lw	a4,22(a1)
	lw	a5,26(a1)
	srli	s2,a3,16
	lw	a3,30(a1)
	slli	s7,s3,16
	srli	s1,s3,16
	slli	s6,s4,16
	srli	s0,s4,16
	slli	s5,t3,16
	slli	s4,t1,16
	srli	t3,t3,16
	slli	s3,a7,16
	or	s2,s2,s7
	srli	t1,t1,16
	or	s7,s1,s6
	srli	a7,a7,16
	or	s1,s0,s5
	or	s6,t3,s4
	slli	s5,a4,16
	slli	t3,a5,16
	srli	a4,a4,16
	srli	a5,a5,16
	slli	s4,a3,16
	or	s0,t1,s3
	sw	s2,0(a0)
	or	t1,a7,s5
	or	s3,a4,t3
	or	s2,a5,s4
	sw	s7,4(a0)
	sw	s1,8(a0)
	sw	s6,12(a0)
	sw	s0,16(a0)
	sw	t1,20(a0)
	sw	s3,24(a0)
	sw	s2,28(a0)
	addi	a0,a0,32
	addi	a1,a1,32
	bne	a0,t5,.L21
	lw	s3,16(sp)
	lw	s4,12(sp)
	lw	s5,8(sp)
	lw	s6,4(sp)
	lw	s7,0(sp)
.L156:
	addi	t5,t4,1
	slli	t5,t5,4
	addi	a2,a2,-18
	j	.L164
.L27:
	mv	a4,a0
	j	.L2
.L159:
	lw	s0,28(sp)
	lw	s1,24(sp)
	lw	s2,20(sp)
	j	.L17
.L168:
 #APP
# 23 "memcpy.c" 1
	mv t0, t6
mv a0, a5
mv a1, a4
ecall
# 0 "" 2
 #NO_APP
	addi	a3,a5,64
	addi	a4,a4,64
	j	.L117
.L169:
	mv	a7,a4
	j	.L11
.L29:
	mv	a7,a4
	mv	t6,a2
	j	.L9
	.size	memcpy, .-memcpy
	.ident	"GCC: (gc891d8dc23e1) 13.2.0"
