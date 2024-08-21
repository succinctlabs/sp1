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
        andi    a3, a1, 3
        beqz    a3, .LBB0_16
        beqz    a2, .LBB0_5
        addi    a4, a1, 1
        li      a6, 1
        mv      a7, a0
.LBB0_3:
        lbu     a3, 0(a1)
        mv      a5, a2
        addi    a1, a1, 1
        sb      a3, 0(a7)
        addi    a7, a7, 1
        andi    a3, a4, 3
        addi    a2, a2, -1
        beqz    a3, .LBB0_6
        addi    a4, a4, 1
        bne     a5, a6, .LBB0_3
        j       .LBB0_6
.LBB0_5:
        mv      a7, a0
.LBB0_6:
        li      a3, 32
        andi    a5, a7, 3
        beqz    a5, .LBB0_17
.LBB0_7:
        bgeu    a2, a3, .LBB0_11
        li      a3, 16
        bgeu    a2, a3, .LBB0_33
.LBB0_9:
        andi    a3, a2, 8
        bnez    a3, .LBB0_34
.LBB0_10:
        andi    a3, a2, 4
        bnez    a3, .LBB0_35
        j       .LBB0_36
.LBB0_11:
        lw      a4, 0(a1)
        li      a3, 3
        beq     a5, a3, .LBB0_27
        li      a3, 2
        bne     a5, a3, .LBB0_30
        sb      a4, 0(a7)
        srli    a3, a4, 8
        sb      a3, 1(a7)
        addi    a7, a7, 2
        addi    a2, a2, -2
        addi    a1, a1, 16
        li      a6, 17
.LBB0_14:
        lw      a3, -12(a1)
        srli    t0, a4, 16
        slli    a5, a3, 16
        lw      a4, -8(a1)
        or      a5, a5, t0
        sw      a5, 0(a7)
        srli    t0, a3, 16
        slli    a5, a4, 16
        lw      a3, -4(a1)
        or      a5, a5, t0
        sw      a5, 4(a7)
        srli    t0, a4, 16
        slli    a5, a3, 16
        lw      a4, 0(a1)
        or      a5, a5, t0
        sw      a5, 8(a7)
        srli    a3, a3, 16
        slli    a5, a4, 16
        or      a3, a3, a5
        sw      a3, 12(a7)
        addi    a7, a7, 16
        addi    a2, a2, -16
        addi    a1, a1, 16
        bltu    a6, a2, .LBB0_14
        addi    a1, a1, -14
        li      a3, 16
        bltu    a2, a3, .LBB0_9
        j       .LBB0_33
.LBB0_16:
        mv      a7, a0
        li      a3, 32
        andi    a5, a0, 3
        bnez    a5, .LBB0_7
.LBB0_17:
        bltu    a3, a2, .LBB0_20
        andi    a3, a2, 3
        bnez    a3, .LBB0_20
        li      a3, 305
        mv      a6, a0
        mv      a5, a2
        mv      a4, a1
        mv      t0, a3
        mv      a0, a4
        mv      a1, a7
        mv      a2, a5
        ecall
        mv      a0, a6
        ret
.LBB0_20:
        li      a3, 16
        bltu    a2, a3, .LBB0_23
        li      a6, 15
.LBB0_22:
        lw      t0, 0(a1)
        lw      a5, 4(a1)
        lw      a4, 8(a1)
        lw      a3, 12(a1)
        sw      t0, 0(a7)
        sw      a5, 4(a7)
        sw      a4, 8(a7)
        sw      a3, 12(a7)
        addi    a1, a1, 16
        addi    a2, a2, -16
        addi    a7, a7, 16
        bltu    a6, a2, .LBB0_22
.LBB0_23:
        li      a3, 8
        bltu    a2, a3, .LBB0_25
        lw      a3, 0(a1)
        lw      a4, 4(a1)
        sw      a3, 0(a7)
        sw      a4, 4(a7)
        addi    a7, a7, 8
        addi    a1, a1, 8
.LBB0_25:
        andi    a3, a2, 4
        beqz    a3, .LBB0_36
        lw      a3, 0(a1)
        sw      a3, 0(a7)
        addi    a7, a7, 4
        addi    a1, a1, 4
        j       .LBB0_36
.LBB0_27:
        sb      a4, 0(a7)
        addi    a7, a7, 1
        addi    a2, a2, -1
        addi    a1, a1, 16
        li      a6, 18
.LBB0_28:
        lw      a3, -12(a1)
        srli    t0, a4, 8
        slli    a5, a3, 24
        lw      a4, -8(a1)
        or      a5, a5, t0
        sw      a5, 0(a7)
        srli    t0, a3, 8
        slli    a5, a4, 24
        lw      a3, -4(a1)
        or      a5, a5, t0
        sw      a5, 4(a7)
        srli    t0, a4, 8
        slli    a5, a3, 24
        lw      a4, 0(a1)
        or      a5, a5, t0
        sw      a5, 8(a7)
        srli    a3, a3, 8
        slli    a5, a4, 24
        or      a3, a3, a5
        sw      a3, 12(a7)
        addi    a7, a7, 16
        addi    a2, a2, -16
        addi    a1, a1, 16
        bltu    a6, a2, .LBB0_28
        addi    a1, a1, -15
        li      a3, 16
        bltu    a2, a3, .LBB0_9
        j       .LBB0_33
.LBB0_30:
        sb      a4, 0(a7)
        srli    a3, a4, 8
        sb      a3, 1(a7)
        srli    a3, a4, 16
        sb      a3, 2(a7)
        addi    a7, a7, 3
        addi    a2, a2, -3
        addi    a1, a1, 16
        li      a6, 16
.LBB0_31:
        lw      a3, -12(a1)
        srli    t0, a4, 24
        slli    a5, a3, 8
        lw      a4, -8(a1)
        or      a5, a5, t0
        sw      a5, 0(a7)
        srli    t0, a3, 24
        slli    a5, a4, 8
        lw      a3, -4(a1)
        or      a5, a5, t0
        sw      a5, 4(a7)
        srli    t0, a4, 24
        slli    a5, a3, 8
        lw      a4, 0(a1)
        or      a5, a5, t0
        sw      a5, 8(a7)
        srli    a3, a3, 24
        slli    a5, a4, 8
        or      a3, a3, a5
        sw      a3, 12(a7)
        addi    a7, a7, 16
        addi    a2, a2, -16
        addi    a1, a1, 16
        bltu    a6, a2, .LBB0_31
        addi    a1, a1, -13
        li      a3, 16
        bltu    a2, a3, .LBB0_9
.LBB0_33:
        lbu     a3, 0(a1)
        lbu     a4, 1(a1)
        lbu     a5, 2(a1)
        sb      a3, 0(a7)
        sb      a4, 1(a7)
        lbu     a3, 3(a1)
        sb      a5, 2(a7)
        lbu     a4, 4(a1)
        lbu     a5, 5(a1)
        sb      a3, 3(a7)
        lbu     a3, 6(a1)
        sb      a4, 4(a7)
        sb      a5, 5(a7)
        lbu     a4, 7(a1)
        sb      a3, 6(a7)
        lbu     a3, 8(a1)
        lbu     a5, 9(a1)
        sb      a4, 7(a7)
        lbu     a4, 10(a1)
        sb      a3, 8(a7)
        sb      a5, 9(a7)
        lbu     a3, 11(a1)
        sb      a4, 10(a7)
        lbu     a4, 12(a1)
        lbu     a5, 13(a1)
        sb      a3, 11(a7)
        lbu     a3, 14(a1)
        sb      a4, 12(a7)
        sb      a5, 13(a7)
        lbu     a4, 15(a1)
        sb      a3, 14(a7)
        addi    a1, a1, 16
        addi    a3, a7, 16
        sb      a4, 15(a7)
        mv      a7, a3
        andi    a3, a2, 8
        beqz    a3, .LBB0_10
.LBB0_34:
        lbu     a3, 0(a1)
        lbu     a4, 1(a1)
        lbu     a5, 2(a1)
        sb      a3, 0(a7)
        sb      a4, 1(a7)
        lbu     a3, 3(a1)
        sb      a5, 2(a7)
        lbu     a4, 4(a1)
        lbu     a5, 5(a1)
        sb      a3, 3(a7)
        lbu     a3, 6(a1)
        sb      a4, 4(a7)
        sb      a5, 5(a7)
        lbu     a4, 7(a1)
        sb      a3, 6(a7)
        addi    a1, a1, 8
        addi    a3, a7, 8
        sb      a4, 7(a7)
        mv      a7, a3
        andi    a3, a2, 4
        beqz    a3, .LBB0_36
.LBB0_35:
        lbu     a3, 0(a1)
        lbu     a4, 1(a1)
        lbu     a5, 2(a1)
        sb      a3, 0(a7)
        sb      a4, 1(a7)
        lbu     a3, 3(a1)
        sb      a5, 2(a7)
        addi    a1, a1, 4
        addi    a4, a7, 4
        sb      a3, 3(a7)
        mv      a7, a4
.LBB0_36:
        andi    a3, a2, 2
        bnez    a3, .LBB0_39
        andi    a2, a2, 1
        bnez    a2, .LBB0_40
.LBB0_38:
        ret
.LBB0_39:
        lbu     a3, 0(a1)
        lbu     a4, 1(a1)
        sb      a3, 0(a7)
        addi    a1, a1, 2
        addi    a3, a7, 2
        sb      a4, 1(a7)
        mv      a7, a3
        andi    a2, a2, 1
        beqz    a2, .LBB0_38
.LBB0_40:
        lbu     a1, 0(a1)
        sb      a1, 0(a7)
        ret
	.size	memcpy, .-memcpy
	.ident	"GCC: (gc891d8dc23e1) 13.2.0"
