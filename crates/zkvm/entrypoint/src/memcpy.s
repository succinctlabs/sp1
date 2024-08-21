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
        andi    a5, a7, 3
        beqz    a5, .LBB0_17
.LBB0_7:
        li      a3, 32
        bgeu    a2, a3, .LBB0_11
        li      a3, 16
        bgeu    a2, a3, .LBB0_32
.LBB0_9:
        andi    a3, a2, 8
        bnez    a3, .LBB0_33
.LBB0_10:
        andi    a3, a2, 4
        bnez    a3, .LBB0_34
        j       .LBB0_35
.LBB0_11:
        lw      a4, 0(a1)
        li      a3, 3
        beq     a5, a3, .LBB0_26
        li      a3, 2
        bne     a5, a3, .LBB0_29
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
        j       .LBB0_32
.LBB0_16:
        mv      a7, a0
        andi    a5, a0, 3
        bnez    a5, .LBB0_7
.LBB0_17:
        andi    a3, a2, 3
        beqz    a3, .LBB0_25
        li      a3, 16
        bltu    a2, a3, .LBB0_21
        li      a6, 15
.LBB0_20:
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
        bltu    a6, a2, .LBB0_20
.LBB0_21:
        li      a3, 8
        bltu    a2, a3, .LBB0_23
        lw      a3, 0(a1)
        lw      a4, 4(a1)
        sw      a3, 0(a7)
        sw      a4, 4(a7)
        addi    a7, a7, 8
        addi    a1, a1, 8
.LBB0_23:
        andi    a3, a2, 4
        beqz    a3, .LBB0_35
        lw      a3, 0(a1)
        sw      a3, 0(a7)
        addi    a7, a7, 4
        addi    a1, a1, 4
        j       .LBB0_35
.LBB0_25:
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
.LBB0_26:
        sb      a4, 0(a7)
        addi    a7, a7, 1
        addi    a2, a2, -1
        addi    a1, a1, 16
        li      a6, 18
.LBB0_27:
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
        bltu    a6, a2, .LBB0_27
        addi    a1, a1, -15
        li      a3, 16
        bltu    a2, a3, .LBB0_9
        j       .LBB0_32
.LBB0_29:
        sb      a4, 0(a7)
        srli    a3, a4, 8
        sb      a3, 1(a7)
        srli    a3, a4, 16
        sb      a3, 2(a7)
        addi    a7, a7, 3
        addi    a2, a2, -3
        addi    a1, a1, 16
        li      a6, 16
.LBB0_30:
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
        bltu    a6, a2, .LBB0_30
        addi    a1, a1, -13
        li      a3, 16
        bltu    a2, a3, .LBB0_9
.LBB0_32:
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
        addi    a1, a1, 8
        addi    a3, a7, 8
        sb      a4, 7(a7)
        mv      a7, a3
        andi    a3, a2, 4
        beqz    a3, .LBB0_35
.LBB0_34:
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
.LBB0_35:
        andi    a3, a2, 2
        bnez    a3, .LBB0_38
        andi    a2, a2, 1
        bnez    a2, .LBB0_39
.LBB0_37:
        ret
.LBB0_38:
        lbu     a3, 0(a1)
        lbu     a4, 1(a1)
        sb      a3, 0(a7)
        addi    a1, a1, 2
        addi    a3, a7, 2
        sb      a4, 1(a7)
        mv      a7, a3
        andi    a2, a2, 1
        beqz    a2, .LBB0_37
.LBB0_39:
        lbu     a1, 0(a1)
        sb      a1, 0(a7)
        ret
	.size	memcpy, .-memcpy
	.ident	"GCC: (gc891d8dc23e1) 13.2.0"
