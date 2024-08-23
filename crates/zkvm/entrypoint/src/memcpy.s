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
        andi    a3, a0, 3
        mv      t4, a2
        mv      a6, a1
        beqz    a3, .LBB0_5
        beqz    t4, .LBB0_5
        addi    a1, a0, 1
        li      a7, 1
        mv      a4, a0
.LBB0_3:
        lbu     a2, 0(a6)
        mv      a3, t4
        addi    a6, a6, 1
        sb      a2, 0(a4)
        addi    a4, a4, 1
        andi    a2, a1, 3
        addi    t4, t4, -1
        beqz    a2, .LBB0_6
        addi    a1, a1, 1
        bne     a3, a7, .LBB0_3
        j       .LBB0_6
.LBB0_5:
        mv      a4, a0
.LBB0_6:
        andi    a1, t4, 3
        beqz    a1, .LBB0_10
        addi    a5, t4, -1
.LBB0_8:
        add     a1, a6, a5
        lbu     a1, 0(a1)
        add     a2, a4, a5
        sb      a1, 0(a2)
        andi    a1, a5, 3
        addi    a5, a5, -1
        bnez    a1, .LBB0_8
        addi    t4, a5, 1
.LBB0_10:
        beqz    t4, .LBB0_15
        li      a1, 32
        andi    a7, a6, 3
        mv      t1, a0
        bltu    t4, a1, .LBB0_14
        li      t2, 305
        li      t3, 31
.LBB0_13:
        mv      t0, t2
        mv      a0, a6
        mv      a1, a4
        li      a2, 32
        mv      a3, a7
        ecall
        addi    a6, a6, 32
        addi    t4, t4, -32
        addi    a4, a4, 32
        bltu    t3, t4, .LBB0_13
.LBB0_14:
        li      a5, 305
        mv      t0, a5
        mv      a0, a6
        mv      a1, a4
        mv      a2, t4
        mv      a3, a7
        ecall
        mv      a0, t1
.LBB0_15:
        ret
	.size	memcpy, .-memcpy
	.ident	"GCC: (gc891d8dc23e1) 13.2.0"
