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
        mv      a6, a0
        andi    a0, a0, 3
        mv      a5, a2
        mv      t2, a1
        beqz    a0, .LBB0_5
        beqz    a5, .LBB0_5
        addi    a0, a6, 1
        li      a7, 1
        mv      a3, a6
.LBB0_3:
        lbu     a1, 0(t2)
        mv      a2, a5
        addi    t2, t2, 1
        sb      a1, 0(a3)
        addi    a3, a3, 1
        andi    a1, a0, 3
        addi    a5, a5, -1
        beqz    a1, .LBB0_6
        addi    a0, a0, 1
        bne     a2, a7, .LBB0_3
        j       .LBB0_6
.LBB0_5:
        mv      a3, a6
.LBB0_6:
        li      a0, 32
        bltu    a5, a0, .LBB0_9
        lui     a0, 16
        addi    a7, a0, 305
        li      t1, 31
.LBB0_8:
        mv      t0, a7
        mv      a0, t2
        mv      a1, a3
        li      a2, 32
        ecall
        addi    t2, t2, 32
        addi    a5, a5, -32
        addi    a3, a3, 32
        bltu    t1, a5, .LBB0_8
.LBB0_9:
        lui     a0, 16
        addi    a4, a0, 305
        mv      t0, a4
        mv      a0, t2
        mv      a1, a3
        mv      a2, a5
        ecall
        mv      a0, a6
        ret
	.size	memcpy, .-memcpy
	.ident	"GCC: (gc891d8dc23e1) 13.2.0"
