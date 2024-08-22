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
        mv      t1, a2
        mv      a5, a1
        beqz    a0, .LBB0_5
        beqz    t1, .LBB0_5
        addi    a0, a6, 1
        li      a7, 1
        mv      a3, a6
.LBB0_3:
        lbu     a1, 0(a5)
        mv      a2, t1
        addi    a5, a5, 1
        sb      a1, 0(a3)
        addi    a3, a3, 1
        andi    a1, a0, 3
        addi    t1, t1, -1
        beqz    a1, .LBB0_6
        addi    a0, a0, 1
        bne     a2, a7, .LBB0_3
        j       .LBB0_6
.LBB0_5:
        mv      a3, a6
.LBB0_6:
        lui     a0, 16
        addi    a4, a0, 305
        mv      t0, a4
        mv      a0, a5
        mv      a1, a3
        mv      a2, t1
        ecall
        mv      a0, a6
        ret
	.size	memcpy, .-memcpy
	.ident	"GCC: (gc891d8dc23e1) 13.2.0"
