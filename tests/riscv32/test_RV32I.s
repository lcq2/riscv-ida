.section .text
.global _start
_start:
	lui a0, %hi(0x40010000)
	addi a0, a0, %lo(0x40010000)
1:	auipc a0, %pcrel_hi(bogus)
	addi a0, a0, %pcrel_lo(1b)
1:
	li a0, 0x12345678
	li a1, 0xabcdef12
	li a2, 0x34abcdef
	nop
	jal 1b
	jalr t0
	beq a0, a1, 2f
	bne a0, a1, 2f
	blt a0, a1, 2f
	bge a0, a1, 2f
	bltu a0, a1, 2f
	bgeu a0, a1, 2f
2:
	lb t0, 8(a0)
	lh t0, 8(a1)
	lw t0, 8(a2)
	lbu t0, 8(a3)
	lhu t0, 8(a4)
	sb t0, 8(a0)
	sh t0, 8(a1)
	sw t0, 8(a2)

3:
	addi a0, a1, -5
	addi a2, a3, 5
	addi t0, t1, -578
	addi a0, a1, 542

	andi a0, a1, 0x23
	andi a2, a3, 0x11

	slti a0, a1, 4
	sltiu a1, a2, 5

	xori t2, t3, 0x23
	xori a0, a1, 0x11

	ori s0, s1, 0x32
	ori s1, a1, 0x11

	slli s0, s1, 8
	srli a1, a4, 30
	srai a1, a5, 30

	add a0, a1, a2
	sub a3, a4, a5
	sll s0, s1, s2
	slt s1, a2, a1
	sltu a0, a1, a2
	xor a0, a1, a2
	srl a0, a1, a2
	sra s0, s1, s2
	or a1, a2, a3
	and s0, a1, t0
bogus:
	.long 0xDEADDEAD
