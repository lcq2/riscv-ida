.section .text
.global _start
_start:
	mul a0, a1, s2
	mul a2, a3, s1
	mul s0, s1, a0
	mul t0, t1, t1
	mulh a0, a2, a3
	mulhsu t0, s2, t4
	mulhu t1, t2, s4
	div a0, a1, a4
	divu a2, a3, a0
	rem a0, a1, a1
	remu a2, a3, a4
