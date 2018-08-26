.section .text
.global _start
_start:
	li a0, 1
	mv a1, a0
	lr.w t0, 0(a0)
	lr.w.aq t0, 0(a0)
	lr.w.rl t0, 0(a0)
	sc.w a0, a2, (a0)
	sc.w.aq a0, a2, (a0)
	sc.w.rl a0, a2, (a0)
	amoswap.w a0, a3, (a1)
	amoadd.w a0, a3, (a1)
	amoand.w a0, a3, (a1)
	amoor.w a0, a3, (a1)
	amoxor.w a0, a3, (a1)
	amomax.w a0, a3, (a1)
	amomin.w a0, a3, (a1)
	amomaxu.w a0, a3, (a1)
	amominu.w a0, a3, (a1)
