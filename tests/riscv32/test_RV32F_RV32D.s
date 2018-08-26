.section .text
.global _start
_start:
	## float
	# load/store
	flw ft0, 8(a0)
	fsw ft0, 8(a0)

	# multiply-add
	fmadd.s ft0, ft1, ft2, ft4
	fmsub.s ft1, ft2, ft3, ft5
	fnmadd.s ft0, ft1, ft2, ft4
	fnmsub.s ft1, ft2, ft3, ft5

	# op
	fadd.s ft0, ft1, ft2
	fsub.s ft0, ft1, ft2
	fmul.s ft0, ft1, ft2
	fdiv.s ft0, ft1, ft2

	# sqrt
	fsqrt.s ft0, ft1

	# fsgnj
	fsgnj.s ft0, ft1, ft2
	fsgnjn.s ft0, ft1, ft2
	fsgnjx.s ft0, ft1, ft2

	# fmin/fmax
	fmin.s ft0, ft1, ft2
	fmax.s ft0, ft1, ft2

	# fcvt.s
	fcvt.w.s a0, ft0
	fcvt.wu.s a0, ft0

	# fmv
	fmv.x.w a0, ft0

	# feq/flt/fle
	feq.s a0, ft0, ft1
	flt.s a0, ft0, ft1
	fle.s a0, ft0, ft1

	# fclass
	fclass.s a0, ft0

	# fcvt.s
	fcvt.s.w ft0, a0
	fcvt.s.wu ft0, a0

	# fmv
	fmv.w.x ft0, a0

	## double
	fld ft0, 8(a0)
	fsd ft0, 8(a0)

	# multiply-add
	fmadd.d ft0, ft1, ft2, ft4
	fmsub.d ft1, ft2, ft3, ft5
	fnmadd.d ft0, ft1, ft2, ft4
	fnmsub.d ft1, ft2, ft3, ft5

	# op
	fadd.d ft0, ft1, ft2
	fsub.d ft0, ft1, ft2
	fmul.d ft0, ft1, ft2
	fdiv.d ft0, ft1, ft2

	# sqrt
	fsqrt.d ft0, ft1

	# fsgnj
	fsgnj.d ft0, ft1, ft2
	fsgnjn.d ft0, ft1, ft2
	fsgnjx.d ft0, ft1, ft2

	# fmin/fmax
	fmin.d ft0, ft1, ft2
	fmax.d ft0, ft1, ft2

	fcvt.s.d ft0, ft1
	fcvt.d.s ft2, ft3
	fcvt.s.d fa0, fa1
	fcvt.d.s fa1, fa2

	# fcvt.s
	fcvt.w.d a0, ft0
	fcvt.wu.d a0, ft0

	# feq/flt/fle
	feq.d a0, ft0, ft1
	flt.d a0, ft0, ft1
	fle.d a0, ft0, ft1

	# fclass
	fclass.d a0, ft0

	# fcvt
	fcvt.d.w ft0, a0
	fcvt.d.wu ft0, a0
