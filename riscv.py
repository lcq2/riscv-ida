from idaapi import *

# keeping __EA64__ name for historical reasons
__EA64__ = BADADDR == 0xFFFFFFFFFFFFFFFF


def fix_sign_32(l):
    l &= 0xFFFFFFFF
    if l & 0x80000000:
        l -= 0x100000000
    return l


def BITS(val, low, high):
    return (val >> low) & ((1 << (high - low + 1)) - 1)


def BIT(val, bit):
    return (val >> bit) & 1


def SIGNEXT(x, b):
    m = 1 << (b - 1)
    x = x & ((1 << b) - 1)
    return (x ^ m) - m


def is_reg(op, regNo):
    return op.reg == regNo


class UnknownInstruction(Exception):
    pass


# RISC-V major opcodes
RV_LUI = 0b0110111
RV_AUIPC = 0b0010111
RV_JAL = 0b1101111
RV_JALR = 0b1100111
RV_BRANCH = 0b1100011
RV_LOAD = 0b0000011
RV_STORE = 0b0100011
RV_IMM = 0b0010011
RV_OP = 0b0110011
RV_MISC_MEM = 0b0001111
RV_SYSTEM = 0b1110011
RV_AMO = 0b0101111
RV_LOAD_FP = 0b0000111
RV_STORE_FP = 0b0100111
RV_FMADD = 0b1000011
RV_FMSUB = 0b1000111
RV_FNMSUB = 0b1001011
RV_FNMADD = 0b1001111
RV_OP_FP = 0b1010011

RV_MAJ_OPCODE_MASK = 0b01111111
RV_C_MASK = 0b11

RV_U_IMM_31_12_MASK = 0b11111111111111111111000000000000
RV_IMM_SIGN_BIT = 0x80000000
RV_C_IMM_SIGN_BIT = 0x1000

RV_OP_FLAG_SIGNED = 1 << 0

RV_AUX_NOPOST = 0  # no postfix, default for most instructions

RV_AUX_RL = 0x1  # .rl for atomic
RV_AUX_AQ = 0x2  # .aq for atomic

RV_AUX_W = 1
RV_AUX_WU = 2
RV_AUX_D = 3
RV_AUX_S = 4
RV_AUX_X = 5
RV_AUX_L = 6
RV_AUX_LU = 7

# csr instruction (some special handling required)
RV_INSN_CSR = 0x1


class riscv_processor_t(processor_t):
    id = 0x8000 + 0x100
    flag = PR_ASSEMBLE | PR_SEGS | PR_DEFSEG32 | PR_USE32 | PRN_HEX | PR_RNAMESOK | PR_NO_SEGMOVE
    cnbits = 8
    dnbits = 8
    psnames = ['riscv']
    plnames = ['RISC-V ISA']
    segreg_size = 0
    tbyte_size = 0
    retcodes = ['\x82\x80']

    instruc = [
        {'name': '', 'feature': 0},  # "not an instruction"

        # RV32I
        {'name': 'lui',     'feature': CF_CHG1 | CF_USE2},
        {'name': 'auipc',   'feature': CF_CHG1 | CF_USE2},
        {'name': 'jal',     'feature': CF_CHG1 | CF_USE1 | CF_USE2 | CF_CALL},
        {'name': 'jalr',    'feature': CF_CHG1 | CF_USE2 | CF_CALL},
        {'name': 'beq',     'feature': CF_USE1 | CF_USE2 | CF_USE3 | CF_JUMP},
        {'name': 'bne',     'feature': CF_USE1 | CF_USE2 | CF_USE3 | CF_JUMP},
        {'name': 'blt',     'feature': CF_USE1 | CF_USE2 | CF_USE3 | CF_JUMP},
        {'name': 'bge',     'feature': CF_USE1 | CF_USE2 | CF_USE3 | CF_JUMP},
        {'name': 'bltu',    'feature': CF_USE1 | CF_USE2 | CF_USE3 | CF_JUMP},
        {'name': 'bgeu',    'feature': CF_USE1 | CF_USE2 | CF_USE3 | CF_JUMP},
        {'name': 'lb',      'feature': CF_CHG1 | CF_USE2},
        {'name': 'lh',      'feature': CF_CHG1 | CF_USE2},
        {'name': 'lw',      'feature': CF_CHG1 | CF_USE2},
        {'name': 'lbu',     'feature': CF_CHG1 | CF_USE2},
        {'name': 'lhu',     'feature': CF_CHG1 | CF_USE2},
        {'name': 'sb',      'feature': CF_USE1 | CF_CHG2},
        {'name': 'sh',      'feature': CF_USE1 | CF_CHG2},
        {'name': 'sw',      'feature': CF_USE1 | CF_CHG2},
        {'name': 'addi',    'feature': CF_CHG1 | CF_USE2 | CF_USE3},
        {'name': 'slti',    'feature': CF_CHG1 | CF_USE2 | CF_USE3},
        {'name': 'sltiu',   'feature': CF_CHG1 | CF_USE2 | CF_USE3},
        {'name': 'xori',    'feature': CF_CHG1 | CF_USE2 | CF_USE3},
        {'name': 'ori',     'feature': CF_CHG1 | CF_USE2 | CF_USE3},
        {'name': 'andi',    'feature': CF_CHG1 | CF_USE2 | CF_USE3},
        {'name': 'slli',    'feature': CF_CHG1 | CF_USE2 | CF_USE3},
        {'name': 'srli',    'feature': CF_CHG1 | CF_USE2 | CF_USE3},
        {'name': 'srai',    'feature': CF_CHG1 | CF_USE2 | CF_USE3},
        {'name': 'add',     'feature': CF_CHG1 | CF_USE2 | CF_USE3},
        {'name': 'sub',     'feature': CF_CHG1 | CF_USE2 | CF_USE3},
        {'name': 'sll',     'feature': CF_CHG1 | CF_USE2 | CF_USE3},
        {'name': 'slt',     'feature': CF_CHG1 | CF_USE2 | CF_USE3},
        {'name': 'sltu',    'feature': CF_CHG1 | CF_USE2 | CF_USE3},
        {'name': 'xor',     'feature': CF_CHG1 | CF_USE2 | CF_USE3},
        {'name': 'slr',     'feature': CF_CHG1 | CF_USE2 | CF_USE3},
        {'name': 'sra',     'feature': CF_CHG1 | CF_USE2 | CF_USE3},
        {'name': 'or',      'feature': CF_CHG1 | CF_USE2 | CF_USE3},
        {'name': 'and',     'feature': CF_CHG1 | CF_USE2 | CF_USE3},
        {'name': 'fence',   'feature': CF_USE1},
        {'name': 'fence.i',  'feature': 0},
        {'name': 'ecall',   'feature': CF_CALL},
        {'name': 'ebreak',  'feature': 0},
        {'name': 'csrrw',   'feature': CF_USE1 | CF_USE2 | CF_USE3},
        {'name': 'csrrs',   'feature': CF_USE1 | CF_USE2 | CF_USE3},
        {'name': 'csrrc',   'feature': CF_USE1 | CF_USE2 | CF_USE3},
        {'name': 'csrrwi',  'feature': CF_USE1 | CF_USE2 | CF_USE3},
        {'name': 'csrrsi',  'feature': CF_USE1 | CF_USE2 | CF_USE3},
        {'name': 'csrrci',  'feature': CF_USE1 | CF_USE2 | CF_USE3},

        # RV64I
        {'name': 'lwu',     'feature': CF_CHG1 | CF_USE2},
        {'name': 'ld',      'feature': CF_CHG1 | CF_USE2},
        {'name': 'sd',      'feature': CF_USE1 | CF_CHG2},
        {'name': 'addiw',   'feature': CF_CHG1 | CF_USE2 | CF_USE3},
        {'name': 'slliw',   'feature': CF_CHG1 | CF_USE2 | CF_USE3},
        {'name': 'srliw',   'feature': CF_CHG1 | CF_USE2 | CF_USE3},
        {'name': 'sraiw',   'feature': CF_CHG1 | CF_USE2 | CF_USE3},
        {'name': 'addw',    'feature': CF_CHG1 | CF_USE2 | CF_USE3},
        {'name': 'subw',    'feature': CF_CHG1 | CF_USE2 | CF_USE3},
        {'name': 'sllw',    'feature': CF_CHG1 | CF_USE2 | CF_USE3},
        {'name': 'srlw',    'feature': CF_CHG1 | CF_USE2 | CF_USE3},
        {'name': 'sraw',    'feature': CF_CHG1 | CF_USE2 | CF_USE3},

        # RV32M
        {'name': 'mul',     'feature': CF_CHG1 | CF_USE2 | CF_USE3},
        {'name': 'mulh',    'feature': CF_CHG1 | CF_USE2 | CF_USE3},
        {'name': 'mulhsu',  'feature': CF_CHG1 | CF_USE2 | CF_USE3},
        {'name': 'mulhu',   'feature': CF_CHG1 | CF_USE2 | CF_USE3},
        {'name': 'div',     'feature': CF_CHG1 | CF_USE2 | CF_USE3},
        {'name': 'divu',    'feature': CF_CHG1 | CF_USE2 | CF_USE3},
        {'name': 'rem',     'feature': CF_CHG1 | CF_USE2 | CF_USE3},
        {'name': 'remu',    'feature': CF_CHG1 | CF_USE2 | CF_USE3},

        # RV32A / RV64A
        {'name': 'lr',        'feature': CF_CHG1 | CF_USE2},
        {'name': 'sc',        'feature': CF_CHG1 | CF_USE2},
        {'name': 'amoswap',   'feature': CF_CHG1 | CF_USE1 | CF_USE2},
        {'name': 'amoadd',    'feature': CF_CHG1 | CF_USE1 | CF_USE2},
        {'name': 'amoxor',    'feature': CF_CHG1 | CF_USE1 | CF_USE2},
        {'name': 'amoand',    'feature': CF_CHG1 | CF_USE1 | CF_USE2},
        {'name': 'amoor',     'feature': CF_CHG1 | CF_USE1 | CF_USE2},
        {'name': 'amomin',    'feature': CF_CHG1 | CF_USE1 | CF_USE2},
        {'name': 'amomax',    'feature': CF_CHG1 | CF_USE1 | CF_USE2},
        {'name': 'amominu',   'feature': CF_CHG1 | CF_USE1 | CF_USE2},
        {'name': 'amomaxu',   'feature': CF_CHG1 | CF_USE1 | CF_USE2},

        # RV32F/RV64F/FV32D/RV64D
        {'name': 'flw',     'feature': CF_CHG1 | CF_USE2},
        {'name': 'fld',     'feature': CF_CHG1 | CF_USE2},
        {'name': 'fsw',     'feature': CF_USE1 | CF_CHG2},
        {'name': 'fsd',     'feature': CF_USE1 | CF_CHG2},
        {'name': 'fmadd',   'feature': CF_CHG1 | CF_USE2 | CF_USE3 | CF_USE4},
        {'name': 'fmsub',   'feature': CF_CHG1 | CF_USE2 | CF_USE3 | CF_USE4},
        {'name': 'fnmsub',  'feature': CF_CHG1 | CF_USE2 | CF_USE3 | CF_USE4},
        {'name': 'fnmadd',  'feature': CF_CHG1 | CF_USE2 | CF_USE3 | CF_USE4},
        {'name': 'fadd',    'feature': CF_CHG1 | CF_USE2 | CF_USE3},
        {'name': 'fsub',    'feature': CF_CHG1 | CF_USE2 | CF_USE3},
        {'name': 'fmul',    'feature': CF_CHG1 | CF_USE2 | CF_USE3},
        {'name': 'fdiv',    'feature': CF_CHG1 | CF_USE2 | CF_USE3},
        {'name': 'fsqrt',   'feature': CF_CHG1 | CF_USE2},
        {'name': 'fsgnj',   'feature': CF_CHG1 | CF_USE2 | CF_USE3},
        {'name': 'fsgnjn',  'feature': CF_CHG1 | CF_USE2 | CF_USE3},
        {'name': 'fsgnjx',  'feature': CF_CHG1 | CF_USE2 | CF_USE3},
        {'name': 'fmin',    'feature': CF_CHG1 | CF_USE2 | CF_USE3},
        {'name': 'fmax',    'feature': CF_CHG1 | CF_USE2 | CF_USE3},
        {'name': 'fcvt',    'feature': CF_CHG1 | CF_USE2},
        {'name': 'fmv',     'feature': CF_CHG1 | CF_USE2},
        {'name': 'feq',     'feature': CF_CHG1 | CF_USE2 | CF_USE3},
        {'name': 'flt',     'feature': CF_CHG1 | CF_USE2 | CF_USE3},
        {'name': 'fle',     'feature': CF_CHG1 | CF_USE2 | CF_USE3},
        {'name': 'fclass',  'feature': CF_CHG1 | CF_USE2},

        # pseudo-instructions
        {'name': 'nop',  'feature': 0},
        {'name': 'li',   'feature': CF_CHG1 | CF_USE2},
        {'name': 'mv',   'feature': CF_CHG1 | CF_USE2},
        {'name': 'not',  'feature': CF_CHG1 | CF_USE2},
        {'name': 'neg',  'feature': CF_CHG1 | CF_USE2},
        {'name': 'negw', 'feature': CF_CHG1 | CF_USE2},
        {'name': 'sext.w',  'feature': CF_CHG1 | CF_USE2},
        {'name': 'seqz',    'feature': CF_CHG1 | CF_USE2},
        {'name': 'snez',    'feature': CF_CHG1 | CF_USE2},
        {'name': 'sltz',    'feature': CF_CHG1 | CF_USE2},
        {'name': 'sgtz',    'feature': CF_CHG1 | CF_USE2},

        # branch pseudo-instructions
        {'name': 'beqz',    'feature': CF_USE1 | CF_USE2 | CF_JUMP},
        {'name': 'bnez',    'feature': CF_USE1 | CF_USE2 | CF_JUMP},
        {'name': 'blez',    'feature': CF_USE1 | CF_USE2 | CF_JUMP},
        {'name': 'bgez',    'feature': CF_USE1 | CF_USE2 | CF_JUMP},
        {'name': 'bltz',    'feature': CF_USE1 | CF_USE2 | CF_JUMP},
        {'name': 'bgtz',    'feature': CF_USE1 | CF_USE2 | CF_JUMP},

        # jump/call pseudo-instructions
        {'name': 'j',       'feature': CF_USE1 | CF_JUMP},
        {'name': 'jr',      'feature': CF_USE1 | CF_JUMP},
        {'name': 'ret',     'feature': CF_STOP},
        {'name': 'call',    'feature': CF_USE1 | CF_CALL},
        {'name': 'tail',    'feature': CF_USE1 | CF_CALL},

        # csr pseudo-instructions
        {'name': 'rdinstret',   'feature': CF_CHG1},
        {'name': 'rdinstreth',  'feature': CF_CHG1},
        {'name': 'rdcycle',     'feature': CF_CHG1},
        {'name': 'rdcycleh',    'feature': CF_CHG1},
        {'name': 'rdtime',      'feature': CF_CHG1},
        {'name': 'rdtimeh',     'feature': CF_CHG1},
        {'name': 'csrr',        'feature': CF_CHG1 | CF_USE2},
        {'name': 'csrw',        'feature': CF_CHG1 | CF_USE2},
        {'name': 'csrs',        'feature': CF_CHG1 | CF_USE2},
        {'name': 'csrc',        'feature': CF_CHG1 | CF_USE2},
        {'name': 'csrwi',       'feature': CF_CHG1 | CF_USE2},
        {'name': 'csrsi',       'feature': CF_CHG1 | CF_USE2},
        {'name': 'csrci',       'feature': CF_CHG1 | CF_USE2}
    ]
    instruc_start = 0
    instruc_end = len(instruc) - 1

    real_width = (0, 0, 0, 0)

    assembler = {
        'flag': ASH_HEXF0 | ASD_DECF0 | ASO_OCTF5 | ASB_BINF0 | AS_N2CHR,
        'uflag': 0,
        'name': "RISC-V assembler",
        'header': ['.riscv'],
        'origin': '.org',
        'end': '.end',
        'cmnt': ';',
        'ascsep': '"',
        'accsep': "'",
        'esccodes': "\"'",
        'a_ascii': '.char',
        'a_byte': '.byte',
        'a_word': '.short',
        'a_dword': '.long',
        'a_bss': '.space %s',
        'a_equ': '.equ',
        'a_seg': 'seg',
        'a_curip': '$',
        'a_public': '.def',
        'a_weak': '',
        'a_extrn': '.ref',
        'a_comdef': '',
        'a_align': '.align',
        'lbrace': '(',
        'rbrace': ')',
        'a_mod': '%',
        'a_band': '&',
        'a_bor': '|',
        'a_xor': '^',
        'a_bnot': '~',
        'a_shl': '<<',
        'a_shr': '>>',
        'a_sizeof_fmt': 'size %s',
        'flag2': 0,
        'a_include_fmt': '.include "%s"'
    }

    def __init__(self):
        processor_t.__init__(self)
        self.PTRSZ = 4
        self.init_instructions()
        self.init_registers()
        self.init_tables()
        if __EA64__:
            print "64bit\n"
        else:
            print "32bit"

        # available postfixes
        self.postfixs = ['.w', '.wu', '.d', '.s', '.x', '.l', '.lu']

        # CSRs number:name dict, some entries will be added during initialization
        # to avoid endless repetition
        self.csr_names = {
            # User Trap Setup
            0x000: 'ustatus',
            0x004: 'uie',
            0x005: 'utvec',

            # User Trap Handling
            0x040: 'uscratch',
            0x041: 'uepc',
            0x042: 'ucause',
            0x043: 'utval',
            0x044: 'uip',

            # User Floating-Point CSRs
            0x001: 'fflags',
            0x002: 'frm',
            0x003: 'fcsr',

            # User Counter/Timers
            0xC00: 'cycle',
            0xC01: 'time',
            0xC02: 'instret',

            # 0xC03-0xC1F: Performance-monitoring counters (see init_csrs)
            0xC80: 'cycleh',
            0xC81: 'timeh',
            0xC82: 'instreth',

            # 0xC83-0xC9F: Upper 32 bits of hpmcounter[xx], RV32I only

            # Machine Trap Setup
            0x300: 'mstatus',
            0x301: 'misa',
            0x302: 'medeleg',
            0x303: 'mideleg',
            0x304: 'mie',
            0x305: 'mtvec',
            0x306: 'mcounteren',

            # Machine Trap Handling
            0x340: 'mscratch',
            0x341: 'mepc',
            0x342: 'mcause',
            0x343: 'mtval',
            0x344: 'mip',

            # Machine Counters / Timers
            0xB00: 'mcycle',
            0xB02: 'minstret',

            # Machine Information Registers
            0xF11: 'mvendorid',
            0xF12: 'marchid',
            0xF13: 'mimpid',
            0xF14: 'mhartid',

        }
        self.init_csrs()

    def imm_sign_extend(self, opcode, imm, bits):
        if opcode & RV_IMM_SIGN_BIT == RV_IMM_SIGN_BIT:
            return SIGNEXT(imm, bits)
        return imm

    def decode_u_imm(self, opcode):
        return opcode & RV_U_IMM_31_12_MASK

    def decode_j_imm(self, opcode):
        imm = (BITS(opcode, 21, 30) << 1) | \
              (BIT(opcode, 20) << 11) | \
              (BITS(opcode, 12, 19) << 12) | \
              (BIT(opcode, 31) << 20)
        return self.imm_sign_extend(opcode, imm, 20)

    def decode_i_imm(self, opcode, sign_extend=True):
        imm = BITS(opcode, 20, 31)
        if opcode & 0x80000000 == 0x80000000 and sign_extend:
            return SIGNEXT(imm, 12)
        return imm

    def decode_b_imm(self, opcode):
        imm = (BITS(opcode, 8, 11) << 1) | \
              (BITS(opcode, 25, 30) << 5) | \
              (BIT(opcode, 7) << 11) | \
              (BIT(opcode, 31) << 12)
        return self.imm_sign_extend(opcode, imm, 12)

    def decode_s_imm(self, opcode):
        imm = (BITS(opcode, 7, 11)) | \
              (BITS(opcode, 25, 27) << 5)
        return self.imm_sign_extend(opcode, imm, 12)

    def decode_rd(self, opcode):
        regNo = BITS(opcode, 7, 11)
        return regNo

    def decode_rs1(self, opcode):
        regNo = BITS(opcode, 15, 19)
        return regNo

    def decode_rs2(self, opcode):
        regNo = BITS(opcode, 20, 24)
        return regNo

    def decode_funct3(self, opcode):
        funct3 = BITS(opcode, 12, 14)
        return funct3

    def decode_funct7(self, opcode):
        funct7 = BITS(opcode, 25, 31)
        return funct7

    def op_reg(self, op, regNo, dtype=dt_dword):
        op.type = o_reg
        op.reg = regNo
        op.dtype = dtype

    def op_imm(self, op, imm, signed=True):
        op.type = o_imm
        op.value = imm
        op.dtype = dt_dword
        op.specflag1 = 0
        if signed:
            op.specflag1 |= RV_OP_FLAG_SIGNED

    def op_addr(self, op, addr):
        op.type = o_near
        op.addr = addr
        op.dtype = dt_code

    def op_displ(self, op, base, displ, dtype=dt_dword):
        op.type = o_displ
        op.reg = base
        op.value = displ
        op.dtype = dtype

    def set_postfix1(self, insn, value):
        insn.auxpref |= (value << 2)

    def set_postfix2(self, insn, value):
        insn.auxpref |= (value << 6)

    def decode_LUI(self, insn, opcode):
        self.op_reg(insn.Op1, self.decode_rd(opcode))
        self.op_imm(insn.Op2, self.decode_u_imm(opcode), signed=False)
        insn.itype = self.itype_lui

    def decode_AUIPC(self, insn, opcode):
        self.op_reg(insn.Op1, self.decode_rd(opcode))
        self.op_imm(insn.Op2, insn.ip + self.decode_u_imm(opcode), signed=False)
        insn.itype = self.itype_auipc

    def decode_JAL(self, insn, opcode):
        self.op_reg(insn.Op1, self.decode_rd(opcode))
        jimm = self.decode_j_imm(opcode)
        self.op_addr(insn.Op2, insn.ip + jimm)
        insn.itype = self.itype_jal

    def decode_JALR(self, insn, opcode):
        self.op_reg(insn.Op1, self.decode_rd(opcode))
        self.op_displ(insn.Op2, self.decode_rs1(opcode), self.decode_i_imm(opcode))
        insn.itype = self.itype_jalr

    def decode_BRANCH(self, insn, opcode):
        self.op_reg(insn.Op1, self.decode_rs1(opcode))
        self.op_reg(insn.Op2, self.decode_rs2(opcode))
        self.op_addr(insn.Op3, insn.ip + self.decode_b_imm(opcode))
        insn.itype = [
            self.itype_beq, self.itype_bne,
            0, 0,
            self.itype_blt, self.itype_bge,
            self.itype_bltu, self.itype_bgeu
        ][self.decode_funct3(opcode)]


    def decode_LOAD(self, insn, opcode):
        funct3 = self.decode_funct3(opcode)
        optbl = [
            [self.itype_lb, dt_byte], [self.itype_lh, dt_word],
            [self.itype_lw, dt_dword], [self.itype_ld, dt_qword],
            [self.itype_lbu, dt_byte], [self.itype_lhu, dt_word], [self.itype_lwu, dt_dword]
        ]
        insn.itype = optbl[funct3][0]
        self.op_reg(insn.Op1, self.decode_rd(opcode))
        self.op_displ(insn.Op2, self.decode_rs1(opcode), self.decode_i_imm(opcode), optbl[funct3][1])

    def decode_STORE(self, insn, opcode):
        funct3 = self.decode_funct3(opcode)
        optbl = [
            [self.itype_sb, dt_byte], [self.itype_sh, dt_word], [self.itype_sw, dt_dword],
            [self.itype_sd, dt_qword]
        ]
        self.op_reg(insn.Op1, self.decode_rs2(opcode))
        self.op_displ(insn.Op2, self.decode_rs1(opcode), self.decode_s_imm(opcode), optbl[funct3][1])
        insn.itype = optbl[funct3][0]

    def decode_IMM(self, insn, opcode):
        self.op_reg(insn.Op1, self.decode_rd(opcode))
        self.op_reg(insn.Op2, self.decode_rs1(opcode))
        funct3 = self.decode_funct3(opcode)
        imm = self.decode_i_imm(opcode)
        if funct3 == 0b001:
            self.op_imm(insn.Op3, imm & 0b11111)
            insn.itype = self.itype_slli
        elif funct3 == 0b101:
            self.op_imm(insn.Op3, imm & 0b11111)
            insn.itype = self.itype_srai if imm & 0x400 == 0x400 else self.itype_srli
        else:
            self.op_imm(insn.Op3, imm)
            insn.itype = [
                self.itype_addi, 0, self.itype_slti,
                self.itype_sltiu, self.itype_xori, 0,
                self.itype_ori, self.itype_andi
            ][funct3]

    def decode_OP(self, insn, opcode):
        self.op_reg(insn.Op1, self.decode_rd(opcode))
        self.op_reg(insn.Op2, self.decode_rs1(opcode))
        self.op_reg(insn.Op3, self.decode_rs2(opcode))
        funct7 = self.decode_funct7(opcode)
        insn.itype = [
            [
                self.itype_add, self.itype_sll, self.itype_slt, self.itype_sltu,
                self.itype_xor, self.itype_slr, self.itype_or, self.itype_and
            ],
            [
                self.itype_mul, self.itype_mulh, self.itype_mulhsu, self.itype_mulhu,
                self.itype_div, self.itype_divu, self.itype_rem, self.itype_remu
            ]
        ][funct7 & 0b1][self.decode_funct3(opcode)]
        if funct7 & 0b0100001 == 0b0100000:
            if insn.itype == self.itype_add:
                insn.itype = self.itype_sub
            elif insn.itype == self.itype_slr:
                insn.itype = self.itype_sra

    def decode_MISC_MEM(self, insn, opcode):
        funct3 = self.decode_funct3(opcode)
        if funct3 == 0:
            self.op_imm(insn.Op1, self.decode_i_imm(opcode, False))
            insn.itype = self.itype_fence
        else:
            insn.itype = self.itype_fencei

    def decode_SYSTEM(self, insn, opcode):
        rd = self.decode_rd(opcode)
        imm = self.decode_i_imm(opcode, sign_extend=False)
        rs1_zimm = self.decode_rs1(opcode)

        funct3 = self.decode_funct3(opcode)
        if funct3 == 0:
            if imm & 0b1 == 0b1:
                insn.itype = self.itype_ebreak
            else:
                insn.itype = self.itype_ecall
        else:
            insn.itype = [
                self.itype_csrrw, self.itype_csrrs, self.itype_csrrc,
                self.itype_csrrwi, self.itype_csrrsi, self.itype_csrrci
            ][funct3-1]
            i = ord(insn.insnpref) | RV_INSN_CSR
            insn.insnpref = chr(i)
            self.op_reg(insn.Op1, self.decode_rd(opcode))
            if funct3 < 3:
                self.op_reg(insn.Op3, rs1_zimm)
            else:
                self.op_imm(insn.Op3, rs1_zimm, signed=False)
            self.op_imm(insn.Op2, imm, signed=False)


    def decode_AMO(self, insn, opcode):
        rd = self.decode_rd(opcode)
        rs1 = self.decode_rs1(opcode)
        rs2 = self.decode_rs2(opcode)
        funct3 = self.decode_funct3(opcode)
        funct7 = self.decode_funct7(opcode)

        # funct3 = 0b010 for RV32A
        # funct3 = 0b011 for RV64A
        # else invalid? not specified in the ISA, assume invalid...
        if funct3 not in [0b010, 0b011]:
            return

        # propagate aq/rl suffix to auxpref
        insn.auxpref |= (funct7 & 0b11)

        # set 32/64 flag
        self.set_postfix1(insn, RV_AUX_W if funct3 & 1 == 0 else RV_AUX_D)

        # extract AMO opcode
        a_opcode = BITS(funct7, 2, 7)
        insn.itype = {
            0b00010: self.itype_lr,
            0b00011: self.itype_sc,
            0b00001: self.itype_amoswap,
            0b00000: self.itype_amoadd,
            0b00100: self.itype_amoxor,
            0b01100: self.itype_amoand,
            0b01000: self.itype_amoor,
            0b10000: self.itype_amomin,
            0b10100: self.itype_amomax,
            0b11000: self.itype_amominu,
            0b11100: self.itype_amomaxu
        }[a_opcode]
        self.op_reg(insn.Op1, rd)
        if insn.itype == self.itype_lr:
            self.op_displ(insn.Op2, rs1, 0)
        else:
            self.op_reg(insn.Op2, rs2)
            self.op_displ(insn.Op3, rs1, 0)

    def decode_LOAD_FP(self, insn, opcode):
        rd = self.decode_rd(opcode)
        rs1 = self.decode_rs1(opcode)
        imm = self.decode_i_imm(opcode)
        funct3 = self.decode_funct3(opcode)

        # fp-regs start at +32 into reg_names array
        self.op_reg(insn.Op1, rd+32)
        self.op_displ(insn.Op2, rs1, imm)
        insn.itype = self.itype_flw if funct3 & 0b1 == 0 else self.itype_fld

    def decode_STORE_FP(self, insn, opcode):
        rs1 = self.decode_rs1(opcode)
        rs2 = self.decode_rs2(opcode)
        imm = self.decode_s_imm(opcode)
        funct3 = self.decode_funct3(opcode)
        isfloat = (funct3 & 0b1) == 0
        dtype = dt_float if isfloat else dt_double

        self.op_reg(insn.Op1, rs2+32, dtype)
        self.op_displ(insn.Op2, rs1, imm, dtype)
        insn.itype = self.itype_fsw if isfloat else self.itype_fsd

    def decode_fmadd(self, insn, opcode):
        rd = self.decode_rd(opcode)
        rs1 = self.decode_rs1(opcode)
        rs2 = self.decode_rs2(opcode)
        rm = self.decode_funct3(opcode)  # rounding mode
        rs3 = BITS(opcode, 27, 31)
        funct2 = BITS(opcode, 25, 26)

        insn.itype = [
            self.itype_fmadd, self.itype_fmsub, \
            self.itype_fnmsub, self.itype_fnmadd
        ][BITS(opcode, 2, 3)]
        self.set_postfix1(insn, RV_AUX_S if funct2 == 0 else RV_AUX_D)

        self.op_reg(insn.Op1, rd+32)
        self.op_reg(insn.Op2, rs1+32)
        self.op_reg(insn.Op3, rs2+32)
        self.op_reg(insn.Op4, rs3+32)

    def decode_OP_FP(self, insn, opcode):
        rd = self.decode_rd(opcode)
        rs1 = self.decode_rs1(opcode)
        rs2 = self.decode_rs2(opcode)
        funct3 = self.decode_funct3(opcode)
        funct7 = self.decode_funct7(opcode)
        isfloat = (funct7 & 0b11) == 0
        dtype = dt_float if isfloat else dt_double

        sz_postfix = RV_AUX_S if isfloat else RV_AUX_D

        sel = funct7 >> 2
        postfix1 = sz_postfix
        postfix2 = 0

        if sel < 4:
            # fadd, fsub, fmul, fdiv
            insn.itype = [self.itype_fadd, self.itype_fsub, self.itype_fmul, self.itype_fdiv][sel]
            self.op_reg(insn.Op1, rd + 32, dtype)
            self.op_reg(insn.Op2, rs1 + 32, dtype)
            self.op_reg(insn.Op3, rs2 + 32, dtype)
        elif sel == 0b01011:
            # fsqrt
            insn.itype = self.itype_fsqrt
            self.op_reg(insn.Op1, rd + 32, dtype)
            self.op_reg(insn.Op2, rs1 + 32, dtype)
        elif sel == 0b00100:
            # fsgnj, fsgnjn, fsgnjx
            insn.itype = [self.itype_fsgnj, self.itype_fsgnjn, self.itype_fsgnjx][funct3]
            self.op_reg(insn.Op1, rd + 32, dtype)
            self.op_reg(insn.Op2, rs1 + 32, dtype)
            self.op_reg(insn.Op3, rs2 + 32, dtype)
        elif sel == 0b10100:
            # feq, flt, fle
            insn.itype = [self.itype_fle, self.itype_flt, self.itype_feq][funct3]
            self.op_reg(insn.Op1, rd, dt_qword if __EA64__ else dt_dword)
            self.op_reg(insn.Op2, rs1 + 32, dtype)
            self.op_reg(insn.Op3, rs2 + 32, dtype)
        elif sel == 0b01000:
            # fcvt[.s|.d][.d|.s]
            if rs2 == 0 or rs2 == 1:
                optbl = [[RV_AUX_S, dt_float], [RV_AUX_D, dt_double]]
                insn.itype = self.itype_fcvt
                postfix2 = optbl[rs2][0]
                self.op_reg(insn.Op1, rd + 32, dtype)
                self.op_reg(insn.Op2, rs1 + 32, optbl[rs2][1])
        elif sel == 0b00101:
            # fmin, fmax
            insn.itype = [self.itype_fmin, self.itype_fmax][funct3]
            self.op_reg(insn.Op1, rd + 32, dtype)
            self.op_reg(insn.Op2, rs1 + 32, dtype)
            self.op_reg(insn.Op3, rs2 + 32, dtype)
        elif sel == 0b11010 or sel == 0b11000:
            cvtsel = BIT(sel, 1)
            # fcvt[.w|.wu|.l|.lu][.s] or fcvt[.s][.w|.wu|.l|.lu]
            optbl = [[RV_AUX_W, dt_dword], [RV_AUX_WU, dt_dword], [RV_AUX_L, dt_qword], [RV_AUX_LU, dt_qword]]
            cvttbl = [
                [rd, rs1+32, optbl[rs2][1], dtype, optbl[rs2][0], sz_postfix],
                [rd+32, rs1, dtype, optbl[rs2][1], sz_postfix, optbl[rs2][0]]
            ]
            insn.itype = self.itype_fcvt
            self.op_reg(insn.Op1, cvttbl[cvtsel][0], cvttbl[cvtsel][2])
            self.op_reg(insn.Op2, cvttbl[cvtsel][1], cvttbl[cvtsel][3])
            postfix1 = cvttbl[cvtsel][4]
            postfix2 = cvttbl[cvtsel][5]
        elif sel == 0b11110 or sel == 0b11100:
            cvtsel = BIT(sel, 1)
            if funct3 == 1:
                if cvtsel == 0:
                    # fclass
                    insn.itype = self.itype_fclass
                    self.op_reg(insn.Op1, rd, dt_qword if __EA64__ else dt_dword)
                    self.op_reg(insn.Op2, rs1 + 32, dtype)
            else:
                # fmv[.w|.d][.x] or fmv[.x][.w|.d]
                insn.itype = self.itype_fmv
                if cvtsel == 0:
                    self.op_reg(insn.Op1, rd, dt_qword if __EA64__ else dt_dword)
                    self.op_reg(insn.Op2, rs1+32, dtype)
                    postfix1 = RV_AUX_X
                    postfix2 = RV_AUX_W if dtype == dt_float else RV_AUX_D
                else:
                    self.op_reg(insn.Op1, rd+32, dtype)
                    self.op_reg(insn.Op2, rs1, dt_qword if __EA64__ else dt_dword)
                    postfix1 = RV_AUX_W if dtype == dt_float else RV_AUX_D
                    postfix2 = RV_AUX_X

        self.set_postfix1(insn, postfix1)
        self.set_postfix2(insn, postfix2)

    def decode_compressed(self, insn):
        opcode = insn.get_next_word()
        # some quick exists
        if opcode == 0:
            # invalid instruction
            insn.itype = self.itype_null
            return insn.size
        if opcode == 1:
            # nop
            insn.itype = self.itype_addi
            self.op_reg(insn.Op1, self.ireg_zero)
            self.op_reg(insn.Op2, self.ireg_zero)
            self.op_imm(insn.Op3, 0)
            return insn.size

        # default to invalid instruction
        insn.itype = self.itype_null

        copcode = BITS(opcode, 13, 15)

        q = opcode & 0b11
        is_signed = (opcode & RV_C_IMM_SIGN_BIT) == RV_C_IMM_SIGN_BIT
        # quadrant 0
        if q == 0:
            rs1 = BITS(opcode, 7, 9)
            rd_rs2 = BITS(opcode, 2, 4)
            if copcode != 0:
                # a lookup table is used for compressed load/store
                # they make up most of compressed instructions in an average executable
                decoder = self.c_q0[copcode-1]
                if decoder[0] != self.itype_null:
                    insn.itype = decoder[0]
                    self.op_reg(insn.Op1, decoder[2][rd_rs2])
                    self.op_displ(insn.Op2, self.ciregs[rs1], decoder[1](opcode))
            else:
                insn.itype = self.itype_addi
                imm = (BIT(opcode, 5) << 3) | (BIT(opcode, 6) << 2) | \
                      (BITS(opcode, 7, 10) << 6) | (BITS(opcode, 11, 12) << 4)
                self.op_reg(insn.Op1, self.ciregs[rd_rs2])
                self.op_reg(insn.Op2, self.ireg_sp)
                self.op_imm(insn.Op3, imm)
        elif q == 1:
            rs1_rd = BITS(opcode, 7, 9)
            rs2 = BITS(opcode, 2, 4)
            if copcode == 0:
                imm = (BITS(opcode, 2, 6)) | (BIT(opcode, 12) << 5)
                if is_signed:
                    imm = SIGNEXT(imm, 6)
                rd = BITS(opcode, 7, 11)
                self.op_reg(insn.Op1, rd)
                self.op_reg(insn.Op2, rd)
                self.op_imm(insn.Op3, imm)
                insn.itype = self.itype_addi
            elif copcode == 0b001:
                # RV32 only
                imm = (BIT(opcode, 2) << 5) | (BITS(opcode, 3, 5) << 1) | \
                      (BIT(opcode, 6) << 7) | (BIT(opcode, 7) << 6) | \
                      (BIT(opcode, 8) << 10) | (BITS(opcode, 9, 10) << 8) | \
                      (BIT(opcode, 11) << 4) | (BIT(opcode, 12) << 11)
                if is_signed:
                    imm = SIGNEXT(imm, 12)
                self.op_reg(insn.Op1, self.ireg_ra)
                self.op_addr(insn.Op2, insn.ip + imm)
                insn.itype = self.itype_jal
            elif copcode == 0b010:
                imm = (BITS(opcode, 2, 6)) | (BIT(opcode, 12) << 5)
                if is_signed:
                    imm = SIGNEXT(imm, 6)
                self.op_reg(insn.Op1, BITS(opcode, 7, 11))
                self.op_reg(insn.Op2, self.ireg_zero)
                self.op_imm(insn.Op3, imm)
                insn.itype = self.itype_addi
            elif copcode == 0b011:
                rs1_rd = BITS(opcode, 7, 11)
                # C.ADDI16SP variant
                if rs1_rd == 2:
                    imm = (BIT(opcode, 2) << 5) | (BITS(opcode, 3, 4) << 7) | \
                          (BIT(opcode, 5) << 6) | (BIT(opcode, 6) << 4) | (BIT(opcode, 12) << 9)
                    if is_signed:
                        imm = SIGNEXT(imm, 10)
                    self.op_reg(insn.Op1, self.ireg_sp)
                    self.op_reg(insn.Op2, self.ireg_sp)
                    self.op_imm(insn.Op3, imm)
                    insn.itype = self.itype_addi
                else:
                    imm = (BITS(opcode, 2, 6) << 12) | (BIT(opcode, 12) << 17)
                    if is_signed:
                        imm = SIGNEXT(imm, 18)
                    self.op_reg(insn.Op1, rs1_rd)
                    self.op_imm(insn.Op2, imm)
                    insn.itype = self.itype_lui
            elif copcode == 0b100:
                imm = (BITS(opcode, 2, 6)) | (BIT(opcode, 12) << 5)
                if is_signed:
                    imm = SIGNEXT(imm, 6)
                sel1 = BITS(opcode, 10, 11)
                sel2 = BITS(opcode, 5, 6)
                self.op_reg(insn.Op1, self.ciregs[rs1_rd])
                self.op_reg(insn.Op2, self.ciregs[rs1_rd])
                if sel1 < 3:
                    insn.itype = [self.itype_srli, self.itype_srai, self.itype_andi][sel1]
                    if sel1 < 2:
                        imm = imm & 0b11111 if imm != 0 else 64
                    self.op_imm(insn.Op3, imm)
                elif sel1 == 0b11:
                    insn.itype =[self.itype_sub, self.itype_xor, self.itype_or, self.itype_and][sel2]
                    self.op_reg(insn.Op3, self.ciregs[rs2])
                    if BIT(opcode, 12) == 1:
                        if insn.itype == self.itype_sub:
                            insn.itype = self.itype_subw
                        elif insn.itype == self.itype_xor:
                            insn.itype = self.itype_addw
            elif copcode == 0b101:
                imm = (BIT(opcode, 2) << 5) | (BITS(opcode, 3, 5) << 1) | \
                      (BIT(opcode, 6) << 7) | (BIT(opcode, 7) << 6) | \
                      (BIT(opcode, 8) << 10) | (BITS(opcode, 9, 10) << 8) | \
                      (BIT(opcode, 11) << 4) | (BIT(opcode, 12) << 11)
                if is_signed:
                    imm = SIGNEXT(imm, 12)
                self.op_reg(insn.Op1, self.ireg_zero)
                self.op_addr(insn.Op2, insn.ip + imm)
                insn.itype = self.itype_jal
            elif copcode > 0b101:
                insn.itype = [self.itype_beq, self.itype_bne][copcode - 0b110]
                imm = (BIT(opcode, 2) << 5) | (BITS(opcode, 3,4) << 1) | (BITS(opcode, 5, 6) << 6) | \
                      (BITS(opcode, 10, 11) << 3) | (BIT(opcode, 12) << 8)
                if is_signed:
                    imm = SIGNEXT(imm, 9)
                self.op_reg(insn.Op1, self.ciregs[rs1_rd])
                self.op_reg(insn.Op2, self.ireg_zero)
                self.op_addr(insn.Op3, insn.ip + imm)
        elif q == 2:
            rs1_rd = BITS(opcode, 7, 11)
            rs2 = BITS(opcode, 2, 6)
            if copcode == 0b000:
                imm = (BITS(opcode, 2, 6)) | (BIT(opcode, 12))
                self.op_reg(insn.Op1, rs1_rd)
                self.op_reg(insn.Op2, rs1_rd)
                self.op_imm(insn.Op3, imm if imm != 0 else 64)
                insn.itype = self.itype_slli
            elif copcode == 0b001:
                imm = (BITS(opcode, 2, 4) << 6) | (BITS(opcode, 5, 6) << 3)
                self.op_reg(insn.Op1, rs1_rd+32)
                self.op_displ(insn.Op2, self.ireg_sp, imm)
                insn.itype = self.itype_fld
            elif copcode == 0b010:
                imm = (BITS(opcode, 2, 3) << 6) | (BITS(opcode, 4, 6) << 2) | (BIT(opcode, 12) << 5)
                self.op_reg(insn.Op1, rs1_rd)
                self.op_displ(insn.Op2, self.ireg_sp, imm)
                insn.itype = self.itype_lw
            elif copcode == 0b011:
                imm = (BITS(opcode, 2, 4) << 6) | (BITS(opcode, 3, 4) << 3) | (BIT(opcode, 12) << 5)
                self.op_reg(insn.Op1, rs1_rd+32)
                self.op_displ(insn.Op2, self.ireg_sp, imm)
                insn.itype = self.itype_flw
            elif copcode == 0b100:
                sel1 = BIT(opcode, 12)
                if sel1 == 0:
                    if rs2 == 0:
                        self.op_reg(insn.Op1, self.ireg_zero)
                        self.op_reg(insn.Op2, rs1_rd)
                        self.op_imm(insn.Op3, 0)
                        insn.itype = self.itype_jalr
                    else:
                        self.op_reg(insn.Op1, rs1_rd)
                        self.op_reg(insn.Op2, self.ireg_zero)
                        self.op_reg(insn.Op3, rs2)
                        insn.itype = self.itype_add
                else:
                    if rs2 == 0:
                        if rs1_rd == 0:
                            insn.itype = self.itype_ebreak
                        else:
                            self.op_reg(insn.Op1, self.ireg_ra)
                            self.op_reg(insn.Op2, rs1_rd)
                            self.op_imm(insn.Op3, 0)
                            insn.itype = self.itype_jalr
                    else:
                        self.op_reg(insn.Op1, rs1_rd)
                        self.op_reg(insn.Op2, rs1_rd)
                        self.op_reg(insn.Op3, rs2)
                        insn.itype = self.itype_add
            elif copcode == 0b101:
                imm = (BITS(opcode, 7, 9) << 6) | (BITS(opcode, 10, 12) << 3)
                self.op_reg(insn.Op1, rs2)
                self.op_displ(insn.Op2, self.ireg_sp, imm)
                insn.itype = self.itype_fsd
            elif copcode == 0b110:
                imm = (BITS(opcode, 7, 8) << 6) | (BITS(opcode, 9, 12) << 2)
                self.op_reg(insn.Op1, rs2)
                self.op_displ(insn.Op2, self.ireg_sp, imm)
                insn.itype = self.itype_sw

        if insn.itype != self.itype_null:
            return insn.size
        print "returning unknown for 0x%08x" % (insn.ea)
        return 0

    def decode_normal(self, insn):
        # normal instructions are 32bit aligned
        opcode = insn.get_next_dword()
        maj_opcode = BITS(opcode, 0, 6)
        try:
            self.maj_opcodes[maj_opcode](insn, opcode)
            if insn.size == 0:
                raise UnknownInstruction()
            return insn.size
        except (KeyError, UnknownInstruction) as e:
            print "error: 0x%08x - %s" % (insn.ea, str(e))
            return 0

    # rewrite one instruction into a simpler form
    def simplify(self, insn):
        # addi rd, zero, imm -> [li rd, imm] | [nop]
        # addi rd, rs, 0 -> [mv rd, rs]
        if insn.itype == self.itype_addi:
            if insn.Op2.reg == self.ireg_zero:
                if insn.Op1.reg != self.ireg_zero:
                    insn.itype = self.itype_li
                    insn.Op2.assign(insn.Op3)
                    insn.Op3.type = o_void
                elif insn.Op3.value == 0:
                    insn.itype = self.itype_nop
                    insn.Op1.type = o_void
                    insn.Op2.type = o_void
                    insn.Op3.type = o_void
            elif insn.Op3.value == 0:
                insn.itype = self.itype_mv
                insn.Op3.type = o_void
        elif insn.itype == self.itype_add:
            # add rd, zero, rs2 -> [mv rd, rs2]
            if insn.Op2.reg == self.ireg_zero:
                insn.itype = self.itype_mv
                insn.Op2.assign(insn.Op3)
                insn.Op3.type = o_void
        elif insn.itype == self.itype_xori:
            if fix_sign_32(insn.Op3.value) == -1:
                insn.itype = self.itype_not
                insn.Op3.type = o_void
        elif insn.itype == self.itype_sub:
            if insn.Op2.reg == self.ireg_zero:
                insn.itype = self.itype_neg
                insn.Op2.assign(insn.Op3)
                insn.Op3.type = o_void
        elif insn.itype == self.itype_jal:
            if insn.Op1.reg == self.ireg_zero:
                insn.itype = self.itype_j
                insn.Op1.assign(insn.Op2)
                insn.Op2.type = o_void
            elif insn.Op1.reg == self.ireg_ra:
                insn.Op1.assign(insn.Op2)
                insn.Op2.type = o_void
        elif insn.itype == self.itype_jalr:
            if insn.Op1.reg == self.ireg_zero:
                if insn.Op2.reg == self.ireg_ra:
                    insn.itype = self.itype_ret
                    insn.Op1.type = o_void
                    insn.Op2.type = o_void
                    insn.Op3.type = o_void
                else:
                    insn.itype = self.itype_jr
                    insn.Op1.assign(insn.Op2)
                    insn.Op2.type = o_void
            elif insn.Op1.reg == self.ireg_ra:
                insn.Op1.assign(insn.Op2)
                insn.Op2.type = o_void
        elif insn.itype == self.itype_beq and insn.Op2.reg == self.ireg_zero:
            insn.itype = self.itype_beqz
            insn.Op2.assign(insn.Op3)
            insn.Op3.type = o_void
        elif insn.itype == self.itype_bne and insn.Op2.reg == self.ireg_zero:
            insn.itype = self.itype_bnez
            insn.Op2.assign(insn.Op3)
            insn.Op3.type = o_void
        elif insn.itype == self.itype_bge and insn.Op1.reg == self.ireg_zero:
            insn.itype = self.itype_blez
            insn.Op1.assign(insn.Op2)
            insn.Op2.assign(insn.Op3)
            insn.Op3.type = o_void
        elif insn.itype == self.itype_bge and insn.Op2.reg == self.ireg_zero:
            insn.itype = self.itype_bgez
            insn.Op2.assign(insn.Op3)
            insn.Op3.type = o_void
        elif insn.itype == self.itype_blt and insn.Op2.reg == self.ireg_zero:
            insn.itype = self.itype_bltz
            insn.Op2.assign(insn.Op3)
            insn.Op3.type = o_void
        elif insn.itype == self.itype_blt and insn.Op1.reg == self.ireg_zero:
            insn.itype = self.itype_bgtz
            insn.Op1.assign(insn.Op2)
            insn.Op2.assign(insn.Op3)
            insn.Op3.type = o_void
        elif ord(insn.insnpref) & RV_INSN_CSR == RV_INSN_CSR:
            csr = insn.Op2.value

            # these CSRs produce a pseudo-instruction rdXXX
            if 0xC00 <= csr <= 0xC02 or 0xC80 <= csr <= 0xC82:
                instrs = ['rdinstret', 'rdcycle', 'rdtime']
                iname = "itype_" + instrs[csr & 0x00F]
                if csr & 0x080 == 0x080:
                    iname += 'h'
                insn.itype = getattr(self, iname)
                insn.Op2.type = o_void
                insn.Op3.type = o_void
            else:
                insn.itype = {
                    self.itype_csrrw: self.itype_csrw,
                    self.itype_csrrs: self.itype_csrs,
                    self.itype_csrrc: self.itype_csrc,
                    self.itype_csrrwi: self.itype_csrwi,
                    self.itype_csrrsi: self.itype_csrsi,
                    self.itype_csrrci: self.itype_csrci
                }[insn.itype]

                if insn.Op3.reg == self.ireg_zero:
                    insn.Op3.type = o_void
                elif insn.Op1.reg == self.ireg_zero:
                    insn.Op1.assign(insn.Op2)
                    insn.Op2.assign(insn.Op3)
                    insn.Op3.type = o_void

    def handle_operand(self, insn, op, r):
        flags = get_flags(insn.ea)
        is_offs = is_off(flags, op.n)
        optype = op.type
        feats = insn.get_canon_feature()

        itype = insn.itype
        if optype == o_near:
            if feats & CF_CALL:
                insn.add_cref(op.addr, op.offb, fl_CN)
            elif feats & CF_JUMP:
                insn.add_cref(op.addr, op.offb, fl_JN)

    def init_instructions(self):
        i = 0
        for x in self.instruc:
            if x['name'] != '':
                setattr(self, 'itype_' + x['name'].replace('.', '_'), i)
            else:
                setattr(self, 'itype_null', i)
            i += 1

    def init_registers(self):
        # using ABI names by default
        self.reg_names = [
            # integer registers
            'zero',  # hard-wired zero
            'ra',  # return address
            'sp',  # stack pointer
            'gp',  # global pointer
            'tp',  # thread pointer
            't0',  # temporary/alternate link register
            't1', 't2',  # temporaries
            's0',  # saved register/frame pointer
            's1',  # saved register
            'a0', 'a1',  # function arguments/return values
            'a2', 'a3', 'a4', 'a5', 'a6', 'a7',  # function arguments
            's2', 's3', 's4', 's5', 's6', 's7', 's8', 's9', 's10', 's11',  # saved registers
            't3', 't4', 't5', 't6',  # temporaries

            # floating point registers
            'ft0', 'ft1', 'ft2', 'ft3', 'ft4', 'ft5', 'ft6', 'ft7',
            'fs0', 'fs1',
            'fa0', 'fa1',
            'fa2', 'fa3', 'fa4', 'fa5', 'fa6', 'fa7',
            'fs2', 'fs3', 'fs4', 'fs5', 'fs6', 'fs7', 'fs8', 'fs9', 'fs10', 'fs11',
            'ft8', 'ft9', 'ft10', 'ft11',
            'vCS',  # fake cs
            'vDS'  # fake ds
        ]

        for i in xrange(len(self.reg_names)):
            setattr(self, 'ireg_' + self.reg_names[i], i)

        self.reg_first_sreg = self.ireg_vCS
        self.reg_last_sreg = self.ireg_vDS
        self.reg_code_sreg = self.ireg_vCS
        self.reg_data_sreg = self.ireg_vDS

        # compressed integer registers
        self.ciregs = [
            self.ireg_s0, self.ireg_s1,
            self.ireg_a0, self.ireg_a1,
            self.ireg_a2, self.ireg_a3,
            self.ireg_a4, self.ireg_a5
        ]

        # compressed floating point registers
        self.cfregs = [
            self.ireg_fs0, self.ireg_fs1,
            self.ireg_fa0, self.ireg_fa1,
            self.ireg_fa2, self.ireg_fa3,
            self.ireg_fa4, self.ireg_fa5
        ]

    def init_csrs(self):
        for i in xrange(3, 32):
            self.csr_names[0xC00+i] = "hpmcounter%d" % (i)
            self.csr_names[0xC80+i] = "hpmcounter%dh" % (i)

    # initializes some decoding tables to speedup decoding a bit (only for some frequent instructions)
    def init_tables(self):

        # main decoder, dispatches decoding depending on major opcode
        self.maj_opcodes = {
            RV_LUI: self.decode_LUI,
            RV_AUIPC: self.decode_AUIPC,
            RV_JAL: self.decode_JAL,
            RV_JALR: self.decode_JALR,
            RV_BRANCH: self.decode_BRANCH,
            RV_LOAD: self.decode_LOAD,
            RV_STORE: self.decode_STORE,
            RV_IMM: self.decode_IMM,
            RV_OP: self.decode_OP,
            RV_MISC_MEM: self.decode_MISC_MEM,
            RV_SYSTEM: self.decode_SYSTEM,
            RV_AMO: self.decode_AMO,
            RV_STORE_FP: self.decode_STORE_FP,
            RV_LOAD_FP: self.decode_LOAD_FP,
            RV_FMADD: self.decode_fmadd,
            RV_FMSUB: self.decode_fmadd,
            RV_FNMADD: self.decode_fmadd,
            RV_FNMSUB: self.decode_fmadd,
            RV_OP_FP: self.decode_OP_FP
        }

        # compressed instructions for load and store, quadrant 0
        # format: [itype, decode_immediate(..), reg_list]
        # these are the most common compressed instructions
        self.c_q0 = [
            # 001
            [self.itype_fld, lambda opcode: (BITS(opcode, 10, 12) << 3) | (BITS(opcode, 5, 6) << 6),
                self.cfregs],
            # 010
            [self.itype_lw, lambda opcode: (BIT(opcode, 6) << 2) | (BITS(opcode, 10, 12) << 3) | (BIT(opcode, 5) << 6),
                self.ciregs],
            # 011
            [self.itype_flw, lambda opcode: (BIT(opcode, 6) << 2) | (BITS(opcode, 10, 12) << 3) | (BIT(opcode, 5) << 6),
                self.cfregs],
            # 100
            [self.itype_null, None, None],
            # 101
            [self.itype_fsd, lambda opcode: (BITS(opcode, 10, 12) << 3) | (BITS(opcode, 5, 6) << 6),
                self.cfregs],
            # 110
            [self.itype_sw, lambda opcode: (BIT(opcode, 5) << 6) | (BIT(opcode, 6) << 2) | (BITS(opcode, 10, 12) << 3),
                self.ciregs],
            # 111
            [self.itype_fsw, lambda opcode: (BIT(opcode, 6) << 2) | (BITS(opcode, 10, 12) << 3) | (BIT(opcode, 5) << 6),
                self.cfregs]
        ]

    # TODO: setup loader hooks and inject correct ELF type
    #def notify_init(self, idp_file):

    #def notify_get_frame_retsize(self, func_ea):
    #   return 4

    # auto-comments are disabled
    def notify_get_autocmt(self, insn):
        pass

    # verify if this instruction is acceptable
    def notify_is_sane_insn(self, insn, no_crefs):
        opcode = get_byte(insn.ea) & RV_MAJ_OPCODE_MASK
        if opcode in self.maj_opcodes or (opcode & RV_C_MASK != RV_C_MASK):
            return 1
        return -1

    # emulate one instruction, used mainly to crefs and drefs
    # and to establish general program flow
    # TODO: add stack tracing
    def notify_emu(self, insn):
        feats = insn.get_canon_feature()

        if feats & CF_USE1:
            self.handle_operand(insn, insn.Op1, 1)
        elif feats & CF_CHG1:
            self.handle_operand(insn, insn.Op1, 0)

        if feats & CF_USE2:
            self.handle_operand(insn, insn.Op2, 1)
        elif feats & CF_CHG2:
            self.handle_operand(insn, insn.Op2, 0)

        if feats & CF_USE3:
            self.handle_operand(insn, insn.Op3, 1)

        if feats & CF_JUMP or feats & CF_CALL:
            remember_problem(PR_JUMP, insn.ea)

        # flow, best part in IDAPro :D
        if feats & CF_STOP == 0:
            add_cref(insn.ea, insn.ea + insn.size, fl_F)
        return 1

    def notify_out_operand(self, ctx, op):
        optype = op.type
        if optype == o_reg:
            ctx.out_register(self.reg_names[op.reg])
        elif optype == o_imm:
            if ord(ctx.insn.insnpref) & RV_INSN_CSR == RV_INSN_CSR:
                ctx.out_register(self.csr_names[op.value])
            else:
                opflag = OOFW_IMM | OOFW_32 | OOF_NUMBER
                if op.specflag1 & RV_OP_FLAG_SIGNED == RV_OP_FLAG_SIGNED:
                    opflag |= OOF_SIGNED
                ctx.out_value(op, opflag)
        elif optype == o_near:
            ctx.out_name_expr(op, op.addr, BADADDR)
        elif optype == o_displ:
            if op.value != 0:
                ctx.out_value(op, OOF_OUTER | OOFW_32 | OOF_SIGNED)
            ctx.out_symbol('(')
            ctx.out_register(self.reg_names[op.reg])
            ctx.out_symbol(')')
        else:
            return False
        return True

    def out_mnem(self, ctx):
        auxpref = ctx.insn.auxpref
        postfix = ""

        if auxpref != 0:
            aqrl = BITS(auxpref, 0, 1)  # extract aq/rl pattern (if present)
            postfix1 = BITS(auxpref, 2, 5)  # extract first postfix
            postfix2 = BITS(auxpref, 6, 9)  # extract second postfix
            if postfix1 != 0:
                postfix = self.postfixs[postfix1-1]
            if postfix2 != 0:
                postfix += self.postfixs[postfix2-1]
            if aqrl & 0b10 == 0b10:
                postfix += ".aq"
            if aqrl & 0b01 == 0b01:
                postfix += ".rl"

        ctx.out_mnem(14, postfix)

    def notify_out_insn(self, ctx):
        # nothing special to be done here
        ctx.out_mnemonic()

        # output all operands
        # number are HEX by default, ugly for negative numbers...
        if ctx.insn.Op1.type != o_void:
            ctx.out_one_operand(0)

        for i in xrange(1,4):
            if ctx.insn[i].type == o_void:
                break
            ctx.out_symbol(',')
            ctx.out_char(' ')
            ctx.out_one_operand(i)
        ctx.flush_outbuf()

    def notify_ana(self, insn):
        # instructions must be aligned
        # TODO: check for eventual CPU features in cfg?
        if (insn.ea & 1) != 0:
            return 0

        # some default values
        insn.auxpref = RV_AUX_NOPOST
        insn.insnpref = ''
        insn.itype = self.itype_null

        # determine if this is a compressed instruction
        # TODO: add support for extended format
        b = get_byte(insn.ea)
        if b & RV_C_MASK != RV_C_MASK:
            retval = self.decode_compressed(insn)
        else:
            retval = self.decode_normal(insn)

        # if we got a valid instruction, simplify it
        if insn.itype != self.itype_null:
            self.simplify(insn)

        return retval


def PROCESSOR_ENTRY():
    return riscv_processor_t()