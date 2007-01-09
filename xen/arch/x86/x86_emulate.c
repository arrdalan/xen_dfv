/******************************************************************************
 * x86_emulate.c
 * 
 * Generic x86 (32-bit and 64-bit) instruction decoder and emulator.
 * 
 * Copyright (c) 2005 Keir Fraser
 */

#ifndef __XEN__
#include <stddef.h>
#include <stdint.h>
#include <public/xen.h>
#else
#include <xen/config.h>
#include <xen/types.h>
#include <xen/lib.h>
#include <asm/regs.h>
#undef cmpxchg
#endif
#include <asm-x86/x86_emulate.h>

/* Operand sizes: 8-bit operands or specified/overridden size. */
#define ByteOp      (1<<0) /* 8-bit operands. */
/* Destination operand type. */
#define DstBitBase  (0<<1) /* Memory operand, bit string. */
#define ImplicitOps (1<<1) /* Implicit in opcode. No generic decode. */
#define DstReg      (2<<1) /* Register operand. */
#define DstMem      (3<<1) /* Memory operand. */
#define DstMask     (3<<1)
/* Source operand type. */
#define SrcNone     (0<<3) /* No source operand. */
#define SrcImplicit (0<<3) /* Source operand is implicit in the opcode. */
#define SrcReg      (1<<3) /* Register operand. */
#define SrcMem      (2<<3) /* Memory operand. */
#define SrcMem16    (3<<3) /* Memory operand (16-bit). */
#define SrcMem32    (4<<3) /* Memory operand (32-bit). */
#define SrcImm      (5<<3) /* Immediate operand. */
#define SrcImmByte  (6<<3) /* 8-bit sign-extended immediate operand. */
#define SrcMask     (7<<3)
/* Generic ModRM decode. */
#define ModRM       (1<<6)
/* Destination is only written; never read. */
#define Mov         (1<<7)

static uint8_t opcode_table[256] = {
    /* 0x00 - 0x07 */
    ByteOp|DstMem|SrcReg|ModRM, DstMem|SrcReg|ModRM,
    ByteOp|DstReg|SrcMem|ModRM, DstReg|SrcMem|ModRM,
    ByteOp|DstReg|SrcImm, DstReg|SrcImm, 0, 0,
    /* 0x08 - 0x0F */
    ByteOp|DstMem|SrcReg|ModRM, DstMem|SrcReg|ModRM,
    ByteOp|DstReg|SrcMem|ModRM, DstReg|SrcMem|ModRM,
    ByteOp|DstReg|SrcImm, DstReg|SrcImm, 0, 0,
    /* 0x10 - 0x17 */
    ByteOp|DstMem|SrcReg|ModRM, DstMem|SrcReg|ModRM,
    ByteOp|DstReg|SrcMem|ModRM, DstReg|SrcMem|ModRM,
    ByteOp|DstReg|SrcImm, DstReg|SrcImm, 0, 0,
    /* 0x18 - 0x1F */
    ByteOp|DstMem|SrcReg|ModRM, DstMem|SrcReg|ModRM,
    ByteOp|DstReg|SrcMem|ModRM, DstReg|SrcMem|ModRM,
    ByteOp|DstReg|SrcImm, DstReg|SrcImm, 0, 0,
    /* 0x20 - 0x27 */
    ByteOp|DstMem|SrcReg|ModRM, DstMem|SrcReg|ModRM,
    ByteOp|DstReg|SrcMem|ModRM, DstReg|SrcMem|ModRM,
    ByteOp|DstReg|SrcImm, DstReg|SrcImm, 0, ImplicitOps,
    /* 0x28 - 0x2F */
    ByteOp|DstMem|SrcReg|ModRM, DstMem|SrcReg|ModRM,
    ByteOp|DstReg|SrcMem|ModRM, DstReg|SrcMem|ModRM,
    ByteOp|DstReg|SrcImm, DstReg|SrcImm, 0, ImplicitOps,
    /* 0x30 - 0x37 */
    ByteOp|DstMem|SrcReg|ModRM, DstMem|SrcReg|ModRM,
    ByteOp|DstReg|SrcMem|ModRM, DstReg|SrcMem|ModRM,
    ByteOp|DstReg|SrcImm, DstReg|SrcImm, 0, ImplicitOps,
    /* 0x38 - 0x3F */
    ByteOp|DstMem|SrcReg|ModRM, DstMem|SrcReg|ModRM,
    ByteOp|DstReg|SrcMem|ModRM, DstReg|SrcMem|ModRM,
    ByteOp|DstReg|SrcImm, DstReg|SrcImm, 0, ImplicitOps,
    /* 0x40 - 0x4F */
    ImplicitOps, ImplicitOps, ImplicitOps, ImplicitOps,
    ImplicitOps, ImplicitOps, ImplicitOps, ImplicitOps,
    ImplicitOps, ImplicitOps, ImplicitOps, ImplicitOps,
    ImplicitOps, ImplicitOps, ImplicitOps, ImplicitOps,
    /* 0x50 - 0x5F */
    ImplicitOps|Mov, ImplicitOps|Mov, ImplicitOps|Mov, ImplicitOps|Mov,
    ImplicitOps|Mov, ImplicitOps|Mov, ImplicitOps|Mov, ImplicitOps|Mov,
    ImplicitOps|Mov, ImplicitOps|Mov, ImplicitOps|Mov, ImplicitOps|Mov,
    ImplicitOps|Mov, ImplicitOps|Mov, ImplicitOps|Mov, ImplicitOps|Mov,
    /* 0x60 - 0x6F */
    0, 0, 0, DstReg|SrcMem32|ModRM|Mov /* movsxd (x86/64) */,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    /* 0x70 - 0x77 */
    ImplicitOps, ImplicitOps, ImplicitOps, ImplicitOps,
    ImplicitOps, ImplicitOps, ImplicitOps, ImplicitOps,
    /* 0x78 - 0x7F */
    ImplicitOps, ImplicitOps, ImplicitOps, ImplicitOps,
    ImplicitOps, ImplicitOps, ImplicitOps, ImplicitOps,
    /* 0x80 - 0x87 */
    ByteOp|DstMem|SrcImm|ModRM, DstMem|SrcImm|ModRM,
    ByteOp|DstMem|SrcImm|ModRM, DstMem|SrcImmByte|ModRM,
    ByteOp|DstMem|SrcReg|ModRM, DstMem|SrcReg|ModRM,
    ByteOp|DstMem|SrcReg|ModRM, DstMem|SrcReg|ModRM,
    /* 0x88 - 0x8F */
    ByteOp|DstMem|SrcReg|ModRM|Mov, DstMem|SrcReg|ModRM|Mov,
    ByteOp|DstReg|SrcMem|ModRM|Mov, DstReg|SrcMem|ModRM|Mov,
    0, DstReg|SrcNone|ModRM, 0, DstMem|SrcNone|ModRM|Mov,
    /* 0x90 - 0x97 */
    ImplicitOps, ImplicitOps, ImplicitOps, ImplicitOps,
    ImplicitOps, ImplicitOps, ImplicitOps, ImplicitOps,
    /* 0x98 - 0x9F */
    0, 0, 0, 0, 0, 0, 0, 0,
    /* 0xA0 - 0xA7 */
    ByteOp|ImplicitOps|Mov, ImplicitOps|Mov,
    ByteOp|ImplicitOps|Mov, ImplicitOps|Mov,
    ByteOp|ImplicitOps|Mov, ImplicitOps|Mov, 0, 0,
    /* 0xA8 - 0xAF */
    ByteOp|DstReg|SrcImm, DstReg|SrcImm,
    ByteOp|ImplicitOps|Mov, ImplicitOps|Mov,
    ByteOp|ImplicitOps|Mov, ImplicitOps|Mov, 0, 0,
    /* 0xB0 - 0xB7 */
    ByteOp|DstReg|SrcImm|Mov, ByteOp|DstReg|SrcImm|Mov,
    ByteOp|DstReg|SrcImm|Mov, ByteOp|DstReg|SrcImm|Mov,
    ByteOp|DstReg|SrcImm|Mov, ByteOp|DstReg|SrcImm|Mov,
    ByteOp|DstReg|SrcImm|Mov, ByteOp|DstReg|SrcImm|Mov,
    /* 0xB8 - 0xBF */
    DstReg|SrcImm|Mov, DstReg|SrcImm|Mov, DstReg|SrcImm|Mov, DstReg|SrcImm|Mov,
    DstReg|SrcImm|Mov, DstReg|SrcImm|Mov, DstReg|SrcImm|Mov, DstReg|SrcImm|Mov,
    /* 0xC0 - 0xC7 */
    ByteOp|DstMem|SrcImm|ModRM, DstMem|SrcImmByte|ModRM, 0, 0,
    0, 0, ByteOp|DstMem|SrcImm|ModRM|Mov, DstMem|SrcImm|ModRM|Mov,
    /* 0xC8 - 0xCF */
    0, 0, 0, 0, 0, 0, 0, 0,
    /* 0xD0 - 0xD7 */
    ByteOp|DstMem|SrcImplicit|ModRM, DstMem|SrcImplicit|ModRM, 
    ByteOp|DstMem|SrcImplicit|ModRM, DstMem|SrcImplicit|ModRM, 
    ImplicitOps, ImplicitOps, ImplicitOps, ImplicitOps,
    /* 0xD8 - 0xDF */
    0, 0, 0, 0, 0, 0, 0, 0,
    /* 0xE0 - 0xE7 */
    0, 0, 0, ImplicitOps, 0, 0, 0, 0,
    /* 0xE8 - 0xEF */
    0, ImplicitOps, 0, ImplicitOps, 0, 0, 0, 0,
    /* 0xF0 - 0xF7 */
    0, 0, 0, 0,
    0, ImplicitOps, ByteOp|DstMem|SrcNone|ModRM, DstMem|SrcNone|ModRM,
    /* 0xF8 - 0xFF */
    ImplicitOps, ImplicitOps, 0, 0,
    ImplicitOps, ImplicitOps, ByteOp|DstMem|SrcNone|ModRM, DstMem|SrcNone|ModRM
};

static uint8_t twobyte_table[256] = {
    /* 0x00 - 0x0F */
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, ImplicitOps|ModRM, 0, 0,
    /* 0x10 - 0x1F */
    0, 0, 0, 0, 0, 0, 0, 0, ImplicitOps|ModRM, 0, 0, 0, 0, 0, 0, 0,
    /* 0x20 - 0x2F */
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    /* 0x30 - 0x3F */
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    /* 0x40 - 0x47 */
    DstReg|SrcMem|ModRM|Mov, DstReg|SrcMem|ModRM|Mov,
    DstReg|SrcMem|ModRM|Mov, DstReg|SrcMem|ModRM|Mov,
    DstReg|SrcMem|ModRM|Mov, DstReg|SrcMem|ModRM|Mov,
    DstReg|SrcMem|ModRM|Mov, DstReg|SrcMem|ModRM|Mov,
    /* 0x48 - 0x4F */
    DstReg|SrcMem|ModRM|Mov, DstReg|SrcMem|ModRM|Mov,
    DstReg|SrcMem|ModRM|Mov, DstReg|SrcMem|ModRM|Mov,
    DstReg|SrcMem|ModRM|Mov, DstReg|SrcMem|ModRM|Mov,
    DstReg|SrcMem|ModRM|Mov, DstReg|SrcMem|ModRM|Mov,
    /* 0x50 - 0x5F */
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    /* 0x60 - 0x6F */
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    /* 0x70 - 0x7F */
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    /* 0x80 - 0x87 */
    ImplicitOps, ImplicitOps, ImplicitOps, ImplicitOps,
    ImplicitOps, ImplicitOps, ImplicitOps, ImplicitOps,
    /* 0x88 - 0x8F */
    ImplicitOps, ImplicitOps, ImplicitOps, ImplicitOps,
    ImplicitOps, ImplicitOps, ImplicitOps, ImplicitOps,
    /* 0x90 - 0x9F */
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    /* 0xA0 - 0xA7 */
    0, 0, 0, DstBitBase|SrcReg|ModRM, 0, 0, 0, 0, 
    /* 0xA8 - 0xAF */
    0, 0, 0, DstBitBase|SrcReg|ModRM, 0, 0, 0, 0,
    /* 0xB0 - 0xB7 */
    ByteOp|DstMem|SrcReg|ModRM, DstMem|SrcReg|ModRM,
    0, DstBitBase|SrcReg|ModRM,
    0, 0, ByteOp|DstReg|SrcMem|ModRM|Mov, DstReg|SrcMem16|ModRM|Mov,
    /* 0xB8 - 0xBF */
    0, 0, DstBitBase|SrcImmByte|ModRM, DstBitBase|SrcReg|ModRM,
    0, 0, ByteOp|DstReg|SrcMem|ModRM|Mov, DstReg|SrcMem16|ModRM|Mov,
    /* 0xC0 - 0xC7 */
    ByteOp|DstMem|SrcReg|ModRM, DstMem|SrcReg|ModRM, 0, 0,
    0, 0, 0, ImplicitOps|ModRM,
    /* 0xC8 - 0xCF */
    0, 0, 0, 0, 0, 0, 0, 0,
    /* 0xD0 - 0xDF */
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    /* 0xE0 - 0xEF */
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    /* 0xF0 - 0xFF */
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
};

/* Type, address-of, and value of an instruction's operand. */
struct operand {
    enum { OP_REG, OP_MEM, OP_IMM } type;
    unsigned int  bytes;
    unsigned long val, orig_val;
    union {
        /* OP_REG: Pointer to register field. */
        unsigned long *reg;
        /* OP_MEM: Segment and offset. */
        struct {
            enum x86_segment seg;
            unsigned long    off;
        } mem;
    };
};

/* EFLAGS bit definitions. */
#define EFLG_OF (1<<11)
#define EFLG_DF (1<<10)
#define EFLG_SF (1<<7)
#define EFLG_ZF (1<<6)
#define EFLG_AF (1<<4)
#define EFLG_PF (1<<2)
#define EFLG_CF (1<<0)

/* Exception definitions. */
#define EXC_DE 0

/*
 * Instruction emulation:
 * Most instructions are emulated directly via a fragment of inline assembly
 * code. This allows us to save/restore EFLAGS and thus very easily pick up
 * any modified flags.
 */

#if defined(__x86_64__)
#define _LO32 "k"          /* force 32-bit operand */
#define _STK  "%%rsp"      /* stack pointer */
#elif defined(__i386__)
#define _LO32 ""           /* force 32-bit operand */
#define _STK  "%%esp"      /* stack pointer */
#endif

/*
 * These EFLAGS bits are restored from saved value during emulation, and
 * any changes are written back to the saved value after emulation.
 */
#define EFLAGS_MASK (EFLG_OF|EFLG_SF|EFLG_ZF|EFLG_AF|EFLG_PF|EFLG_CF)

/* Before executing instruction: restore necessary bits in EFLAGS. */
#define _PRE_EFLAGS(_sav, _msk, _tmp)           \
/* EFLAGS = (_sav & _msk) | (EFLAGS & ~_msk); */\
"push %"_sav"; "                                \
"movl %"_msk",%"_LO32 _tmp"; "                  \
"andl %"_LO32 _tmp",("_STK"); "                 \
"pushf; "                                       \
"notl %"_LO32 _tmp"; "                          \
"andl %"_LO32 _tmp",("_STK"); "                 \
"pop  %"_tmp"; "                                \
"orl  %"_LO32 _tmp",("_STK"); "                 \
"popf; "                                        \
/* _sav &= ~msk; */                             \
"movl %"_msk",%"_LO32 _tmp"; "                  \
"notl %"_LO32 _tmp"; "                          \
"andl %"_LO32 _tmp",%"_sav"; "

/* After executing instruction: write-back necessary bits in EFLAGS. */
#define _POST_EFLAGS(_sav, _msk, _tmp)          \
/* _sav |= EFLAGS & _msk; */                    \
"pushf; "                                       \
"pop  %"_tmp"; "                                \
"andl %"_msk",%"_LO32 _tmp"; "                  \
"orl  %"_LO32 _tmp",%"_sav"; "

/* Raw emulation: instruction has two explicit operands. */
#define __emulate_2op_nobyte(_op,_src,_dst,_eflags,_wx,_wy,_lx,_ly,_qx,_qy)\
do{ unsigned long _tmp;                                                    \
    switch ( (_dst).bytes )                                                \
    {                                                                      \
    case 2:                                                                \
        __asm__ __volatile__ (                                             \
            _PRE_EFLAGS("0","4","2")                                       \
            _op"w %"_wx"3,%1; "                                            \
            _POST_EFLAGS("0","4","2")                                      \
            : "=m" (_eflags), "=m" ((_dst).val), "=&r" (_tmp)              \
            : _wy ((_src).val), "i" (EFLAGS_MASK) );                       \
        break;                                                             \
    case 4:                                                                \
        __asm__ __volatile__ (                                             \
            _PRE_EFLAGS("0","4","2")                                       \
            _op"l %"_lx"3,%1; "                                            \
            _POST_EFLAGS("0","4","2")                                      \
            : "=m" (_eflags), "=m" ((_dst).val), "=&r" (_tmp)              \
            : _ly ((_src).val), "i" (EFLAGS_MASK) );                       \
        break;                                                             \
    case 8:                                                                \
        __emulate_2op_8byte(_op, _src, _dst, _eflags, _qx, _qy);           \
        break;                                                             \
    }                                                                      \
} while (0)
#define __emulate_2op(_op,_src,_dst,_eflags,_bx,_by,_wx,_wy,_lx,_ly,_qx,_qy)\
do{ unsigned long _tmp;                                                    \
    switch ( (_dst).bytes )                                                \
    {                                                                      \
    case 1:                                                                \
        __asm__ __volatile__ (                                             \
            _PRE_EFLAGS("0","4","2")                                       \
            _op"b %"_bx"3,%1; "                                            \
            _POST_EFLAGS("0","4","2")                                      \
            : "=m" (_eflags), "=m" ((_dst).val), "=&r" (_tmp)              \
            : _by ((_src).val), "i" (EFLAGS_MASK) );                       \
        break;                                                             \
    default:                                                               \
        __emulate_2op_nobyte(_op,_src,_dst,_eflags,_wx,_wy,_lx,_ly,_qx,_qy);\
        break;                                                             \
    }                                                                      \
} while (0)
/* Source operand is byte-sized and may be restricted to just %cl. */
#define emulate_2op_SrcB(_op, _src, _dst, _eflags)                         \
    __emulate_2op(_op, _src, _dst, _eflags,                                \
                  "b", "c", "b", "c", "b", "c", "b", "c")
/* Source operand is byte, word, long or quad sized. */
#define emulate_2op_SrcV(_op, _src, _dst, _eflags)                         \
    __emulate_2op(_op, _src, _dst, _eflags,                                \
                  "b", "q", "w", "r", _LO32, "r", "", "r")
/* Source operand is word, long or quad sized. */
#define emulate_2op_SrcV_nobyte(_op, _src, _dst, _eflags)                  \
    __emulate_2op_nobyte(_op, _src, _dst, _eflags,                         \
                  "w", "r", _LO32, "r", "", "r")

/* Instruction has only one explicit operand (no source operand). */
#define emulate_1op(_op,_dst,_eflags)                                      \
do{ unsigned long _tmp;                                                    \
    switch ( (_dst).bytes )                                                \
    {                                                                      \
    case 1:                                                                \
        __asm__ __volatile__ (                                             \
            _PRE_EFLAGS("0","3","2")                                       \
            _op"b %1; "                                                    \
            _POST_EFLAGS("0","3","2")                                      \
            : "=m" (_eflags), "=m" ((_dst).val), "=&r" (_tmp)              \
            : "i" (EFLAGS_MASK) );                                         \
        break;                                                             \
    case 2:                                                                \
        __asm__ __volatile__ (                                             \
            _PRE_EFLAGS("0","3","2")                                       \
            _op"w %1; "                                                    \
            _POST_EFLAGS("0","3","2")                                      \
            : "=m" (_eflags), "=m" ((_dst).val), "=&r" (_tmp)              \
            : "i" (EFLAGS_MASK) );                                         \
        break;                                                             \
    case 4:                                                                \
        __asm__ __volatile__ (                                             \
            _PRE_EFLAGS("0","3","2")                                       \
            _op"l %1; "                                                    \
            _POST_EFLAGS("0","3","2")                                      \
            : "=m" (_eflags), "=m" ((_dst).val), "=&r" (_tmp)              \
            : "i" (EFLAGS_MASK) );                                         \
        break;                                                             \
    case 8:                                                                \
        __emulate_1op_8byte(_op, _dst, _eflags);                           \
        break;                                                             \
    }                                                                      \
} while (0)

/* Emulate an instruction with quadword operands (x86/64 only). */
#if defined(__x86_64__)
#define __emulate_2op_8byte(_op, _src, _dst, _eflags, _qx, _qy)         \
do{ __asm__ __volatile__ (                                              \
        _PRE_EFLAGS("0","4","2")                                        \
        _op"q %"_qx"3,%1; "                                             \
        _POST_EFLAGS("0","4","2")                                       \
        : "=m" (_eflags), "=m" ((_dst).val), "=&r" (_tmp)               \
        : _qy ((_src).val), "i" (EFLAGS_MASK) );                        \
} while (0)
#define __emulate_1op_8byte(_op, _dst, _eflags)                         \
do{ __asm__ __volatile__ (                                              \
        _PRE_EFLAGS("0","3","2")                                        \
        _op"q %1; "                                                     \
        _POST_EFLAGS("0","3","2")                                       \
        : "=m" (_eflags), "=m" ((_dst).val), "=&r" (_tmp)               \
        : "i" (EFLAGS_MASK) );                                          \
} while (0)
#elif defined(__i386__)
#define __emulate_2op_8byte(_op, _src, _dst, _eflags, _qx, _qy)
#define __emulate_1op_8byte(_op, _dst, _eflags)
#endif /* __i386__ */

/* Fetch next part of the instruction being emulated. */
#define insn_fetch_bytes(_size)                                         \
({ unsigned long _x, _eip = _truncate_ea(_regs.eip, def_ad_bytes);      \
   if ( !mode_64bit() ) _eip = (uint32_t)_eip; /* ignore upper dword */ \
   rc = ops->insn_fetch(x86_seg_cs, _eip, &_x, (_size), ctxt);          \
   if ( rc ) goto done;                                                 \
   _regs.eip += (_size); /* real hardware doesn't truncate */           \
   _x;                                                                  \
})
#define insn_fetch_type(_type) ((_type)insn_fetch_bytes(sizeof(_type)))

#define _truncate_ea(ea, byte_width)                    \
({  unsigned long __ea = (ea);                          \
    (((byte_width) == sizeof(unsigned long)) ? __ea :   \
     (__ea & ((1UL << ((byte_width) << 3)) - 1)));      \
})
#define truncate_ea(ea) _truncate_ea((ea), ad_bytes)

#define mode_64bit() (def_ad_bytes == 8)

#define fail_if(p)                              \
do {                                            \
    rc = (p) ? X86EMUL_UNHANDLEABLE : 0;        \
    if ( rc ) goto done;                        \
} while (0)

/* In future we will be able to generate arbitrary exceptions. */
#define generate_exception_if(p, e) fail_if(p)

/* Given byte has even parity (even number of 1s)? */
static int even_parity(uint8_t v)
{
    __asm__ ( "test %%al,%%al; setp %%al"
              : "=a" (v) : "0" (v) );
    return v;
}

/* Update address held in a register, based on addressing mode. */
#define _register_address_increment(reg, inc, byte_width)               \
do {                                                                    \
    int _inc = (inc); /* signed type ensures sign extension to long */  \
    if ( (byte_width) == sizeof(unsigned long) )                        \
        (reg) += _inc;                                                  \
    else if ( mode_64bit() )                                            \
        (reg) = ((reg) + _inc) & ((1UL << ((byte_width) << 3)) - 1);    \
    else                                                                \
        (reg) = ((reg) & ~((1UL << ((byte_width) << 3)) - 1)) |         \
                (((reg) + _inc) & ((1UL << ((byte_width) << 3)) - 1));  \
} while (0)
#define register_address_increment(reg, inc) \
    _register_address_increment((reg), (inc), ad_bytes)

#define jmp_rel(rel)                                                    \
do {                                                                    \
    _regs.eip += (int)(rel);                                            \
    if ( !mode_64bit() )                                                \
        _regs.eip = ((op_bytes == 2)                                    \
                     ? (uint16_t)_regs.eip : (uint32_t)_regs.eip);      \
} while (0)

static int
test_cc(
    unsigned int condition, unsigned int flags)
{
    int rc = 0;

    switch ( (condition & 15) >> 1 )
    {
    case 0: /* o */
        rc |= (flags & EFLG_OF);
        break;
    case 1: /* b/c/nae */
        rc |= (flags & EFLG_CF);
        break;
    case 2: /* z/e */
        rc |= (flags & EFLG_ZF);
        break;
    case 3: /* be/na */
        rc |= (flags & (EFLG_CF|EFLG_ZF));
        break;
    case 4: /* s */
        rc |= (flags & EFLG_SF);
        break;
    case 5: /* p/pe */
        rc |= (flags & EFLG_PF);
        break;
    case 7: /* le/ng */
        rc |= (flags & EFLG_ZF);
        /* fall through */
    case 6: /* l/nge */
        rc |= (!(flags & EFLG_SF) != !(flags & EFLG_OF));
        break;
    }

    /* Odd condition identifiers (lsb == 1) have inverted sense. */
    return (!!rc ^ (condition & 1));
}

void *
decode_register(
    uint8_t modrm_reg, struct cpu_user_regs *regs, int highbyte_regs)
{
    void *p;

    switch ( modrm_reg )
    {
    case  0: p = &regs->eax; break;
    case  1: p = &regs->ecx; break;
    case  2: p = &regs->edx; break;
    case  3: p = &regs->ebx; break;
    case  4: p = (highbyte_regs ?
                  ((unsigned char *)&regs->eax + 1) : 
                  (unsigned char *)&regs->esp); break;
    case  5: p = (highbyte_regs ?
                  ((unsigned char *)&regs->ecx + 1) : 
                  (unsigned char *)&regs->ebp); break;
    case  6: p = (highbyte_regs ?
                  ((unsigned char *)&regs->edx + 1) : 
                  (unsigned char *)&regs->esi); break;
    case  7: p = (highbyte_regs ?
                  ((unsigned char *)&regs->ebx + 1) : 
                  (unsigned char *)&regs->edi); break;
#if defined(__x86_64__)
    case  8: p = &regs->r8;  break;
    case  9: p = &regs->r9;  break;
    case 10: p = &regs->r10; break;
    case 11: p = &regs->r11; break;
    case 12: p = &regs->r12; break;
    case 13: p = &regs->r13; break;
    case 14: p = &regs->r14; break;
    case 15: p = &regs->r15; break;
#endif
    default: p = NULL; break;
    }

    return p;
}

int
x86_emulate(
    struct x86_emulate_ctxt *ctxt,
    struct x86_emulate_ops  *ops)
{
    /* Shadow copy of register state. Committed on successful emulation. */
    struct cpu_user_regs _regs = *ctxt->regs;

    uint8_t b, d, sib, sib_index, sib_base, twobyte = 0, rex_prefix = 0;
    uint8_t modrm, modrm_mod = 0, modrm_reg = 0, modrm_rm = 0;
    unsigned int op_bytes, ad_bytes, def_ad_bytes;
    unsigned int lock_prefix = 0, rep_prefix = 0, i;
    int rc = 0;
    struct operand src, dst;

    /* Data operand effective address (usually computed from ModRM). */
    struct operand ea;

    /* Default is a memory operand relative to segment DS. */
    ea.type    = OP_MEM;
    ea.mem.seg = x86_seg_ds;
    ea.mem.off = 0;

    op_bytes = ad_bytes = def_ad_bytes = ctxt->address_bytes;
    if ( op_bytes == 8 )
    {
        op_bytes = 4;
#ifndef __x86_64__
        return -1;
#endif
    }

    /* Prefix bytes. */
    for ( i = 0; i < 8; i++ )
    {
        switch ( b = insn_fetch_type(uint8_t) )
        {
        case 0x66: /* operand-size override */
            op_bytes ^= 6;      /* switch between 2/4 bytes */
            break;
        case 0x67: /* address-size override */
            if ( mode_64bit() )
                ad_bytes ^= 12; /* switch between 4/8 bytes */
            else
                ad_bytes ^= 6;  /* switch between 2/4 bytes */
            break;
        case 0x2e: /* CS override */
            ea.mem.seg = x86_seg_cs;
            break;
        case 0x3e: /* DS override */
            ea.mem.seg = x86_seg_ds;
            break;
        case 0x26: /* ES override */
            ea.mem.seg = x86_seg_es;
            break;
        case 0x64: /* FS override */
            ea.mem.seg = x86_seg_fs;
            break;
        case 0x65: /* GS override */
            ea.mem.seg = x86_seg_gs;
            break;
        case 0x36: /* SS override */
            ea.mem.seg = x86_seg_ss;
            break;
        case 0xf0: /* LOCK */
            lock_prefix = 1;
            break;
        case 0xf2: /* REPNE/REPNZ */
        case 0xf3: /* REP/REPE/REPZ */
            rep_prefix = 1;
            break;
        case 0x40 ... 0x4f: /* REX */
            if ( !mode_64bit() )
                goto done_prefixes;
            rex_prefix = b;
            continue;
        default:
            goto done_prefixes;
        }

        /* Any legacy prefix after a REX prefix nullifies its effect. */
        rex_prefix = 0;
    }
 done_prefixes:

    if ( rex_prefix & 8 ) /* REX.W */
        op_bytes = 8;

    /* Opcode byte(s). */
    d = opcode_table[b];
    if ( d == 0 )
    {
        /* Two-byte opcode? */
        if ( b == 0x0f )
        {
            twobyte = 1;
            b = insn_fetch_type(uint8_t);
            d = twobyte_table[b];
        }

        /* Unrecognised? */
        if ( d == 0 )
            goto cannot_emulate;
    }

    /* ModRM and SIB bytes. */
    if ( d & ModRM )
    {
        modrm = insn_fetch_type(uint8_t);
        modrm_mod = (modrm & 0xc0) >> 6;
        modrm_reg = ((rex_prefix & 4) << 1) | ((modrm & 0x38) >> 3);
        modrm_rm  = modrm & 0x07;

        if ( modrm_mod == 3 )
        {
            modrm_rm |= (rex_prefix & 1) << 3;
            ea.type = OP_REG;
            ea.reg  = decode_register(
                modrm_rm, &_regs, (d & ByteOp) && (rex_prefix == 0));
        }
        else if ( ad_bytes == 2 )
        {
            /* 16-bit ModR/M decode. */
            switch ( modrm_rm )
            {
            case 0: ea.mem.off = _regs.ebx + _regs.esi; break;
            case 1: ea.mem.off = _regs.ebx + _regs.edi; break;
            case 2: ea.mem.off = _regs.ebp + _regs.esi; break;
            case 3: ea.mem.off = _regs.ebp + _regs.edi; break;
            case 4: ea.mem.off = _regs.esi; break;
            case 5: ea.mem.off = _regs.edi; break;
            case 6: ea.mem.off = _regs.ebp; break;
            case 7: ea.mem.off = _regs.ebx; break;
            }
            switch ( modrm_mod )
            {
            case 0:
                if ( modrm_rm == 6 )
                    ea.mem.off = insn_fetch_type(int16_t);
                break;
            case 1:
                ea.mem.off += insn_fetch_type(int8_t);
                break;
            case 2:
                ea.mem.off += insn_fetch_type(int16_t);
                break;
            }
            ea.mem.off = truncate_ea(ea.mem.off);
        }
        else
        {
            /* 32/64-bit ModR/M decode. */
            if ( modrm_rm == 4 )
            {
                sib = insn_fetch_type(uint8_t);
                sib_index = ((sib >> 3) & 7) | ((rex_prefix << 2) & 8);
                sib_base  = (sib & 7) | ((rex_prefix << 3) & 8);
                if ( sib_index != 4 )
                    ea.mem.off = *(long*)decode_register(sib_index, &_regs, 0);
                ea.mem.off <<= (sib >> 6) & 3;
                if ( (modrm_mod == 0) && ((sib_base & 7) == 5) )
                    ea.mem.off += insn_fetch_type(int32_t);
                else if ( (sib_base == 4) && !twobyte && (b == 0x8f) )
                    /* POP <rm> must have its EA calculated post increment. */
                    ea.mem.off += _regs.esp +
                        ((mode_64bit() && (op_bytes == 4)) ? 8 : op_bytes);
                else
                    ea.mem.off += *(long*)decode_register(sib_base, &_regs, 0);
            }
            else
            {
                modrm_rm |= (rex_prefix & 1) << 3;
                ea.mem.off = *(long *)decode_register(modrm_rm, &_regs, 0);
            }
            switch ( modrm_mod )
            {
            case 0:
                if ( (modrm_rm & 7) != 5 )
                    break;
                ea.mem.off = insn_fetch_type(int32_t);
                if ( !mode_64bit() )
                    break;
                /* Relative to RIP of next instruction. Argh! */
                ea.mem.off += _regs.eip;
                if ( (d & SrcMask) == SrcImm )
                    ea.mem.off += (d & ByteOp) ? 1 :
                        ((op_bytes == 8) ? 4 : op_bytes);
                else if ( (d & SrcMask) == SrcImmByte )
                    ea.mem.off += 1;
                else if ( ((b == 0xf6) || (b == 0xf7)) &&
                          ((modrm_reg & 7) <= 1) )
                    /* Special case in Grp3: test has immediate operand. */
                    ea.mem.off += (d & ByteOp) ? 1
                        : ((op_bytes == 8) ? 4 : op_bytes);
                break;
            case 1:
                ea.mem.off += insn_fetch_type(int8_t);
                break;
            case 2:
                ea.mem.off += insn_fetch_type(int32_t);
                break;
            }
            ea.mem.off = truncate_ea(ea.mem.off);
        }
    }

    /* Special instructions do their own operand decoding. */
    if ( (d & DstMask) == ImplicitOps )
        goto special_insn;

    /* Decode and fetch the source operand: register, memory or immediate. */
    switch ( d & SrcMask )
    {
    case SrcNone:
        break;
    case SrcReg:
        src.type = OP_REG;
        if ( d & ByteOp )
        {
            src.reg = decode_register(modrm_reg, &_regs, (rex_prefix == 0));
            src.val = *(uint8_t *)src.reg;
            src.bytes = 1;
        }
        else
        {
            src.reg = decode_register(modrm_reg, &_regs, 0);
            switch ( (src.bytes = op_bytes) )
            {
            case 2: src.val = *(uint16_t *)src.reg; break;
            case 4: src.val = *(uint32_t *)src.reg; break;
            case 8: src.val = *(uint64_t *)src.reg; break;
            }
        }
        break;
    case SrcMem16:
        ea.bytes = 2;
        goto srcmem_common;
    case SrcMem32:
        ea.bytes = 4;
        goto srcmem_common;
    case SrcMem:
        ea.bytes = (d & ByteOp) ? 1 : op_bytes;
    srcmem_common:
        src = ea;
        if ( src.type == OP_REG )
        {
            switch ( src.bytes )
            {
            case 1: src.val = *(uint8_t  *)src.reg; break;
            case 2: src.val = *(uint16_t *)src.reg; break;
            case 4: src.val = *(uint32_t *)src.reg; break;
            case 8: src.val = *(uint64_t *)src.reg; break;
            }
        }
        else if ( (rc = ops->read(src.mem.seg, src.mem.off,
                                  &src.val, src.bytes, ctxt)) )
            goto done;
        break;
    case SrcImm:
        src.type  = OP_IMM;
        src.bytes = (d & ByteOp) ? 1 : op_bytes;
        if ( src.bytes == 8 ) src.bytes = 4;
        /* NB. Immediates are sign-extended as necessary. */
        switch ( src.bytes )
        {
        case 1: src.val = insn_fetch_type(int8_t);  break;
        case 2: src.val = insn_fetch_type(int16_t); break;
        case 4: src.val = insn_fetch_type(int32_t); break;
        }
        break;
    case SrcImmByte:
        src.type  = OP_IMM;
        src.bytes = 1;
        src.val   = insn_fetch_type(int8_t);
        break;
    }

    /* Decode and fetch the destination operand: register or memory. */
    switch ( d & DstMask )
    {
    case DstReg:
        dst.type = OP_REG;
        if ( d & ByteOp )
        {
            dst.reg = decode_register(modrm_reg, &_regs, (rex_prefix == 0));
            dst.val = *(uint8_t *)dst.reg;
            dst.bytes = 1;
        }
        else
        {
            dst.reg = decode_register(modrm_reg, &_regs, 0);
            switch ( (dst.bytes = op_bytes) )
            {
            case 2: dst.val = *(uint16_t *)dst.reg; break;
            case 4: dst.val = *(uint32_t *)dst.reg; break;
            case 8: dst.val = *(uint64_t *)dst.reg; break;
            }
        }
        break;
    case DstBitBase:
        if ( ((d & SrcMask) == SrcImmByte) || (ea.type == OP_REG) )
        {
            src.val &= (op_bytes << 3) - 1;
        }
        else
        {
            /*
             * EA       += BitOffset DIV op_bytes*8
             * BitOffset = BitOffset MOD op_byte*8
             * DIV truncates towards negative infinity.
             * MOD always produces a positive result.
             */
            if ( op_bytes == 2 )
                src.val = (int16_t)src.val;
            else if ( op_bytes == 4 )
                src.val = (int32_t)src.val;
            if ( (long)src.val < 0 )
            {
                unsigned long byte_offset;
                byte_offset = op_bytes + (((-src.val-1) >> 3) & ~(op_bytes-1));
                ea.mem.off -= byte_offset;
                src.val = (byte_offset << 3) + src.val;
            }
            else
            {
                ea.mem.off += (src.val >> 3) & ~(op_bytes - 1);
                src.val &= (op_bytes << 3) - 1;
            }
        }
        /* Becomes a normal DstMem operation from here on. */
        d = (d & ~DstMask) | DstMem;
    case DstMem:
        ea.bytes = (d & ByteOp) ? 1 : op_bytes;
        dst = ea;
        if ( dst.type == OP_REG )
        {
            switch ( dst.bytes )
            {
            case 1: dst.val = *(uint8_t  *)dst.reg; break;
            case 2: dst.val = *(uint16_t *)dst.reg; break;
            case 4: dst.val = *(uint32_t *)dst.reg; break;
            case 8: dst.val = *(uint64_t *)dst.reg; break;
            }
        }
        else if ( !(d & Mov) && /* optimisation - avoid slow emulated read */
                  (rc = ops->read(dst.mem.seg, dst.mem.off,
                                  &dst.val, dst.bytes, ctxt)) )
            goto done;
        break;
    }
    dst.orig_val = dst.val;

    if ( twobyte )
        goto twobyte_insn;

    switch ( b )
    {
    case 0x04 ... 0x05: /* add imm,%%eax */
        dst.reg = (unsigned long *)&_regs.eax;
        dst.val = dst.orig_val = _regs.eax;
    case 0x00 ... 0x03: add: /* add */
        emulate_2op_SrcV("add", src, dst, _regs.eflags);
        break;

    case 0x0c ... 0x0d: /* or imm,%%eax */
        dst.reg = (unsigned long *)&_regs.eax;
        dst.val = dst.orig_val = _regs.eax;
    case 0x08 ... 0x0b: or:  /* or */
        emulate_2op_SrcV("or", src, dst, _regs.eflags);
        break;

    case 0x14 ... 0x15: /* adc imm,%%eax */
        dst.reg = (unsigned long *)&_regs.eax;
        dst.val = dst.orig_val = _regs.eax;
    case 0x10 ... 0x13: adc: /* adc */
        emulate_2op_SrcV("adc", src, dst, _regs.eflags);
        break;

    case 0x1c ... 0x1d: /* sbb imm,%%eax */
        dst.reg = (unsigned long *)&_regs.eax;
        dst.val = dst.orig_val = _regs.eax;
    case 0x18 ... 0x1b: sbb: /* sbb */
        emulate_2op_SrcV("sbb", src, dst, _regs.eflags);
        break;

    case 0x24 ... 0x25: /* and imm,%%eax */
        dst.reg = (unsigned long *)&_regs.eax;
        dst.val = dst.orig_val = _regs.eax;
    case 0x20 ... 0x23: and: /* and */
        emulate_2op_SrcV("and", src, dst, _regs.eflags);
        break;

    case 0x2c ... 0x2d: /* sub imm,%%eax */
        dst.reg = (unsigned long *)&_regs.eax;
        dst.val = dst.orig_val = _regs.eax;
    case 0x28 ... 0x2b: sub: /* sub */
        emulate_2op_SrcV("sub", src, dst, _regs.eflags);
        break;

    case 0x34 ... 0x35: /* xor imm,%%eax */
        dst.reg = (unsigned long *)&_regs.eax;
        dst.val = dst.orig_val = _regs.eax;
    case 0x30 ... 0x33: xor: /* xor */
        emulate_2op_SrcV("xor", src, dst, _regs.eflags);
        break;

    case 0x3c ... 0x3d: /* cmp imm,%%eax */
        dst.reg = (unsigned long *)&_regs.eax;
        dst.val = dst.orig_val = _regs.eax;
    case 0x38 ... 0x3b: cmp: /* cmp */
        emulate_2op_SrcV("cmp", src, dst, _regs.eflags);
        break;

    case 0x63: /* movsxd */
        if ( !mode_64bit() )
            goto cannot_emulate;
        dst.val = (int32_t)src.val;
        break;

    case 0x80 ... 0x83: /* Grp1 */
        switch ( modrm_reg & 7 )
        {
        case 0: goto add;
        case 1: goto or;
        case 2: goto adc;
        case 3: goto sbb;
        case 4: goto and;
        case 5: goto sub;
        case 6: goto xor;
        case 7: goto cmp;
        }
        break;

    case 0xa8 ... 0xa9: /* test imm,%%eax */
        dst.reg = (unsigned long *)&_regs.eax;
        dst.val = dst.orig_val = _regs.eax;
    case 0x84 ... 0x85: test: /* test */
        emulate_2op_SrcV("test", src, dst, _regs.eflags);
        break;

    case 0x86 ... 0x87: xchg: /* xchg */
        /* Write back the register source. */
        switch ( dst.bytes )
        {
        case 1: *(uint8_t  *)src.reg = (uint8_t)dst.val; break;
        case 2: *(uint16_t *)src.reg = (uint16_t)dst.val; break;
        case 4: *src.reg = (uint32_t)dst.val; break; /* 64b reg: zero-extend */
        case 8: *src.reg = dst.val; break;
        }
        /* Write back the memory destination with implicit LOCK prefix. */
        dst.val = src.val;
        lock_prefix = 1;
        break;

    case 0xc6 ... 0xc7: /* mov (sole member of Grp11) */
        fail_if((modrm_reg & 7) != 0);
    case 0x88 ... 0x8b: /* mov */
        dst.val = src.val;
        break;

    case 0x8d: /* lea */
        dst.val = ea.mem.off;
        break;

    case 0x8f: /* pop (sole member of Grp1a) */
        fail_if((modrm_reg & 7) != 0);
        /* 64-bit mode: POP defaults to a 64-bit operand. */
        if ( mode_64bit() && (dst.bytes == 4) )
            dst.bytes = 8;
        if ( (rc = ops->read(x86_seg_ss, truncate_ea(_regs.esp),
                             &dst.val, dst.bytes, ctxt)) != 0 )
            goto done;
        register_address_increment(_regs.esp, dst.bytes);
        break;

    case 0xb0 ... 0xb7: /* mov imm8,r8 */
        dst.reg = decode_register(
            (b & 7) | ((rex_prefix & 1) << 3), &_regs, (rex_prefix == 0));
        dst.val = src.val;
        break;

    case 0xb8 ... 0xbf: /* mov imm{16,32,64},r{16,32,64} */
        if ( dst.bytes == 8 ) /* Fetch more bytes to obtain imm64 */
            src.val = ((uint32_t)src.val |
                       ((uint64_t)insn_fetch_type(uint32_t) << 32));
        dst.reg = decode_register(
            (b & 7) | ((rex_prefix & 1) << 3), &_regs, 0);
        dst.val = src.val;
        break;

    case 0xc0 ... 0xc1: grp2: /* Grp2 */
        switch ( modrm_reg & 7 )
        {
        case 0: /* rol */
            emulate_2op_SrcB("rol", src, dst, _regs.eflags);
            break;
        case 1: /* ror */
            emulate_2op_SrcB("ror", src, dst, _regs.eflags);
            break;
        case 2: /* rcl */
            emulate_2op_SrcB("rcl", src, dst, _regs.eflags);
            break;
        case 3: /* rcr */
            emulate_2op_SrcB("rcr", src, dst, _regs.eflags);
            break;
        case 4: /* sal/shl */
        case 6: /* sal/shl */
            emulate_2op_SrcB("sal", src, dst, _regs.eflags);
            break;
        case 5: /* shr */
            emulate_2op_SrcB("shr", src, dst, _regs.eflags);
            break;
        case 7: /* sar */
            emulate_2op_SrcB("sar", src, dst, _regs.eflags);
            break;
        }
        break;

    case 0xd0 ... 0xd1: /* Grp2 */
        src.val = 1;
        goto grp2;

    case 0xd2 ... 0xd3: /* Grp2 */
        src.val = _regs.ecx;
        goto grp2;

    case 0xf6 ... 0xf7: /* Grp3 */
        switch ( modrm_reg & 7 )
        {
        case 0 ... 1: /* test */
            /* Special case in Grp3: test has an immediate source operand. */
            src.type = OP_IMM;
            src.bytes = (d & ByteOp) ? 1 : op_bytes;
            if ( src.bytes == 8 ) src.bytes = 4;
            switch ( src.bytes )
            {
            case 1: src.val = insn_fetch_type(int8_t);  break;
            case 2: src.val = insn_fetch_type(int16_t); break;
            case 4: src.val = insn_fetch_type(int32_t); break;
            }
            goto test;
        case 2: /* not */
            dst.val = ~dst.val;
            break;
        case 3: /* neg */
            emulate_1op("neg", dst, _regs.eflags);
            break;
        default:
            goto cannot_emulate;
        }
        break;

    case 0xfe: /* Grp4 */
        fail_if((modrm_reg & 7) >= 2);
    case 0xff: /* Grp5 */
        switch ( modrm_reg & 7 )
        {
        case 0: /* inc */
            emulate_1op("inc", dst, _regs.eflags);
            break;
        case 1: /* dec */
            emulate_1op("dec", dst, _regs.eflags);
            break;
        case 6: /* push */
            /* 64-bit mode: PUSH defaults to a 64-bit operand. */
            if ( mode_64bit() && (dst.bytes == 4) )
            {
                dst.bytes = 8;
                if ( (rc = ops->read(dst.mem.seg, dst.mem.off,
                                     &dst.val, 8, ctxt)) != 0 )
                    goto done;
            }
            register_address_increment(_regs.esp, -dst.bytes);
            if ( (rc = ops->write(x86_seg_ss, truncate_ea(_regs.esp),
                                  dst.val, dst.bytes, ctxt)) != 0 )
                goto done;
            dst.val = dst.orig_val; /* skanky: disable writeback */
            break;
        case 7:
            fail_if(1);
        default:
            goto cannot_emulate;
        }
        break;
    }

 writeback:
    if ( (d & Mov) || (dst.orig_val != dst.val) )
    {
        switch ( dst.type )
        {
        case OP_REG:
            /* The 4-byte case *is* correct: in 64-bit mode we zero-extend. */
            switch ( dst.bytes )
            {
            case 1: *(uint8_t  *)dst.reg = (uint8_t)dst.val; break;
            case 2: *(uint16_t *)dst.reg = (uint16_t)dst.val; break;
            case 4: *dst.reg = (uint32_t)dst.val; break; /* 64b: zero-ext */
            case 8: *dst.reg = dst.val; break;
            }
            break;
        case OP_MEM:
            if ( lock_prefix )
                rc = ops->cmpxchg(
                    dst.mem.seg, dst.mem.off, dst.orig_val,
                    dst.val, dst.bytes, ctxt);
            else
                rc = ops->write(
                    dst.mem.seg, dst.mem.off, dst.val, dst.bytes, ctxt);
            if ( rc != 0 )
                goto done;
        default:
            break;
        }
    }

    /* Commit shadow register state. */
    *ctxt->regs = _regs;

 done:
    return (rc == X86EMUL_UNHANDLEABLE) ? -1 : 0;

 special_insn:
    /* Default action: disable writeback. There may be no dest operand. */
    dst.orig_val = dst.val;

    if ( twobyte )
        goto twobyte_special_insn;

    if ( rep_prefix )
    {
        if ( _regs.ecx == 0 )
        {
            ctxt->regs->eip = _regs.eip;
            goto done;
        }
        _regs.ecx--;
        _regs.eip = ctxt->regs->eip;
    }

    switch ( b )
    {
    case 0x27: /* daa */ {
        uint8_t al = _regs.eax;
        unsigned long tmp;
        fail_if(mode_64bit());
        __asm__ __volatile__ (
            _PRE_EFLAGS("0","4","2") "daa; " _POST_EFLAGS("0","4","2")
            : "=m" (_regs.eflags), "=a" (al), "=&r" (tmp)
            : "a" (al), "i" (EFLAGS_MASK) );
        *(uint8_t *)_regs.eax = al;
        break;
    }

    case 0x2f: /* das */ {
        uint8_t al = _regs.eax;
        unsigned long tmp;
        fail_if(mode_64bit());
        __asm__ __volatile__ (
            _PRE_EFLAGS("0","4","2") "das; " _POST_EFLAGS("0","4","2")
            : "=m" (_regs.eflags), "=a" (al), "=&r" (tmp)
            : "a" (al), "i" (EFLAGS_MASK) );
        *(uint8_t *)_regs.eax = al;
        break;
    }

    case 0x37: /* aaa */
    case 0x3f: /* aas */
        fail_if(mode_64bit());
        _regs.eflags &= ~EFLG_CF;
        if ( ((uint8_t)_regs.eax > 9) || (_regs.eflags & EFLG_AF) )
        {
            ((uint8_t *)&_regs.eax)[0] += (b == 0x37) ? 6 : -6;
            ((uint8_t *)&_regs.eax)[1] += (b == 0x37) ? 1 : -1;
            _regs.eflags |= EFLG_CF | EFLG_AF;
        }
        ((uint8_t *)&_regs.eax)[0] &= 0x0f;
        break;

    case 0x40 ... 0x4f: /* inc/dec reg */
        dst.type  = OP_REG;
        dst.reg   = decode_register(b & 7, &_regs, 0);
        dst.bytes = op_bytes;
        dst.orig_val = dst.val = *dst.reg;
        if ( b & 8 )
            emulate_1op("dec", dst, _regs.eflags);
        else
            emulate_1op("inc", dst, _regs.eflags);
        break;

    case 0x50 ... 0x57: /* push reg */
        dst.type  = OP_MEM;
        dst.bytes = op_bytes;
        if ( mode_64bit() && (dst.bytes == 4) )
            dst.bytes = 8;
        dst.val = *(unsigned long *)decode_register(
            (b & 7) | ((rex_prefix & 1) << 3), &_regs, 0);
        register_address_increment(_regs.esp, -dst.bytes);
        dst.mem.seg = x86_seg_ss;
        dst.mem.off = truncate_ea(_regs.esp);
        break;

    case 0x58 ... 0x5f: /* pop reg */
        dst.type  = OP_REG;
        dst.reg   = decode_register(
            (b & 7) | ((rex_prefix & 1) << 3), &_regs, 0);
        dst.bytes = op_bytes;
        if ( mode_64bit() && (dst.bytes == 4) )
            dst.bytes = 8;
        if ( (rc = ops->read(x86_seg_ss, truncate_ea(_regs.esp),
                             &dst.val, dst.bytes, ctxt)) != 0 )
            goto done;
        register_address_increment(_regs.esp, dst.bytes);
        break;

    case 0x70 ... 0x7f: /* jcc (short) */ {
        int rel = insn_fetch_type(int8_t);
        if ( test_cc(b, _regs.eflags) )
            jmp_rel(rel);
        break;
    }

    case 0x90: /* nop / xchg %%r8,%%rax */
        if ( !(rex_prefix & 1) )
            break; /* nop */

    case 0x91 ... 0x97: /* xchg reg,%%rax */
        src.type = dst.type = OP_REG;
        src.bytes = dst.bytes = op_bytes;
        src.reg  = (unsigned long *)&_regs.eax;
        src.val  = *src.reg;
        dst.reg  = decode_register(
            (b & 7) | ((rex_prefix & 1) << 3), &_regs, 0);
        dst.val  = dst.orig_val = *dst.reg;
        goto xchg;

    case 0xa0 ... 0xa1: /* mov mem.offs,{%al,%ax,%eax,%rax} */
        /* Source EA is not encoded via ModRM. */
        dst.type  = OP_REG;
        dst.reg   = (unsigned long *)&_regs.eax;
        dst.bytes = (d & ByteOp) ? 1 : op_bytes;
        if ( (rc = ops->read(ea.mem.seg, insn_fetch_bytes(ad_bytes),
                             &dst.val, dst.bytes, ctxt)) != 0 )
            goto done;
        break;

    case 0xa2 ... 0xa3: /* mov {%al,%ax,%eax,%rax},mem.offs */
        /* Destination EA is not encoded via ModRM. */
        dst.type  = OP_MEM;
        dst.mem.seg = ea.mem.seg;
        dst.mem.off = insn_fetch_bytes(ad_bytes);
        dst.bytes = (d & ByteOp) ? 1 : op_bytes;
        dst.val   = (unsigned long)_regs.eax;
        break;

    case 0xa4 ... 0xa5: /* movs */
        dst.type  = OP_MEM;
        dst.bytes = (d & ByteOp) ? 1 : op_bytes;
        dst.mem.seg = x86_seg_es;
        dst.mem.off = truncate_ea(_regs.edi);
        if ( (rc = ops->read(ea.mem.seg, truncate_ea(_regs.esi),
                             &dst.val, dst.bytes, ctxt)) != 0 )
            goto done;
        register_address_increment(
            _regs.esi, (_regs.eflags & EFLG_DF) ? -dst.bytes : dst.bytes);
        register_address_increment(
            _regs.edi, (_regs.eflags & EFLG_DF) ? -dst.bytes : dst.bytes);
        break;

    case 0xaa ... 0xab: /* stos */
        dst.type  = OP_MEM;
        dst.bytes = (d & ByteOp) ? 1 : op_bytes;
        dst.mem.seg = x86_seg_es;
        dst.mem.off = truncate_ea(_regs.edi);
        dst.val   = _regs.eax;
        register_address_increment(
            _regs.edi, (_regs.eflags & EFLG_DF) ? -dst.bytes : dst.bytes);
        break;

    case 0xac ... 0xad: /* lods */
        dst.type  = OP_REG;
        dst.bytes = (d & ByteOp) ? 1 : op_bytes;
        dst.reg   = (unsigned long *)&_regs.eax;
        if ( (rc = ops->read(ea.mem.seg, truncate_ea(_regs.esi),
                             &dst.val, dst.bytes, ctxt)) != 0 )
            goto done;
        register_address_increment(
            _regs.esi, (_regs.eflags & EFLG_DF) ? -dst.bytes : dst.bytes);
        break;

    case 0xd4: /* aam */ {
        unsigned int base = insn_fetch_type(uint8_t);
        uint8_t al = _regs.eax;
        fail_if(mode_64bit());
        generate_exception_if(base == 0, EXC_DE);
        *(uint16_t *)&_regs.eax = ((al / base) << 8) | (al % base);
        _regs.eflags &= ~(EFLG_SF|EFLG_ZF|EFLG_PF);
        _regs.eflags |= ((uint8_t)_regs.eax == 0) ? EFLG_ZF : 0;
        _regs.eflags |= (( int8_t)_regs.eax <  0) ? EFLG_SF : 0;
        _regs.eflags |= even_parity(_regs.eax) ? EFLG_PF : 0;
        break;
    }

    case 0xd5: /* aad */ {
        unsigned int base = insn_fetch_type(uint8_t);
        uint16_t ax = _regs.eax;
        fail_if(mode_64bit());
        *(uint16_t *)&_regs.eax = (uint8_t)(ax + ((ax >> 8) * base));
        _regs.eflags &= ~(EFLG_SF|EFLG_ZF|EFLG_PF);
        _regs.eflags |= ((uint8_t)_regs.eax == 0) ? EFLG_ZF : 0;
        _regs.eflags |= (( int8_t)_regs.eax <  0) ? EFLG_SF : 0;
        _regs.eflags |= even_parity(_regs.eax) ? EFLG_PF : 0;
        break;
    }

    case 0xd6: /* salc */
        fail_if(mode_64bit());
        *(uint8_t *)&_regs.eax = (_regs.eflags & EFLG_CF) ? 0xff : 0x00;
        break;

    case 0xd7: /* xlat */ {
        unsigned long al = (uint8_t)_regs.eax;
        if ( (rc = ops->read(ea.mem.seg, truncate_ea(_regs.ebx + al),
                             &al, 1, ctxt)) != 0 )
            goto done;
        *(uint8_t *)&_regs.eax = al;
        break;
    }

    case 0xe3: /* jcxz/jecxz (short) */ {
        int rel = insn_fetch_type(int8_t);
        if ( (ad_bytes == 2) ? !(uint16_t)_regs.ecx :
             (ad_bytes == 4) ? !(uint32_t)_regs.ecx : !_regs.ecx )
            jmp_rel(rel);
        break;
    }

    case 0xe9: /* jmp (short) */
        jmp_rel(insn_fetch_type(int8_t));
        break;

    case 0xeb: /* jmp (near) */
        jmp_rel(insn_fetch_bytes(mode_64bit() ? 4 : op_bytes));
        break;

    case 0xf5: /* cmc */
        _regs.eflags ^= EFLG_CF;
        break;

    case 0xf8: /* clc */
        _regs.eflags &= ~EFLG_CF;
        break;

    case 0xf9: /* stc */
        _regs.eflags |= EFLG_CF;
        break;

    case 0xfc: /* cld */
        _regs.eflags &= ~EFLG_DF;
        break;

    case 0xfd: /* std */
        _regs.eflags |= EFLG_DF;
        break;
    }
    goto writeback;

 twobyte_insn:
    switch ( b )
    {
    case 0x40 ... 0x4f: /* cmov */
        dst.val = dst.orig_val = src.val;
        d = (d & ~Mov) | (test_cc(b, _regs.eflags) ? Mov : 0);
        break;

    case 0xb0 ... 0xb1: /* cmpxchg */
        /* Save real source value, then compare EAX against destination. */
        src.orig_val = src.val;
        src.val = _regs.eax;
        emulate_2op_SrcV("cmp", src, dst, _regs.eflags);
        /* Always write back. The question is: where to? */
        d |= Mov;
        if ( _regs.eflags & EFLG_ZF )
        {
            /* Success: write back to memory. */
            dst.val = src.orig_val;
        }
        else
        {
            /* Failure: write the value we saw to EAX. */
            dst.type = OP_REG;
            dst.reg  = (unsigned long *)&_regs.eax;
        }
        break;

    case 0xa3: bt: /* bt */
        emulate_2op_SrcV_nobyte("bt", src, dst, _regs.eflags);
        break;

    case 0xb3: btr: /* btr */
        emulate_2op_SrcV_nobyte("btr", src, dst, _regs.eflags);
        break;

    case 0xab: bts: /* bts */
        emulate_2op_SrcV_nobyte("bts", src, dst, _regs.eflags);
        break;

    case 0xb6: /* movzx rm8,r{16,32,64} */
        /* Recompute DstReg as we may have decoded AH/BH/CH/DH. */
        dst.reg   = decode_register(modrm_reg, &_regs, 0);
        dst.bytes = op_bytes;
        dst.val   = (uint8_t)src.val;
        break;

    case 0xb7: /* movzx rm16,r{16,32,64} */
        dst.val = (uint16_t)src.val;
        break;

    case 0xbb: btc: /* btc */
        emulate_2op_SrcV_nobyte("btc", src, dst, _regs.eflags);
        break;

    case 0xba: /* Grp8 */
        switch ( modrm_reg & 3 )
        {
        case 0: goto bt;
        case 1: goto bts;
        case 2: goto btr;
        case 3: goto btc;
        }
        break;

    case 0xbe: /* movsx rm8,r{16,32,64} */
        /* Recompute DstReg as we may have decoded AH/BH/CH/DH. */
        dst.reg   = decode_register(modrm_reg, &_regs, 0);
        dst.bytes = op_bytes;
        dst.val   = (int8_t)src.val;
        break;

    case 0xbf: /* movsx rm16,r{16,32,64} */
        dst.val = (int16_t)src.val;
        break;

    case 0xc0 ... 0xc1: /* xadd */
        /* Write back the register source. */
        switch ( dst.bytes )
        {
        case 1: *(uint8_t  *)src.reg = (uint8_t)dst.val; break;
        case 2: *(uint16_t *)src.reg = (uint16_t)dst.val; break;
        case 4: *src.reg = (uint32_t)dst.val; break; /* 64b reg: zero-extend */
        case 8: *src.reg = dst.val; break;
        }
        goto add;
    }
    goto writeback;

 twobyte_special_insn:
    switch ( b )
    {
    case 0x0d: /* GrpP (prefetch) */
    case 0x18: /* Grp16 (prefetch/nop) */
        break;

    case 0x80 ... 0x8f: /* jcc (near) */ {
        int rel = insn_fetch_bytes(mode_64bit() ? 4 : op_bytes);
        if ( test_cc(b, _regs.eflags) )
            jmp_rel(rel);
        break;
    }

    case 0xc7: /* Grp9 (cmpxchg8b) */
#if defined(__i386__)
    {
        unsigned long old_lo, old_hi;
        if ( (rc = ops->read(ea.mem.seg, ea.mem.off+0, &old_lo, 4, ctxt)) ||
             (rc = ops->read(ea.mem.seg, ea.mem.off+4, &old_hi, 4, ctxt)) )
            goto done;
        if ( (old_lo != _regs.eax) || (old_hi != _regs.edx) )
        {
            _regs.eax = old_lo;
            _regs.edx = old_hi;
            _regs.eflags &= ~EFLG_ZF;
        }
        else if ( ops->cmpxchg8b == NULL )
        {
            rc = X86EMUL_UNHANDLEABLE;
            goto done;
        }
        else
        {
            if ( (rc = ops->cmpxchg8b(ea.mem.seg, ea.mem.off, old_lo, old_hi,
                                      _regs.ebx, _regs.ecx, ctxt)) != 0 )
                goto done;
            _regs.eflags |= EFLG_ZF;
        }
        break;
    }
#elif defined(__x86_64__)
    {
        unsigned long old, new;
        if ( (rc = ops->read(ea.mem.seg, ea.mem.off, &old, 8, ctxt)) != 0 )
            goto done;
        if ( ((uint32_t)(old>>0) != (uint32_t)_regs.eax) ||
             ((uint32_t)(old>>32) != (uint32_t)_regs.edx) )
        {
            _regs.eax = (uint32_t)(old>>0);
            _regs.edx = (uint32_t)(old>>32);
            _regs.eflags &= ~EFLG_ZF;
        }
        else
        {
            new = (_regs.ecx<<32)|(uint32_t)_regs.ebx;
            if ( (rc = ops->cmpxchg(ea.mem.seg, ea.mem.off, old,
                                    new, 8, ctxt)) != 0 )
                goto done;
            _regs.eflags |= EFLG_ZF;
        }
        break;
    }
#endif
    }
    goto writeback;

 cannot_emulate:
#ifdef __XEN__
    gdprintk(XENLOG_DEBUG, "Instr:");
    for ( ea.mem.off = ctxt->regs->eip; ea.mem.off < _regs.eip; ea.mem.off++ )
    {
        unsigned long x;
        ops->insn_fetch(x86_seg_cs, ea.mem.off, &x, 1, ctxt);
        printk(" %02x", (uint8_t)x);
    }
    printk("\n");
#endif
    return -1;
}
