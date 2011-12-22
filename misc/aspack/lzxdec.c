//#include <windows.h>

typedef unsigned char BYTE;
typedef int INT;
typedef unsigned int UINT;
typedef unsigned long DWORD;
typedef int BOOL;

#define FALSE 0
#define TRUE  1

#include "lzxdec.h"

/* #define LZX_DEBUG_LOG */

#if defined _DEBUG && defined LZX_DEBUG_LOG
# include <stdio.h>
static FILE* FDebLog = NULL;
#endif

/* ##### *** COMMON FUNCTIONS *** ########################################## */

/* memset local redefinition */
static void lzx_memset(void* dst, int val, unsigned int count)
{
  while( count-- )
  {
    *(char*)(dst) = val;
    dst = (char*)(dst) + 1;
  }
}

/* memcpy local redefinition */
static void lzx_memcpy(void* dst, void* src, unsigned int count)
{
  while( count-- )
  {
    *(char*)(dst) = *(char*)(src);
    dst = (char*)(dst) + 1;
    src = (char*)(src) + 1;
  }
}

/* ##### *** BIT READER FUNCTIONS *** ###################################### */

/* init bit reader */
#define BITRDR_INIT(BitRdr, RawSrc, RawLen)  {          \
  (BitRdr)->SrcData = (RawSrc);                         \
  (BitRdr)->SrcSize = (RawLen);                         \
  (BitRdr)->CurOffs = 0;                                \
  (BitRdr)->BitBuff = 0;                                \
  (BitRdr)->BitFree = 32;                               \
}

/* read input byte (can be rewritten for file io) */
#define BITRDR_GETBYTE(BitRdr, RetVal) {                \
  if ( (BitRdr)->CurOffs < (BitRdr)->SrcSize )          \
    RetVal = (BitRdr)->SrcData[(BitRdr)->CurOffs++];    \
  else                                                  \
    return(-1); /* error */                             \
}

/* remove number of bits from bit buffer */
#define BITRDR_DROPBITS(BitRdr, BitNum)  {              \
  (BitRdr)->BitFree += (BitNum);                        \
}

/* extract integer from bit buffer */
#define BITRDR_GETINT(BitRdr, RetVal)  {                \
  DWORD BitBuff = (BitRdr)->BitBuff;                    \
  UINT  BitFree = (BitRdr)->BitFree;                    \
  UINT  UVal;                                           \
  while( BitFree >= 8 ) {                               \
    BITRDR_GETBYTE(BitRdr, UVal);                       \
    BitBuff = (BitBuff << 8) | UVal;                    \
    BitFree -= 8;                                       \
  }                                                     \
  RetVal = (BitBuff >> (8 - BitFree)) & 0x00ffffff;     \
  (BitRdr)->BitFree = BitFree;                          \
  (BitRdr)->BitBuff = BitBuff;                          \
}

/* read number of bits from bit buffer */
#define BITRDR_GETBITS(BitRdr, BitNum, RetVal)  {       \
  DWORD BitBuff = (BitRdr)->BitBuff;                    \
  UINT  BitFree = (BitRdr)->BitFree;                    \
  UINT  UVal;                                           \
  while( BitFree >= 8 ) {                               \
    BITRDR_GETBYTE(BitRdr, UVal);                       \
    BitBuff = (BitBuff << 8) | UVal;                    \
    BitFree -= 8;                                       \
  }                                                     \
  RetVal = (BitBuff >> (8  - BitFree));                 \
  RetVal = (RetVal & 0x00ffffff) >> (24 - (BitNum));    \
  (BitRdr)->BitFree = (BitFree + (BitNum));             \
  (BitRdr)->BitBuff = BitBuff;                          \
}

/* ##### *** SLIDING WINDOW DICTIONARY FUNCTIONS *** ####################### */

/* init swd context */
#define SWD_INIT(Wnd, Mem, Len)  {                      \
  (Wnd)->Window = (Mem);                                \
  (Wnd)->WndLen = (Len);                                \
  (Wnd)->CurOfs = 0;                                    \
}

/* put byte to dictionary */
#define SWD_PUTBYTE(Wnd, DVal)  {                       \
  if ( (Wnd)->CurOfs < (Wnd)->WndLen )                  \
    (Wnd)->Window[(Wnd)->CurOfs++] = (BYTE)(DVal);      \
  else                                                  \
    return(-1); /* error */                             \
}

/* copy lz phrase in window */
#define SWD_DELTACOPY(Wnd, DOfs, DLen)  {               \
  BYTE* WndPtr;                                         \
  if ( (Wnd)->CurOfs < (DOfs) )                         \
    return(-1); /* error */                             \
  if ( (Wnd)->CurOfs + (DLen) > (Wnd)->WndLen )         \
    return(-1); /* error */                             \
  WndPtr = (Wnd)->Window + (Wnd)->CurOfs;               \
  lzx_memcpy(WndPtr, WndPtr - (DOfs), (DLen));          \
  (Wnd)->CurOfs += (DLen);                              \
}

/* ##### *** HUFFMAN DECODERS FUNCTIONS *** ################################ */

/* init huffman decoder, return next table address */
static BYTE* LzxHuf_Init(LZX_HUFF* Huf, LZX_BITRDR* BitRdr, UINT SymNum,
                         BYTE* HufTbl)
{
  Huf->BitRdr = BitRdr;
  Huf->SymNum = SymNum;
  Huf->Symbol = (UINT*)(HufTbl);
  HufTbl += (SymNum * sizeof(Huf->Symbol[0]));
  Huf->Length = HufTbl;
  HufTbl += (256 * sizeof(Huf->Length[0]));
  return(HufTbl);
}

/* decode one huffman symbol */
static INT LzxHuf_DecodeSymbol(LZX_HUFF* Huf)
{
  UINT HVal, BNum, IOfs;

  BITRDR_GETINT(Huf->BitRdr, HVal);
  HVal &= 0x00fffe00;

  if ( HVal < Huf->SymLim[8] )
    BNum = Huf->Length[HVal >> 16];
  else if ( HVal < Huf->SymLim[10] )
    BNum = (HVal < Huf->SymLim[9]) ? (9) : (10);
  else if ( HVal < Huf->SymLim[11] )
    BNum = 11;
  else if ( HVal < Huf->SymLim[12] )
    BNum = 12;
  else if ( HVal < Huf->SymLim[13] )
    BNum = 13;
  else
    BNum = (HVal < Huf->SymLim[14]) ? (14) : (15);

  BITRDR_DROPBITS(Huf->BitRdr, BNum);
  IOfs = (HVal - Huf->SymLim[BNum-1]) >> (24 - BNum);
  return(Huf->Symbol[Huf->SymIdx[BNum] + IOfs]);
}

/* construct huffman tables */
static INT LzxHuf_HufTblBuild(LZX_HUFF* Huf, BYTE* CodeLen)
{
  UINT LenCnt[16];
  UINT CurIdx[16];
  UINT SymIdx, I;
  UINT Lim, Idx;
  UINT Ofs;
  
  for ( I = 0; I < 16; I++ )
    LenCnt[I] = 0;
  for ( SymIdx = 0; SymIdx < Huf->SymNum; SymIdx++ )
    LenCnt[CodeLen[SymIdx]]++;

#ifdef LZX_DEBUG_LOG
  if ( NULL == FDebLog )
    FDebLog = fopen("lzxdeb.log", "wt");
#endif

  LenCnt[0] = 0;
  CurIdx[0] = 0;
  Huf->SymIdx[0] = 0;
  Huf->SymLim[0] = 0;
  Lim = 0;
  Idx = 0;
  
  for ( I = 1; I < 16; I++ )
  {
    Lim += (LenCnt[I] << (24 - I));
    if ( Lim > 0x1000000 )
      return(-1); /* overrun */

    Huf->SymLim[I] = Lim;
    Huf->SymIdx[I] = Huf->SymIdx[I-1] + LenCnt[I-1];
    CurIdx[I] = Huf->SymIdx[I];
    
    if ( I <= 8 )
    {
      Ofs = (Huf->SymLim[I] >> 16);
      lzx_memset(&Huf->Length[Idx], I, Ofs - Idx);
      Idx = Ofs;
    }
  }
  
  if ( Lim != 0x1000000 )
    return(-1); /* not full set */

#ifdef LZX_DEBUG_LOG
  fprintf(FDebLog, "Huf->SymNum == %u\n", Huf->SymNum);
  fprintf(FDebLog, "Huf->SymIdx == ");
  for ( I = 0; I < 16; I++ )
    fprintf(FDebLog, "%u ", Huf->SymIdx[I]);
  fprintf(FDebLog, "\n");
  fprintf(FDebLog, "Huf->SymLim == ");
  for ( I = 0; I < 16; I++ )
    fprintf(FDebLog, "%u ", Huf->SymLim[I]);
  fprintf(FDebLog, "\n");
  fflush(FDebLog);
#endif
  
  for ( SymIdx = 0; SymIdx < Huf->SymNum; SymIdx++ )
  {
    if ( CodeLen[SymIdx] )
    {
#ifdef LZX_DEBUG_LOG
      fprintf(FDebLog, "%u\n", SymIdx);
      fflush(FDebLog);
#endif
      Huf->Symbol[CurIdx[CodeLen[SymIdx]]++] = SymIdx;
    }
  }

  return(0); /* all ok */
}

/* ##### *** LZX DECODER FUNCTIONS *** ##################################### */

/* basic lzx tables */
static const UINT LzxTblLenBits[28] = {
  0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2, 3, 3, 3, 3, 4, 4, 4, 4,
  5, 5, 5, 5
};
static const UINT LzxTblLenBase[28] = {
   0,  1,  2,  3,  4,  5,   6,   7,   8,  10,  12, 14, 16, 20, 24, 28, 32,
  40, 48, 56, 64, 80, 96, 112, 128, 160, 192, 224
};
static const UINT LzxTblOfsBits[58] = {
   0,  0,  0,  0,  1,  1,  2,  2,  3,  3,  4,  4,  5,  5,  6,  6,  7,  7,
   8,  8,  9,  9, 10, 10, 11, 11, 12, 12, 13, 13, 14, 14, 15, 15, 16, 16,
  17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 18, 18, 18, 18,
  18, 18, 18, 18
};
static const UINT LzxTblOfsBase[58] = {
  0x00000000, 0x00000001, 0x00000002, 0x00000003, 0x00000004, 0x00000006,
  0x00000008, 0x0000000C, 0x00000010, 0x00000018, 0x00000020, 0x00000030,
  0x00000040, 0x00000060, 0x00000080, 0x000000C0, 0x00000100, 0x00000180,
  0x00000200, 0x00000300, 0x00000400, 0x00000600, 0x00000800, 0x00000C00,
  0x00001000, 0x00001800, 0x00002000, 0x00003000, 0x00004000, 0x00006000,
  0x00008000, 0x0000C000, 0x00010000, 0x00018000, 0x00020000, 0x00030000,
  0x00040000, 0x00060000, 0x00080000, 0x000A0000, 0x000C0000, 0x000E0000,
  0x00100000, 0x00120000, 0x00140000, 0x00160000, 0x00180000, 0x001A0000,
  0x001C0000, 0x001E0000, 0x00200000, 0x00240000, 0x00280000, 0x002C0000,
  0x00300000, 0x00340000, 0x00380000, 0x003C0000
};

/* ------------------------------------------------------------------------- */

/* build lzx tables */
static INT Lzx_LzxTblBuild(LZX_CONTEXT* Ctx)
{
  BYTE* Heap;
  BYTE  LenTbl[19];
  BYTE  HufSym[757];
  UINT  Val, I, Sym;
  INT   ISym;

  Heap = Ctx->LstMem;
  BITRDR_GETBITS(&Ctx->BitRdr, 1, Val);
  if ( !Val ) lzx_memset(Heap, 0, 757);

  for ( I = 0; I < 19; I++ )
  {
    BITRDR_GETBITS(&Ctx->BitRdr, 4, Val);
    LenTbl[I] = (BYTE)(Val);
  }
  
  if ( LzxHuf_HufTblBuild(&Ctx->HufSpec, LenTbl) )
    return(-1); /* error */

  I = 0;
  while ( I < 757 )
  {
    if ( (ISym = LzxHuf_DecodeSymbol(&Ctx->HufSpec)) == -1 )
      return(-1); /* error */

    if ( (Sym = (UINT)(ISym)) < 16 )
    {
      HufSym[I] = (BYTE)((Heap[I] + Sym) & 15); I++;
      continue;
    }
    
    if ( Sym == 16 )
    {
      BITRDR_GETBITS(&Ctx->BitRdr, 2, Val); Val += 3;
      while ( Val > 0 && I < 757 )
      {
        HufSym[I] = HufSym[I-1];
        Val--; I++;
      }
      continue;
    }

    if ( Sym == 17 )
    {
      BITRDR_GETBITS(&Ctx->BitRdr, 3, Val);
      Val += 3;
    }
    else
    {
      BITRDR_GETBITS(&Ctx->BitRdr, 7, Val);
      Val += 11;
    }

    while ( Val > 0 && I < 757 )
    {
      HufSym[I] = 0;
      Val--; I++;
    }
  }

  if ( LzxHuf_HufTblBuild(&Ctx->HufBase, &HufSym[0]) )
    return(-1);
  if ( LzxHuf_HufTblBuild(&Ctx->HufLens, &HufSym[721]) )
    return(-1);
  if ( LzxHuf_HufTblBuild(&Ctx->HufOffs, &HufSym[749]) )
    return(-1);

  Ctx->HasOffs = FALSE;
  for ( I = 0; I < 8; I++ )
  {
    if ( HufSym[749+I] != 3 )
    {
      Ctx->HasOffs = TRUE;
      break;
    }
  }
  
  lzx_memcpy(Heap, &HufSym[0], 757);
  return(0); /* all ok */
}

/* ------------------------------------------------------------------------- */

INT DecodeLZX(LZX_CONTEXT* Ctx, BYTE* Src, BYTE* Dst, UINT PSize, UINT USize)
{
  UINT  Written;
  UINT  Symbol;
  BYTE* HufMem;
  UINT  Ofs;
  UINT  Len;
  UINT  Num;
  UINT  Val;
  INT   ISym;

  /* check params */
  if ( !Ctx || !Src || !Dst || !USize )
    return(-1); /* invalid param */

  /* init lzx context */
  BITRDR_INIT(&Ctx->BitRdr, Src, PSize);
  SWD_INIT(&Ctx->Window, Dst, USize);
  Ctx->HasOffs = FALSE;
  Ctx->LstOfs[0] = 0;
  Ctx->LstOfs[1] = 0;
  Ctx->LstOfs[2] = 0;
  
  /* init huffman coders */
  HufMem = &Ctx->HufTbl[0];
  HufMem = LzxHuf_Init(&Ctx->HufBase, &Ctx->BitRdr, 721, HufMem);
  HufMem = LzxHuf_Init(&Ctx->HufLens, &Ctx->BitRdr,  28, HufMem);
  HufMem = LzxHuf_Init(&Ctx->HufOffs, &Ctx->BitRdr,   8, HufMem);
  HufMem = LzxHuf_Init(&Ctx->HufSpec, &Ctx->BitRdr,  19, HufMem);
  lzx_memset(Ctx->LstMem = HufMem, 0, 757);

  /* build lzx tables */
  if ( Lzx_LzxTblBuild(Ctx) )
    return(-1);

  /* decode */
  Written = 0;
  while ( Written < USize )
  {
    if ( (ISym = LzxHuf_DecodeSymbol(&Ctx->HufBase)) == -1 )
      return(-1);

    if ( (Symbol = (UINT)(ISym)) < 256 )
    {
      /* literal */
      SWD_PUTBYTE(&Ctx->Window, Symbol);
      Written++;
      continue;
    }

    if ( Symbol < 720 )
    {
      /* phrase */
      Symbol -= 256;
      Ofs = (Symbol >> 3);
      Len = (Symbol & 7) + 2;

      if ( Len == 9 )
      {
        if ( (ISym = LzxHuf_DecodeSymbol(&Ctx->HufLens)) == -1 )
          return(-1);

        Symbol = (UINT)(ISym);
        Num = LzxTblLenBits[Symbol];
        BITRDR_GETBITS(&Ctx->BitRdr, Num, Val);
        Len += (Val + LzxTblLenBase[Symbol]);
      }

      Num = LzxTblOfsBits[Ofs];
      Ofs = LzxTblOfsBase[Ofs];

      if ( Num < 3 || !Ctx->HasOffs )
      {
        BITRDR_GETBITS(&Ctx->BitRdr, Num, Val);
        Ofs += Val;
      }
      else
      {
        Num -= 3;
        BITRDR_GETBITS(&Ctx->BitRdr, Num, Val);
        if ( (ISym = LzxHuf_DecodeSymbol(&Ctx->HufOffs)) == -1 )
          return(-1);
        Ofs += ((UINT)(ISym) + (Val << 3));
      }

      if ( Ofs < 3 )
      {
        /* use saved last offset */
        Ofs = Ctx->LstOfs[Num = Ofs];
        if ( Num )
        {
          Ctx->LstOfs[Num] = Ctx->LstOfs[0];
          Ctx->LstOfs[0]   = Ofs;
        }
      }
      else
      {
        /* update last offset */
        Ctx->LstOfs[2] = Ctx->LstOfs[1];
        Ctx->LstOfs[1] = Ctx->LstOfs[0];
        Ctx->LstOfs[0] = (Ofs -= 3);
      }

      /* copy phrase */
      SWD_DELTACOPY(&Ctx->Window, Ofs+1, Len);
      Written += Len;
      continue;
    }

    /* update trees */
    if ( Lzx_LzxTblBuild(Ctx) )
      return(-1);
  }

  return(Written); /* all ok */
}

/* ------------------------------------------------------------------------- */
