#ifndef _LZXDEC_H_
#define _LZXDEC_H_  "ASPack's lzx-alike raw stream decoder"

//#include <windows.h>

/* ------------------------------------------------------------------------- */

/* bit reader context */
typedef struct _LZX_BITRDR {
  BYTE*  SrcData;                      /* input raw data */
  UINT   SrcSize;                      /* raw data size  */
  UINT   CurOffs;                      /* current offset */
  DWORD  BitBuff;                      /* bits buffer    */
  UINT   BitFree;                      /* bits counter   */
} LZX_BITRDR, *PLZX_BITRDR;

/* sliding window dictionary */
typedef struct _LZX_SWD {
  BYTE*  Window;                       /* window memory  */
  UINT   WndLen;                       /* size of window */
  UINT   CurOfs;                       /* current offset */
} LZX_SWD, *PLZX_SWD;

/* huffman decoder context */
typedef struct _LZX_HUFF {
  LZX_BITRDR* BitRdr;                  /* bit stream reader       */
  UINT  SymLim[16];                    /* max symbol for x bits   */
  UINT  SymIdx[16];                    /* symbol index for x bits */
  UINT  SymNum;                        /* total number of symbols */
  UINT* Symbol;                        /* symbols array for x len */
  BYTE* Length;                        /* symbols length array    */
} LZX_HUFF, *PLZX_HUFF;

/* general decoder context */
typedef struct _LZX_CONTEXT {
  LZX_BITRDR  BitRdr;                  /* source reader / bit-buffer */
  UINT        LstOfs[3];               /* saved last phrases offsets */
  BYTE*       LstMem;                  /* free huffman heap mem ptr  */
  LZX_SWD     Window;                  /* sliding window dictionary  */
  LZX_HUFF    HufBase;                 /* general huffman decoder    */
  LZX_HUFF    HufLens;                 /* lengths huffman decoder    */
  LZX_HUFF    HufOffs;                 /* offsets huffman decoder    */
  LZX_HUFF    HufSpec;                 /* special huffman decoder    */
  BOOL        HasOffs;                 /* offsets decoder used flag  */
  BYTE        HufTbl[6144];            /* huffman tables heap memory */
} LZX_CONTEXT, *PLZX_CONTEXT;

/* ------------------------------------------------------------------------- */

/* general aspack stream decoder               */
/* return decoded size or -1 in case of errors */
INT DecodeLZX(LZX_CONTEXT* Ctx, BYTE* Src, BYTE* Dst, UINT PSize, UINT USize);

/* ------------------------------------------------------------------------- */

#endif /* _LZXDEC_H_ */
