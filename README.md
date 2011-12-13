pedump
======

Description
-----------
A pure ruby implementation of win32 PE binary files dumper, including:

 * MZ Header
 * DOS stub
 * ['Rich' Header](http://ntcore.com/files/richsign.htm)
 * PE Header
 * Data Directory
 * Sections
 * Resources
 * Strings
 * Imports & Exports
 * PE Packer/Compiler detection
 * a conventient way to upload your PE's to http://pedump.me for a nice HTML tables with image previews, candies & stuff

Installation
------------
    gem install pedump

Usage
-----

    # pedump -h

    Usage: pedump [options]
        -V, --version                    Print version information and exit
        -v, --[no-]verbose               Run verbosely
        -F, --force                      Try to dump by all means
                                         (can cause exceptions & heavy wounds)
        -f, --format FORMAT              Output format: bin,c,dump,hex,inspect,table
                                         (default: table)
            --mz
            --dos-stub
            --rich
            --pe
            --data-directory
            --sections
            --strings
            --resources
            --resource-directory
            --imports
            --exports
            --packer
        -P, --packer-only                packer/compiler detect only,
                                         mimics 'file' command output
            --all                        Dump all but resource-directory (default)
            --va2file VA                 Convert RVA to file offset
        -W, --web                        Uploads files to a http://pedump.me
                                         for a nice HTML tables with image previews,
                                         candies & stuff

### MZ Header

    # pedump --mz calc.exe

    === MZ Header ===
    
                         signature:                     "MZ"
               bytes_in_last_block:        144          0x90
                    blocks_in_file:          3             3
                        num_relocs:          0             0
                 header_paragraphs:          4             4
              min_extra_paragraphs:          0             0
              max_extra_paragraphs:      65535        0xffff
                                ss:          0             0
                                sp:        184          0xb8
                          checksum:          0             0
                                ip:          0             0
                                cs:          0             0
                reloc_table_offset:         64          0x40
                    overlay_number:          0             0
                         reserved0:          0             0
                            oem_id:          0             0
                          oem_info:          0             0
                         reserved2:          0             0
                         reserved3:          0             0
                         reserved4:          0             0
                         reserved5:          0             0
                         reserved6:          0             0
                            lfanew:        232          0xe8

### 'Rich' Header

    # pedump --rich calc.exe

    === RICH Header ===
    
        LIB_ID        VERSION        TIMES_USED   
       149  95      21022  521e         9   9
         1   1          0     0       367 16f
       147  93      21022  521e        29  1d
       132  84      21022  521e       129  81
       131  83      21022  521e        25  19
       148  94      21022  521e         1   1
       145  91      21022  521e         1   1

### PE Header

    # pedump --pe calc.exe

    === PE Header ===
    
                         signature:             "PE\x00\x00"
    
    # IMAGE_FILE_HEADER:
                           Machine:        332         0x14c  x86
                  NumberOfSections:          4             4
                     TimeDateStamp:    "2008-09-14 11:28:52"
              PointerToSymbolTable:          0             0
                   NumberOfSymbols:          0             0
              SizeOfOptionalHeader:        224          0xe0
                   Characteristics:        258         0x102
    
    # IMAGE_OPTIONAL_HEADER:
                             Magic:        267         0x10b  32-bit executable
                     LinkerVersion:                      9.0
                        SizeOfCode:     305664       0x4aa00
             SizeOfInitializedData:     340480       0x53200
           SizeOfUninitializedData:          0             0
               AddressOfEntryPoint:     230155       0x3830b
                        BaseOfCode:       4096        0x1000
                        BaseOfData:     311296       0x4c000
                         ImageBase:   16777216     0x1000000
                  SectionAlignment:       4096        0x1000
                     FileAlignment:        512         0x200
            OperatingSystemVersion:                      5.1
                      ImageVersion:                    5.256
                  SubsystemVersion:                      5.1
                         Reserved1:          0             0
                       SizeOfImage:     659456       0xa1000
                     SizeOfHeaders:       1024         0x400
                          CheckSum:     690555       0xa897b
                         Subsystem:          2             2  WINDOWS_GUI
                DllCharacteristics:      33088        0x8140
                SizeOfStackReserve:     262144       0x40000
                 SizeOfStackCommit:       8192        0x2000
                 SizeOfHeapReserve:    1048576      0x100000
                  SizeOfHeapCommit:       4096        0x1000
                       LoaderFlags:          0             0
               NumberOfRvaAndSizes:         16          0x10

### Data Directory

    # pedump --data-directory calc.exe

    === DATA DIRECTORY ===
    
      EXPORT        rva:0x       0   size:0x        0
      IMPORT        rva:0x   49c1c   size:0x      12c
      RESOURCE      rva:0x   51000   size:0x    4ab07
      EXCEPTION     rva:0x       0   size:0x        0
      SECURITY      rva:0x       0   size:0x        0
      BASERELOC     rva:0x   9c000   size:0x     3588
      DEBUG         rva:0x    1610   size:0x       1c
      ARCHITECTURE  rva:0x       0   size:0x        0
      GLOBALPTR     rva:0x       0   size:0x        0
      TLS           rva:0x       0   size:0x        0
      LOAD_CONFIG   rva:0x    3d78   size:0x       40
      Bound_IAT     rva:0x     280   size:0x      12c
      IAT           rva:0x    1000   size:0x      594
      Delay_IAT     rva:0x   49bac   size:0x       40
      CLR_Header    rva:0x       0   size:0x        0
                    rva:0x       0   size:0x        0

### Sections

    # pedump --sections calc.exe

    === SECTIONS ===
    
      NAME          RVA      VSZ   RAW_SZ  RAW_PTR  nREL  REL_PTR nLINE LINE_PTR     FLAGS
      .text        1000    4a99a    4aa00      400     0        0     0        0  60000020  R-X CODE
      .data       4c000     431c     3000    4ae00     0        0     0        0  c0000040  RW- IDATA
      .rsrc       51000    4ab07    4ac00    4de00     0        0     0        0  40000040  R-- IDATA
      .reloc      9c000     41f6     4200    98a00     0        0     0        0  42000040  R-- IDATA DISCARDABLE

### Resources

    # pedump --resources calc.exe

    === RESOURCES ===
    
    FILE_OFFSET    CP  LANG     SIZE  TYPE          NAME
        0x4ec84     0 0x409     7465  IMAGE         #157
        0x509b0     0 0x409     4086  IMAGE         #165
        0x519a8     0 0x409     4234  IMAGE         #170
        0x52a34     0 0x409     4625  IMAGE         #175
        0x53c48     0 0x409     4873  IMAGE         #180
        0x54f54     0 0x409     3048  IMAGE         #204
        0x55b3c     0 0x409     3052  IMAGE         #208
        0x56728     0 0x409     3217  IMAGE         #212
        0x573bc     0 0x409     3338  IMAGE         #216
        0x580c8     0 0x409     4191  IMAGE         #217
        0x59128     0 0x409     4229  IMAGE         #218
        0x5a1b0     0 0x409     4110  IMAGE         #219
        0x5b1c0     0 0x409     4065  IMAGE         #220
        0x5c1a4     0 0x409     3235  IMAGE         #961
        0x5ce48     0 0x409      470  IMAGE         #981
        0x5d020     0 0x409      587  IMAGE         #982
        0x5d26c     0 0x409      518  IMAGE         #983
        0x5d474     0 0x409     5344  IMAGE         #3000
        0x5e954     0 0x409     4154  IMAGE         #3015
        0x5f990     0 0x409     4815  IMAGE         #3045
        0x60c60     0 0x409     6038  IMAGE         #3051
        0x623f8     0 0x409     4290  IMAGE         #3060
    ...

### Strings

    # pedump --strings calc.exe.mui

    === STRINGS ===
    
       ID    ID  LANG  STRING
        0     0   409  "+/-"
        1     1   409  "C"
        2     2   409  "CE"
        3     3   409  "Backspace"
        4     4   409  "."
        6     6   409  "And"
        7     7   409  "Or"
        8     8   409  "Xor"
        9     9   409  "Lsh"
       10     a   409  "Rsh"
       11     b   409  "/"
       12     c   409  "*"
       13     d   409  "+"
       14     e   409  "-"
       15     f   409  "Mod"
       16    10   409  "R"
       17    11   409  "^"
       18    12   409  "Int"
       19    13   409  "RoL"
       20    14   409  "RoR"
       21    15   409  "Not"
       22    16   409  "sin"
    ...

### Imports

    # pedump --imports calc.exe

    === IMPORTS ===
    
    MODULE_NAME      HINT   ORD  FUNCTION_NAME
    SHLWAPI.dll              e1  
    gdiplus.dll        50        GdipCreateBitmapFromScan0
    gdiplus.dll        5f        GdipCreateHBITMAPFromBitmap
    gdiplus.dll        82        GdipCreateSolidFill
    gdiplus.dll       121        GdipGetImageGraphicsContext
    gdiplus.dll       218        GdipSetInterpolationMode
    gdiplus.dll       249        GdipSetSmoothingMode
    gdiplus.dll       224        GdipSetPageUnit
    gdiplus.dll        bc        GdipDrawLineI
    gdiplus.dll        9b        GdipDrawArcI
    gdiplus.dll        e5        GdipFillRectangleI
    gdiplus.dll        32        GdipCloneBrush
    gdiplus.dll        98        GdipDisposeImage
    gdiplus.dll        4d        GdipCreateBitmapFromHBITMAP
    gdiplus.dll        4f        GdipCreateBitmapFromResource
    gdiplus.dll        5b        GdipCreateFromHDC
    gdiplus.dll        b8        GdipDrawImageRectI
    gdiplus.dll        31        GdipCloneBitmapAreaI
    gdiplus.dll        7a        GdipCreatePen1
    gdiplus.dll        8a        GdipDeleteBrush
    gdiplus.dll        21        GdipAlloc
    gdiplus.dll        ed        GdipFree
    ...

### Exports

    # pedump --exports calc.exe



### Packer / Compiler detection

    # pedump --packer calc.exe



License
-------
Released under the MIT License.  See the [LICENSE](https://github.com/zed-0xff/pedump/blob/master/LICENSE.txt) file for further details.
