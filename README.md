pedump    [![Build Status](https://travis-ci.org/zed-0xff/pedump.png?branch=master)](https://travis-ci.org/zed-0xff/pedump) [![ko-fi](https://www.ko-fi.com/img/githubbutton_sm.svg)](https://ko-fi.com/K3K81Z3W5)
======

News
----
```
2024.04.20 - cli: add --set-dll-char to patch dll characteristics
             pe: imphash calculation
             cli: added --imphash option
2024.01.15 - add "--set-os-version VER" cmdline option for patching OS version in PE header
2023.12.04 - workaround IO.pread() not available on windows
2021.02.18 - updated gems; changed open-uri to URI.open; enabled SSL on https://pedump.me/
2020.08.09 - CLI: added resource extracting with --extract ID
2020.07.28 - 0.6.1; better RICH HDR parsing/output
2020.07.27 - 0.6.0
2020.07.26 - now travis autotests run on ARM and OSX too!
2020.07.25 - added EFI TE parsing; removed 'progressbar' gem dependency
```

Description
-----------
A pure ruby implementation of win32 PE binary files dumper.

Supported formats:

 * DOS MZ EXE
 * win16 NE
 * win32 PE
 * win64 PE
 * EFI TE

Can dump:

 * MZ/NE/PE Header
 * DOS stub
 * ['Rich' Header](http://ntcore.com/files/richsign.htm)
 * Data Directory
 * Sections
 * Resources
 * Strings
 * Imports & Exports
 * VS_VERSIONINFO parsing
 * PE Packer/Compiler detection
 * a convenient way to upload your PE's to https://pedump.me for a nice HTML tables with image previews, candies & stuff

Installation
------------
    gem install pedump

Usage
-----

    # pedump -h

    Usage: pedump [options]
            --version                    Print version information and exit
        -v, --verbose                    Run verbosely
                                         (can be used multiple times)
        -q, --quiet                      Silent any warnings
                                         (can be used multiple times)
        -F, --force                      Try to dump by all means
                                         (can cause exceptions & heavy wounds)
        -f, --format FORMAT              Output format: bin,c,dump,hex,inspect,json,table,yaml
                                         (default: table)
    
            --clr                        a shortcut for --clr_header, --clr_metadata, --clr_streams, --clr_tables
            --clr-header                 clr_header
            --clr-metadata               clr_metadata
            --clr-streams                clr_streams
            --clr-tables [TABLES]        clr_tables
            --data-directory             data_directory
            --dos-stub                   dos_stub
        -E, --exports                    exports
            --imphash                    imphash
        -I, --imports                    imports
            --mz                         mz
            --ne                         ne
            --packer                     packer
            --pe                         pe
            --resource-directory         resource_directory
        -R, --resources                  resources
            --rich                       rich
        -S, --sections                   sections
            --security                   security
        -s, --strings                    strings
            --tail                       tail
            --te                         te
            --tls                        tls
        -V, --version-info               version_info
    
            --deep                       packer deep scan, significantly slower
        -P, --packer-only                packer/compiler detect only,
                                         mimics 'file' command output
        -r, --recursive                  recurse dirs in packer detect
            --all                        Dump all but resource-directory (default)
    
            --extract ID                 Extract a resource/section/data_dir
                                         ID: datadir:EXPORT     - datadir by type
                                         ID: resource:0x98478   - resource by offset
                                         ID: resource:ICON/#1   - resource by type & name
                                         ID: section:.text      - section by name
                                         ID: section:rva/0x1000 - section by RVA
                                         ID: section:raw/0x400  - section by RAW_PTR
                                         ID: tail               - file tail
                                         ID: tail:c00           - file tail + 0xc00 offset
            --va2file VA                 Convert RVA to file offset
            --set-os-version VER         Patch OS version in PE header
            --set-dll-char X             Patch IMAGE_OPTIONAL_HEADER32.DllCharacteristics
    
        -W, --web                        Uploads files to a https://pedump.me
                                         for a nice HTML tables with image previews,
                                         candies & stuff
        -C, --console                    opens IRB console with specified file loaded

### MZ Header

    # pedump --mz calc.exe

    === MZ Header ===
    
                         signature:                     "MZ"
               bytes_in_last_block:        144            90
                    blocks_in_file:                        3
                        num_relocs:                        0
                 header_paragraphs:                        4
              min_extra_paragraphs:                        0
              max_extra_paragraphs:      65535          ffff
                                ss:                        0
                                sp:        184            b8
                          checksum:                        0
                                ip:                        0
                                cs:                        0
                reloc_table_offset:         64            40
                    overlay_number:                        0
                         reserved0:                        0
                            oem_id:                        0
                          oem_info:                        0
                         reserved2:                        0
                         reserved3:                        0
                         reserved4:                        0
                         reserved5:                        0
                         reserved6:                        0
                            lfanew:        232            e8

### DOS stub

    # pedump --dos-stub calc.exe

    === DOS STUB ===
    
    00000000: 0e 1f ba 0e 00 b4 09 cd  21 b8 01 4c cd 21 54 68  |.... ...!..L.!Th|
    00000010: 69 73 20 70 72 6f 67 72  61 6d 20 63 61 6e 6e 6f  |is program canno|
    00000020: 74 20 62 65 20 72 75 6e  20 69 6e 20 44 4f 53 20  |t be run in DOS |
    00000030: 6d 6f 64 65 2e 0d 0d 0a  24 00 00 00 00 00 00 00  |mode....$       |

### 'Rich' Header

    # pedump --rich calc.exe

    === RICH Header ===
    
       ID   VER         COUNT  DESCRIPTION
       95  521e             9  [ASM] VS2008 build 21022
        1     0           367  [---] Unmarked objects
       93  521e            29  [IMP] VS2008 build 21022
       84  521e           129  [C++] VS2008 build 21022
       83  521e            25  [ C ] VS2008 build 21022
       94  521e             1  [RES] VS2008 build 21022
       91  521e             1  [LNK] VS2008 build 21022

### PE Header

    # pedump --pe calc.exe

    === PE Header ===
    
                         signature:             "PE\x00\x00"
    
    # IMAGE_FILE_HEADER:
                           Machine:        332           14c  x86
                  NumberOfSections:                        4
                     TimeDateStamp:    "2008-09-14 07:28:52"
              PointerToSymbolTable:                        0
                   NumberOfSymbols:                        0
              SizeOfOptionalHeader:        224            e0
                   Characteristics:        258           102  EXECUTABLE_IMAGE, 32BIT_MACHINE
    
    # IMAGE_OPTIONAL_HEADER32:
                             Magic:        267           10b  32-bit executable
                     LinkerVersion:                      9.0
                        SizeOfCode:     305664         4aa00
             SizeOfInitializedData:     340480         53200
           SizeOfUninitializedData:                        0
               AddressOfEntryPoint:     230155         3830b
                        BaseOfCode:       4096          1000
                        BaseOfData:     311296         4c000
                         ImageBase:   16777216       1000000
                  SectionAlignment:       4096          1000
                     FileAlignment:        512           200
            OperatingSystemVersion:                      5.1
                      ImageVersion:                    5.256
                  SubsystemVersion:                      5.1
                         Reserved1:                        0
                       SizeOfImage:     659456         a1000
                     SizeOfHeaders:       1024           400
                          CheckSum:     690555         a897b
                         Subsystem:                        2  WINDOWS_GUI
                DllCharacteristics:      33088          8140  DYNAMIC_BASE, NX_COMPAT, TERMINAL_SERVER_AWARE
                SizeOfStackReserve:     262144         40000
                 SizeOfStackCommit:       8192          2000
                 SizeOfHeapReserve:    1048576        100000
                  SizeOfHeapCommit:       4096          1000
                       LoaderFlags:                        0
               NumberOfRvaAndSizes:         16            10

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

    # pedump --imports zlib.dll

    === IMPORTS ===
    
    MODULE_NAME      HINT   ORD  FUNCTION_NAME
    KERNEL32.dll       e1        GetLastError
    KERNEL32.dll      153        HeapAlloc
    KERNEL32.dll      159        HeapFree
    KERNEL32.dll       9f        GetCommandLineA
    KERNEL32.dll      103        GetProcAddress
    KERNEL32.dll       eb        GetModuleHandleA
    KERNEL32.dll      137        GetVersion
    KERNEL32.dll      164        InitializeCriticalSection
    KERNEL32.dll       44        DeleteCriticalSection
    KERNEL32.dll       4f        EnterCriticalSection
    KERNEL32.dll      177        LeaveCriticalSection
    KERNEL32.dll      1fa        SetHandleCount
    KERNEL32.dll       dc        GetFileType
    KERNEL32.dll      116        GetStdHandle
    KERNEL32.dll      114        GetStartupInfoA
    KERNEL32.dll      155        HeapCreate
    KERNEL32.dll      157        HeapDestroy
    KERNEL32.dll       c7        GetCurrentThreadId
    KERNEL32.dll      222        TlsSetValue
    KERNEL32.dll      21f        TlsAlloc
    KERNEL32.dll      220        TlsFree
    KERNEL32.dll      1fd        SetLastError
    KERNEL32.dll      221        TlsGetValue
    KERNEL32.dll       62        ExitProcess
    KERNEL32.dll      1b8        ReadFile
    KERNEL32.dll       16        CloseHandle
    KERNEL32.dll      24f        WriteFile
    KERNEL32.dll       83        FlushFileBuffers
    KERNEL32.dll       e9        GetModuleFileNameA
    KERNEL32.dll       98        GetCPInfo
    KERNEL32.dll       92        GetACP
    KERNEL32.dll       f6        GetOEMCP
    KERNEL32.dll       8b        FreeEnvironmentStringsA
    KERNEL32.dll       d0        GetEnvironmentStrings
    KERNEL32.dll       8c        FreeEnvironmentStringsW
    KERNEL32.dll       d2        GetEnvironmentStringsW
    KERNEL32.dll      242        WideCharToMultiByte
    KERNEL32.dll       2b        CreateFileA
    KERNEL32.dll      1f8        SetFilePointer
    KERNEL32.dll      206        SetStdHandle
    KERNEL32.dll      178        LoadLibraryA
    KERNEL32.dll      1ef        SetEndOfFile

### Exports

    # pedump --exports zlib.dll

    === EXPORTS ===
    
    # module "zlib.dll"
    # flags=0x0  ts="1996-05-07 08:46:46"  version=0.0  ord_base=1
    # nFuncs=27  nNames=27
    
      ORD ENTRY_VA  NAME
        1     76d0  adler32
        2     2db0  compress
        3     4aa0  crc32
        4     3c90  deflate
        5     4060  deflateCopy
        6     3fd0  deflateEnd
        7     37f0  deflateInit2_
        8     37c0  deflateInit_
        9     3bc0  deflateParams
        a     3b40  deflateReset
        b     3a40  deflateSetDictionary
        c     7510  gzclose
        d     6f00  gzdopen
        e     75a0  gzerror
        f     73f0  gzflush
       10     6c50  gzopen
       11     7190  gzread
       12     7350  gzwrite
       13     4e50  inflate
       14     4cc0  inflateEnd
       15     4d20  inflateInit2_
       16     4e30  inflateInit_
       17     4c70  inflateReset
       18     5260  inflateSetDictionary
       19     52f0  inflateSync
       1a     4bd0  uncompress
       1b     e340  zlib_version

### VS_VERSIONINFO parsing

    # pedump --version-info calc.exe

    === VERSION INFO ===
    
    # VS_FIXEDFILEINFO:
      FileVersion         :  6.1.6801.0
      ProductVersion      :  6.1.6801.0
      StrucVersion        :  0x10000
      FileFlagsMask       :  0x3f
      FileFlags           :  0
      FileOS              :  0x40004
      FileType            :  1
      FileSubtype         :  0
    
    # StringTable 040904B0:
      CompanyName         :  "Microsoft Corporation"
      FileDescription     :  "Windows Calculator"
      FileVersion         :  "6.1.6801.0 (winmain_win7m3.080913-2030)"
      InternalName        :  "CALC"
      LegalCopyright      :  "© Microsoft Corporation. All rights reserved."
      OriginalFilename    :  "CALC.EXE"
      ProductName         :  "Microsoft® Windows® Operating System"
      ProductVersion      :  "6.1.6801.0"
    
      VarFileInfo         :  [ 0x409, 0x4b0 ]

### Packer / Compiler detection

    # pedump --packer zlib.dll

    === Packer / Compiler ===
    
      MS Visual C v2.0

#### pedump can mimic 'file' command output:

    #pedump --packer-only -qqq samples/*
    
    samples/StringLoader.dll:                 Microsoft Visual C++ 6.0 DLL (Debug)
    samples/control.exe:                      ASPack v2.12
    samples/gms_v1_0_3.exe:                   UPX 2.90 [LZMA] (Markus Oberhumer, Laszlo Molnar & John Reiser)
    samples/unpackme.exe:                     ASProtect 1.33 - 2.1 Registered (Alexey Solodovnikov)
    samples/zlib.dll:                         Microsoft Visual C v2.0

### Extracting

#### Resources

by name:

    # pedump calc.exe --extract resource:VERSION/#1 | hexdump -C | head

    00000000  78 03 34 00 00 00 56 00  53 00 5f 00 56 00 45 00  |x.4...V.S._.V.E.|
    00000010  52 00 53 00 49 00 4f 00  4e 00 5f 00 49 00 4e 00  |R.S.I.O.N._.I.N.|
    00000020  46 00 4f 00 00 00 00 00  bd 04 ef fe 00 00 01 00  |F.O.............|
    00000030  01 00 06 00 00 00 91 1a  01 00 06 00 00 00 91 1a  |................|
    00000040  3f 00 00 00 00 00 00 00  04 00 04 00 01 00 00 00  |?...............|
    00000050  00 00 00 00 00 00 00 00  00 00 00 00 d6 02 00 00  |................|
    00000060  01 00 53 00 74 00 72 00  69 00 6e 00 67 00 46 00  |..S.t.r.i.n.g.F.|
    00000070  69 00 6c 00 65 00 49 00  6e 00 66 00 6f 00 00 00  |i.l.e.I.n.f.o...|
    00000080  b2 02 00 00 01 00 30 00  34 00 30 00 39 00 30 00  |......0.4.0.9.0.|
    00000090  34 00 42 00 30 00 00 00  4c 00 16 00 01 00 43 00  |4.B.0...L.....C.|

by offset:

    # pedump calc.exe --extract resource:0x98478 | head

    <?xml version="1.0" encoding="UTF-8" standalone="yes"?>
    <!-- Copyright (c) Microsoft Corporation -->
    <assembly xmlns="urn:schemas-microsoft-com:asm.v1" manifestVersion="1.0">
    <assemblyIdentity
        name="Microsoft.Windows.Shell.calc"
        processorArchitecture="x86"
        version="5.1.0.0"
        type="win32"/>
    <description>Windows Shell</description>
    <dependency>

#### Sections

by name:

    # pedump calc.exe --extract section:.text | hexdump -C | head -4

    00000000  0b aa cb 77 f7 c4 cc 77  a4 c4 cc 77 c4 c4 cc 77  |...w...w...w...w|
    00000010  3e d7 ca 77 ec b4 cb 77  69 9c f0 77 dc c4 cc 77  |>..w...wi..w...w|
    00000020  12 9c cb 77 4d af cb 77  b4 c4 cc 77 6e a8 ee 77  |...wM..w...wn..w|
    00000030  14 fc f0 77 00 00 00 00  2c 92 04 76 09 62 04 76  |...w....,..v.b.v|

by RVA:

    # pedump calc.exe --extract section:rva/0x1000 | hexdump -C | head -4

    00000000  0b aa cb 77 f7 c4 cc 77  a4 c4 cc 77 c4 c4 cc 77  |...w...w...w...w|
    00000010  3e d7 ca 77 ec b4 cb 77  69 9c f0 77 dc c4 cc 77  |>..w...wi..w...w|
    00000020  12 9c cb 77 4d af cb 77  b4 c4 cc 77 6e a8 ee 77  |...wM..w...wn..w|
    00000030  14 fc f0 77 00 00 00 00  2c 92 04 76 09 62 04 76  |...w....,..v.b.v|

by RAW_PTR (file offset):

    # pedump calc.exe --extract section:raw/0x400 | hexdump -C | head -4

    00000000  0b aa cb 77 f7 c4 cc 77  a4 c4 cc 77 c4 c4 cc 77  |...w...w...w...w|
    00000010  3e d7 ca 77 ec b4 cb 77  69 9c f0 77 dc c4 cc 77  |>..w...wi..w...w|
    00000020  12 9c cb 77 4d af cb 77  b4 c4 cc 77 6e a8 ee 77  |...wM..w...wn..w|
    00000030  14 fc f0 77 00 00 00 00  2c 92 04 76 09 62 04 76  |...w....,..v.b.v|

#### Data Directory

    # pedump calc.exe --extract datadir:IMPORT | hexdump -C | head -4

    00000000  90 9f 04 00 ff ff ff ff  ff ff ff ff dc a2 04 00  |................|
    00000010  48 12 00 00 f4 a0 04 00  ff ff ff ff ff ff ff ff  |H...............|
    00000020  10 a5 04 00 ac 13 00 00  48 9d 04 00 ff ff ff ff  |........H.......|
    00000030  ff ff ff ff f6 a5 04 00  00 10 00 00 5c 9f 04 00  |............\...|

License
-------
Released under the MIT License.  See the [LICENSE](https://github.com/zed-0xff/pedump/blob/master/LICENSE.txt) file for further details.
