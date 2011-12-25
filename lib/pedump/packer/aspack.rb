#!/usr/bin/env ruby
# coding: binary
require 'pedump'
require 'pedump/packer'
require 'zlib' # for crc32

class PEdump::Packer::ASPack
  attr_accessor :pedump

  DATA_ROOT = File.dirname(File.dirname(File.dirname(File.dirname(__FILE__))))
  UNLZX     = File.join(DATA_ROOT, "misc", "aspack", "aspack_unlzx")

  # thanks to Dr.Golova for ASPack Unpacker v1.00

  ASPACK_INFO = Struct.new(
    :Crc1Ofs,                      # crc1 offset
    :Crc1Len,                      # crc1 length
    :Crc1Val,                      # crc1 value
    :Crc2Ofs,                      #   crc2 offset
    :Crc2Len,                      #   crc2 length
    :Crc2Val,                      #   crc2 value
    :version,                      # ASPack version name
    :ObjTbl,                       # object table offset
    :FlgE8E9,                      # e8/e9 filter flag offset
    :ModE8E9,                      # e8/e9 filter mode offset
    :CmpE8E9,                      # e8/e9 filter mark offset
    :RelTbl,                       # offset of relocation table rva
    :ImpTbl,                       # offset of import table rva
    :OepOfs                        # offset of entry point rva
  )

  AspInfos = [
    ASPACK_INFO.new(
      0x39e,                   # crc1 offset
      0x21,                    # crc1 length
      0x98604df5,              # crc1 value
      0x9d,                    #   crc2 offset
      0x62,                    #   crc2 length
      0xa82446ae,              #   crc2 value
      "v2.12",                 # name of this version
      0x57b,                   # object table offset
      0xfe,                    # e8/e9 filter flag offset
      0x144,                   # e8/e9 filter mode offset
      0x147,                   # e8/e9 filter mark offset
      0x54b,                   # offset of relocation table rva
      0x278,                   # offset of import table rva
      0x39a                    # offset of entry point rva
    )
  ]

# 0x442a4e = ep       = 0x4150d2
# 0x4429ac = e8_flag

#    004151CE 8B 9D ?? ?? ?? ??           mov     ebx, [ebp+442A3Eh]
#    004151D4 0B DB                       or      ebx, ebx
#    004151D6 74 0A                       jz      short crc2_start
#    004151D8 8B 03                       mov     eax, [ebx]
#    004151DA 87 85 ?? ?? ?? ??           xchg    eax, [ebp+442A42h]
#    004151E0 89 03                       mov     [ebx], eax
#
#    004151E2 8D B5 ?? ?? ?? ??           lea     esi, [ebp+442A5Ah]
#    004151E8 83 3E 00                    cmp     dword ptr [esi], 0
#    004151EB 0F 84 1F 01 00 00           jz      loc_415310
#    004151F1 8D B5 ?? ?? ?? ??           lea     esi, [ebp+442A5Ah]
#    004151F7 6A 04                       push    4
#    004151F9 68 00 10 00 00              push    1000h
#    004151FE 68 00 18 00 00              push    1800h
#    00415203 6A 00                       push    0
#    00415205 FF 95 ?? ?? ?? ??           call    dword ptr [ebp+4429B9h]
#    0041520B 89 85 ?? ?? ?? ??           mov     [ebp+4429B5h], eax
#
#    00415211 8B 46 04                    mov     eax, [esi+4]
#    00415214 05 0E 01 00 00              add     eax, 10Eh
#    00415219 6A 04                       push    4
#    0041521B 68 00 10 00 00              push    1000h
#    00415220 50                          push    eax
#    00415221 6A 00                       push    0
#    00415223 FF 95 ?? ?? ?? ??           call    dword ptr [ebp+4429B9h]
#    00415229 89 85 ?? ?? ?? ??           mov     [ebp+4429B1h], eax
#    0041522F 56                          push    esi
#    00415230 8B 1E                       mov     ebx, [esi]
#    00415232 03 9D ?? ?? ?? ??           add     ebx, [ebp+4437E0h]
#    00415238 FF B5 ?? ?? ?? ??           push    dword ptr [ebp+4429B5h]
#    0041523E FF 76 04                    push    dword ptr [esi+4]
#    00415241 50                          push    eax
#    00415242 53                          push    ebx
#    00415243 E8 3B 03 00 00              call    sub_415583
#    00415248 80 BD ?? ?? ?? ?? 00        cmp     byte ptr [ebp+4429ACh], 0
  RE = /
    \x8B\x9D....\x0B\xDB\x74\x0A\x8B\x03\x87\x85....\x89\x03\x8D\xB5....\x83
    \x3E\x00\x0F\x84\x1F\x01\x00\x00\x8D\xB5....\x6A\x04\x68\x00\x10\x00\x00
    \x68\x00\x18\x00\x00\x6A\x00\xFF\x95....\x89\x85....\x8B\x46\x04\x05\x0E
    \x01\x00\x00\x6A\x04\x68\x00\x10\x00\x00\x50\x6A\x00\xFF\x95....\x89\x85
    ....\x56\x8B\x1E\x03\x9D....\xFF\xB5....\xFF\x76\x04\x50\x53\xE8\x3B\x03
    \x00\x00\x80\xBD....\x00/mx

  ASP_OBJ = PEdump.create_struct 'V2', :va, :size

  EP_CODE_SIZE = 0x10000

  def initialize fname
    @pedump = PEdump.new(fname)
    File.open(fname,"rb") do |f|
      @pe = @pedump.pe(f)
      @pedump.sections(f) # scan sections for va2file

      @ep = @pe.ioh.AddressOfEntryPoint
      @uMaxOfs = @pe.ioh.SizeOfImage - @ep

      ep_file_offset = @pedump.va2file(@ep)
      raise "cannot find file_offset of EntryPoint" unless ep_file_offset

      f.seek ep_file_offset
      @ep_code = f.read(EP_CODE_SIZE)
    end
  end

  # detect used ASPack version
  def find_version
    @info = _find_version
  end

  # detect used ASPack version
  def _find_version
    logger.debug "[.] uMaxOfs = #@uMaxOfs"
    AspInfos.each do |info|
      #logger.debug "[.] info = #{info.inspect}"
      next if info.Crc1Ofs >= @uMaxOfs || info.Crc1Len >= @uMaxOfs # overrun
      next if (info.Crc1Ofs + info.Crc1Len) > @uMaxOfs # overrun

      # compare first checksums
      crc = Zlib.crc32(@ep_code[info.Crc1Ofs, info.Crc1Len])
      #logger.debug "[.] crc1 = #{crc}"
      next if crc ^ info.Crc1Val != 0xffff_ffff

      # check second crc info
      next if info.Crc2Ofs >= @uMaxOfs || info.Crc2Len >= @uMaxOfs # overrun
      next if (info.Crc2Ofs + info.Crc2Len) > @uMaxOfs # overrun

      # compare second checksums
      crc = Zlib.crc32(@ep_code[info.Crc2Ofs, info.Crc2Len])
      next if crc ^ info.Crc2Val != 0xffff_ffff

      logger.info "[.] detected ASPack #{info.version}"
      return info
    end

    if pos = (@ep_code =~ RE)
      logger.info "[.] RE found at offset 0x%x" % pos
      info = ASPACK_INFO.new
      info.version = "v2.1"
      info.ObjTbl  = pos - 0xf0
      info.OepOfs  = pos - 0xfc
      info.ImpTbl  = pos - 0x100
      info.FlgE8E9 = pos - 0x19e
      info.ModE8E9 = pos + 0xc3
      info.CmpE8E9 = pos + 0xc6
      logger.info "[.] detected ASPack #{info.version}"
      return info
    end

    # try to find UNLZX table
    t = find_by_unlzx
    return t if t

    logger.fatal "[!] unknown ASPack version, or not ASPack at all!"

    # not found
    nil
  end

  def find_by_unlzx
    # LzxTblLenBase
    a = [ 0,  1,  2,  3,  4,  5,   6,   7,   8,  10,  12, 14, 16, 20, 24, 28, 32, 40, 48, 56, 64, 80, 96, 112, 128, 160, 192, 224]
    re = Regexp.new(a.map{ |x| "\\x%02x" % x}.join.force_encoding('binary'), Regexp::MULTILINE)
    if pos = (@ep_code =~ re)
      logger.info "[.] found LzxTblLenBase at 0x%x" % pos
      s = "".force_encoding('binary')
      10.times{ s << 0 } # string of 10 NULL characters
      pos -= 2 while pos > 0 && @ep_code[pos,10] != s
      if pos <= 0
        logger.error "[!] failed to find block of zeroes before LzxTblLenBase"
        return nil
      end
      pos0 = pos
      pos-=1 while pos > 0 && @ep_code[pos] == "\x00"
      if pos <= 0
        logger.error "[!] can't find nonzero bytes before zeroes"
        return nil
      end
      zeroes_start = pos+1
      pos = pos0
      pos+=1 while pos < @ep_code.size && @ep_code[pos] == "\x00"
      logger.debug "[.] found block of 0x%x zeroes starting at 0x%x" % [pos-zeroes_start, zeroes_start]
      pos = zeroes_start
      pos0 = pos

      found = false
      while pos > 0 && (pos0-pos < 0xff)
        a = @ep_code[pos,4*4].unpack('V*')
        if(
           a[0] == @pe.sections[0].VirtualAddress && a[1] <= @pe.sections[0].VirtualSize &&
           a[2] == @pe.sections[1].VirtualAddress && a[3] <= @pe.sections[0].VirtualSize
          )
          found = true
          break
        end
        pos -= 1
      end
      unless found
        logger.debug "[.] failed to find obj_tbl"
        return nil
      end
      logger.debug "[.] found possible obj_tbl at 0x%x" % pos

      info = ASPACK_INFO.new
      info.version = '?.?'
      info.ObjTbl = pos
      return info
    end
    nil
  end

  def decode_e8_e9 data
    return if @info.FlgE8E9.to_i == 0
    return if !data || data.size < 6
    flag = @ep_code[@info.FlgE8E9].ord
    if flag != 0
      logger.info "[.] FlgE8E9 = %x" % flag
      return
    end

    bCmp = @ep_code[@info.CmpE8E9].ord
    mode = @ep_code[@info.ModE8E9] == "\x00" ? 0 : 1
    logger.info "[.] CmpE8E9 = %x, ModE8E9 = %x" % [bCmp, mode]
    size = data.size - 6
    offs = 0
    while size > 0
      b0 = data[offs]
      if b0 != "\xE8" && b0 != "\xE9"
        size-=1; offs+=1
        next
      end

      dw = data[offs+1,4].unpack('V').first
      if mode == 0
        if (dw & 0xff) != bCmp
          size-=1; offs+=1
          next
        end
        # dw &= 0xffffff00; dw = ROL(dw, 24)
        dw >>= 8
      end

      t = (dw-offs) & 0xffffffff  # keep value in 32 bits
      #logger.debug "[d] data[%6x] = %8x" % [offs+1, t]
      data[offs+1,4] = [t].pack('V')
      offs += 5; size -= [size, 5].min
    end
  end

  def rebuild_imports ldr
    if @info.ImpTbl.to_i == 0
      logger.error "[!] WARNING: no imports (ImpTbl=#{@info.ImpTbl.inspect})"
      return
    end
    rva = @ep_code[@info.ImpTbl,4].unpack('V').first
    if rva == 0
      logger.warn "[?] no imports? (rva=0)"
      return
    end
    logger.info "[.] imports rva=%6x" % rva
    unless io = ldr.va2stream(rva)
      logger.error "[!] va2stream(0x%x) FAIL" % rva
      return
    end

    size = 0
    while true
      iid = PEdump::IMAGE_IMPORT_DESCRIPTOR.read(io)
      size += PEdump::IMAGE_IMPORT_DESCRIPTOR::SIZE
      break if iid.Name.to_i == 0
    end
    ldr.pe_hdr.ioh.DataDirectory[PEdump::IMAGE_DATA_DIRECTORY::IMPORT].tap do |dd|
      dd.va = rva
      dd.size = size
    end
  end

  def update_oep ldr
    if @info.OepOfs.to_i == 0
      ldr.pe_hdr.ioh.AddressOfEntryPoint = 0
      logger.error "[!] WARNING: no entry point (OepOfs=#{@info.OepOfs.inspect})"
      return
    end
    rva = @ep_code[@info.OepOfs,4].unpack('V').first
    logger.info "[.] oep=%6x" % rva
    ldr.pe_hdr.ioh.AddressOfEntryPoint = rva
  end

  def rebuild_relocs ldr
    return if @info.RelTbl.to_i == 0
    rva = @ep_code[@info.RelTbl,4].unpack('V').first
    logger.info "[.] relocs  rva=%6x" % rva

    size = 0
    if rva != 0
      unless io = ldr.va2stream(rva)
        logger.error "[!] va2stream(0x%x) FAIL" % rva
        return
      end

      until io.eof?
        a = io.read(4*2).unpack('V*')
        break if a[0] == 0 || a[1] == 0
        size += a[1]
        io.seek(a[1], IO::SEEK_CUR)
      end
    end
    rva = 0 if size == 0

    ldr.pe_hdr.ioh.DataDirectory[PEdump::IMAGE_DATA_DIRECTORY::BASERELOC].tap do |dd|
      dd.va = rva
      dd.size = size
    end
  end

  def rebuild_tls ldr
    dd = ldr.pe_hdr.ioh.DataDirectory[PEdump::IMAGE_DATA_DIRECTORY::TLS]
    return if dd.va.to_i == 0 && dd.size.to_i == 0

    tls_data = ldr[dd.va, dd.size]
    # search for original TLS data in all unpacked sections
    ldr.sections.each do |section|
      if section.data.index(tls_data) == 0
        # found a TLS section
        dd.va = section.va
        return
      end
    end
    logger.error "[!] can't find TLS section"
  end

  def obj_tbl
    @obj_tbl ||=
      begin
        r = []
        offset = @info.ObjTbl
        while true
          obj = ASP_OBJ.new(*@ep_code[offset, ASP_OBJ::SIZE].unpack(ASP_OBJ::FORMAT))
          break if obj.va == 0
          r << obj
          offset += ASP_OBJ::SIZE
        end
        if logger.level <= ::Logger::INFO
          r.each do |obj|
            logger.info "[.] Obj va=%6x  size=%6x" % [obj.va, obj.size]
          end
        end
        r
      end
  end

  def unpack data, packed_size, unpacked_size
    raise "no aspack_unlzx binary" unless File.file?(UNLZX) && File.executable?(UNLZX)
    data = IO.popen("#{UNLZX} #{packed_size.to_i} #{unpacked_size.to_i}","r+") do |f|
      f.write data
      f.close_write
      f.read
    end
    raise $?.inspect unless $?.success?
    data
  end

  def logger
    @pedump.logger
  end
end

if __FILE__ == $0
  STDOUT.sync = true
  aspack = PEdump::Packer::ASPack.new(ARGV.first)
  aspack.logger.level = ::Logger::DEBUG
  aspack.find_version
  f = File.open(ARGV.first, "rb")

  require 'pp'
  require './lib/pedump/loader'
  f.rewind
  ldr = PEdump::Loader.new(f)
  #pp ldr

  sorted_obj_tbl = aspack.obj_tbl.sort_by{ |x| aspack.pedump.va2file(x.va) }
  sorted_obj_tbl.each_with_index do |obj,idx|
    file_offset = aspack.pedump.va2file(obj.va)
    f.seek file_offset
    packed_size =
      if idx == sorted_obj_tbl.size - 1
        # last obj
        obj.size
      else
        # subtract this file_offset from next object file_offset
        aspack.pedump.va2file(sorted_obj_tbl[idx+1].va) - file_offset
      end
    pdata = f.read(packed_size)
    aspack.logger.debug "[.] va:%7x : %7x -> %7x" % [obj.va, pdata.size, obj.size]
    #fname = "%06x-%06x.bin" % [obj.va, obj.size]
    unpacked_data = aspack.unpack(pdata, pdata.size, obj.size).force_encoding('binary')
    aspack.decode_e8_e9 unpacked_data
    ldr[obj.va, unpacked_data.size] = unpacked_data
  end
  aspack.rebuild_imports ldr
  aspack.rebuild_relocs ldr
  aspack.rebuild_tls ldr
  aspack.update_oep ldr
  #pp ldr.sections
  File.open(ARGV[1] || 'unpacked.exe','wb') do |f|
    ldr.dump(f)
  end
end
