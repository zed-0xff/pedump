#!/usr/bin/env ruby
require 'pedump'
require 'pedump/packer'
require 'zlib' # for crc32

class PEdump::Packer::ASPack
  attr_accessor :pedump

  DATA_ROOT = File.dirname(File.dirname(File.dirname(File.dirname(__FILE__))))
  UNLZX     = File.join(DATA_ROOT, "misc", "aspack", "aspack_unlzx")

  # thanks to Dr.Golova for ASPack Unpacker v1.00

  ASPACK_INFO = PEdump.create_struct 'V14',
    :Crc1Ofs,                      # first checksum offset
    :Crc1Len,                      # first checksum length
    :Crc1Val,                      # first checksum value
    :Crc2Ofs,                      # second checksum offset
    :Crc2Len,                      # second checksum length
    :Crc2Val,                      # second checksum value
    :VerName,                      # name of this version
    :ObjTbl,                       # object table offset
    :FlgE8E9,                      # e8/e9 filter flag offset
    :ModE8E9,                      # e8/e9 filter mode offset
    :CmpE8E9,                      # e8/e9 filter mark offset
    :RelTbl,                       # offset of relocation table rva
    :ImpTbl,                       # offset of import table rva
    :OepOfs                        # offset of entry point rva

  AspInfos = [
    ASPACK_INFO.new(
      0x39e,                   # first checksum offset
      0x21,                    # first checksum length
      0x98604df5,              # first checksum value
      0x9d,                    # second checksum offset
      0x62,                    # second checksum length
      0xa82446ae,              # second checksum value
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
      @info = find_version
    end
  end

  # detect used ASPack version
  def find_version
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

      return info
    end

    # not found
    nil
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
  ldr = PEdump::Loader.new(aspack.pedump, f)
  pp ldr

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
    ldr[obj.va, unpacked_data.size] = unpacked_data
  end
  pp ldr
  File.open('dump','wb') do |f|
    ldr.dump(f)
  end
end
