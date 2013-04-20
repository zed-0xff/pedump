#!/usr/bin/env ruby

require 'pedump'
require 'stringio'
require 'pedump/loader/section'
require 'pedump/loader/minidump'

# This class is kinda Virtual Machine that mimics executable loading as real OS does.
# Can be used for unpacking, emulating, reversing, ...
class PEdump::Loader
  attr_accessor :mz_hdr, :dos_stub, :pe_hdr, :sections, :pedump, :image_base
  attr_accessor :find_limit

  DEFAULT_FIND_LIMIT = 2**64

  # shortcuts
  alias :pe :pe_hdr
  def ep; @pe_hdr.ioh.AddressOfEntryPoint; end
  def ep= v; @pe_hdr.ioh.AddressOfEntryPoint=v; end

  ########################################################################
  # constructors
  ########################################################################

  def initialize io = nil, params = {}
    @pedump = PEdump.new(io, params)
    if io
      @mz_hdr     = @pedump.mz
      @dos_stub   = @pedump.dos_stub
      @pe_hdr     = @pedump.pe
      @image_base = params[:image_base] || @pe_hdr.try(:ioh).try(:ImageBase) || 0
      load_sections @pedump.sections, io
    end
    @find_limit = params[:find_limit] || DEFAULT_FIND_LIMIT
  end

  def load_sections section_hdrs, f = nil
    if section_hdrs.is_a?(Array)
      @sections = section_hdrs.map do |x|
        raise "unknown section hdr: #{x.inspect}" unless x.is_a?(PEdump::IMAGE_SECTION_HEADER)
        Section.new(x, :deferred_load_io => f, :image_base => @image_base )
      end
      if f.respond_to?(:seek) && f.respond_to?(:read)
        #
        # converted to deferred loading
        #
#        section_hdrs.each_with_index do |sect_hdr, idx|
#          f.seek sect_hdr.PointerToRawData
#          @sections[idx].data = f.read(sect_hdr.SizeOfRawData)
#        end
      elsif f
        raise "invalid 2nd arg: #{f.inspect}"
      end
    else
      raise "invalid arg: #{section_hdrs.inspect}"
    end
  end

  # load MS Minidump (*.dmp) file, that can be created in Task Manager via
  # right click on process -> save memory dump
  def load_minidump io, options = {}
    @sections ||= []
    md = Minidump.new io
    options[:merge] = true unless options.key?(:merge)
    md.memory_ranges(options).each do |mr|
      hdr = PEdump::IMAGE_SECTION_HEADER.new(
        :VirtualAddress   => mr.va,
        :PointerToRawData => mr.file_offset,
        :SizeOfRawData    => mr.size,
        :VirtualSize      => mr.size            # XXX may be larger than SizeOfRawData
      )
      @sections << Section.new( hdr, :deferred_load_io => io )
    end
  end

  def self.load_minidump io
    new.tap{ |ldr| ldr.load_minidump io }
  end

  ########################################################################
  # VA conversion
  ########################################################################

  # VA to section
  def va2section va
    @sections.find{ |x| x.range.include?(va) }
  end

  # RVA (Relative VA) to section
  def rva2section rva
    va2section( rva + @image_base )
  end

  def va2stream va
    return nil unless section = va2section(va)
    StringIO.new(section.data).tap do |io|
      io.seek va-section.va
    end
  end

  def rva2stream rva
    va2stream( rva + @image_base )
  end

  ########################################################################
  # virtual memory read/write
  ########################################################################

  # read arbitrary string
  def [] va, size, params = {}
    section = va2section(va)
    raise "no section for va=0x#{va.to_s 16}" unless section
    offset = va - section.va
    raise "negative offset #{offset}" if offset < 0
    r = section.data[offset,size]
    return nil if r.nil?
    if r.size < size && params.fetch(:zerofill, true)
      # append some empty data
      r << ("\x00".force_encoding('binary')) * (size - r.size)
    end
    r
  end

  # write arbitrary string
  def []= va, size, data
    raise "data.size != size" if data.size != size
    section = va2section(va)
    raise "no section for va=0x#{va.to_s 16}" unless section
    offset = va - section.va
    raise "negative offset #{offset}" if offset < 0
    if section.data.size < offset
      # append some empty data
      section.data << ("\x00".force_encoding('binary') * (offset-section.data.size))
    end
    section.data[offset, data.size] = data
  end

  # returns StringIO with section data, pre-seeked to specified VA
  # TODO: make io cross sections
  def io va
    section = va2section(va)
    raise "no section for va=0x#{va.to_s 16}" unless section
    offset = va - section.va
    raise "negative offset #{offset}" if offset < 0
    StringIO.new(section.data).tap{ |io| io.seek offset }
  end

  # read single DWord (4 bytes) if no 'n' specified
  # delegate to #dwords otherwise
  def dw va, n=nil
    n ? dwords(va,n) : self[va,4].unpack('L')[0]
  end
  alias :dword :dw

  # read N DWords, returns array
  def dwords va, n
    self[va,4*n].unpack('L*')
  end

  # check if any section has specified VA in its range
  def valid_va? va
    @ranges ||= _merge_ranges
    @ranges.any?{ |range| range.include?(va) }
  end

  # increasing max_diff speed ups the :valid_va? method, but may cause false positives
  def _merge_ranges max_diff = nil
    max_diff ||=
      if sections.size > 100
        1024*1024
      else
        0
      end

    ranges0 = sections.map(&:range).sort_by(&:begin)
    #puts "[.] #{ranges0.size} ranges"
    ranges1 = []
    range = ranges0.shift
    while ranges0.any?
      while (ranges0.first.begin-range.end).abs <= max_diff
        range = range.begin...ranges0.shift.end
        break if ranges0.empty?
      end
      #puts "[.] diff #{ranges0.first.begin-range.end}"
      ranges1 << range
      range = ranges0.shift
    end
    ranges1 << range
    #puts "[=] #{ranges1.size} ranges"
    ranges1.uniq.compact
  end

  # find first occurence of string
  # returns VA
  def find needle, options = {}
    options[:align] ||= 1
    options[:limit] ||= @find_limit

    if needle.is_a?(Fixnum)
      # silently convert to DWORD
      needle = [needle].pack('L')
    end

    if options[:align] == 1
      # fastest find?
      processed_bytes = 0
      sections.each do |section|
        next unless section.data # skip empty sections
        pos = section.data.index(needle)
        return section.va+pos if pos
        processed_bytes += section.vsize
        return nil if processed_bytes >= options[:limit]
      end
    end
    nil
  end

  # find all occurences of string
  # returns array of VAs or empty array
  def find_all needle, options = {}
    options[:align] ||= 1
    options[:limit] ||= @find_limit

    if needle.is_a?(Fixnum)
      # silently convert to DWORD
      needle = [needle].pack('L')
    end

    r = []
    if options[:align] == 1
      # fastest find?
      processed_bytes = 0
      sections.each do |section|
        next unless section.data # skip empty sections
        section.data.scan(needle) do
          r << $~.begin(0) + section.va
        end
        processed_bytes += section.vsize
        return r if processed_bytes >= options[:limit]
      end
    end
    r
  end

  ########################################################################
  # parsing names
  ########################################################################

  def names
    return @names if @names
    @names = {}
    if oep = @pe_hdr.try(:ioh).try(:AddressOfEntryPoint)
      oep += @image_base
      @names[oep] = 'start'
    end
    _parse_imports
    _parse_exports
    #TODO: debug info
    @names
  end

  def _parse_imports
    @pedump.imports.each do |iid| # Image Import Descriptor
      va = iid.FirstThunk + @image_base
      (Array(iid.original_first_thunk) + Array(iid.first_thunk)).uniq.each do |func|
        name = func.name || "##{func.ordinal}"
        @names[va] = name
        va += 4
      end
    end
  end

  def _parse_exports
    return {} unless @pedump.exports
    @pedump.exports.functions.each do |func|
      @names[@image_base + func.va] = func.name || "##{func.ordinal}"
    end
  end

  ########################################################################
  # generating PE binary
  ########################################################################

  def section_table
    @sections.map do |section|
      section.hdr.SizeOfRawData = section.data.size
      section.hdr.PointerToRelocations ||= 0
      section.hdr.PointerToLinenumbers ||= 0
      section.hdr.NumberOfRelocations  ||= 0
      section.hdr.NumberOfLinenumbers  ||= 0
      section.hdr.Characteristics      ||= 0
      section.hdr.pack
    end.join
  end

  # save a new PE file to specified IO
  def export io
    @mz_hdr     ||= PEdump::MZ.new("MZ", *[0]*22)
    @dos_stub   ||= ''
    @pe_hdr     ||= PEdump::PE.new("PE\x00\x00")
    @pe_hdr.ioh ||=
      PEdump::IMAGE_OPTIONAL_HEADER32.read( StringIO.new("\x00" * 224) ).tap do |ioh|
        ioh.Magic               = 0x10b # 32-bit executable
        #ioh.NumberOfRvaAndSizes = 0x10
      end
    @pe_hdr.ifh ||= PEdump::IMAGE_FILE_HEADER.new(
      :Machine              => 0x14c,          # x86
      :NumberOfSections     => @sections.size,
      :TimeDateStamp        => 0,
      :PointerToSymbolTable => 0,
      :NumberOfSymbols      => 0,
      :SizeOfOptionalHeader => @pe_hdr.ioh.pack.size,
      :Characteristics      => 0x102           # EXECUTABLE_IMAGE | 32BIT_MACHINE
    )

    if @pe_hdr.ioh.FileAlignment.to_i == 0
      # default file align = 512 bytes
      @pe_hdr.ioh.FileAlignment = 0x200
    end
    if @pe_hdr.ioh.SectionAlignment.to_i == 0
      # default section align = 4k
      @pe_hdr.ioh.SectionAlignment = 0x1000
    end

    mz_size = @mz_hdr.pack.size
    raise "odd mz_size #{mz_size}" if mz_size % 0x10 != 0
    @mz_hdr.header_paragraphs = mz_size / 0x10              # offset of dos_stub
    @mz_hdr.lfanew = mz_size + @dos_stub.size               # offset of PE hdr
    io.write @mz_hdr.pack
    io.write @dos_stub
    io.write @pe_hdr.pack
    io.write @pe_hdr.ioh.DataDirectory.map(&:pack).join

    section_tbl_offset = io.tell # store offset for 2nd write of section table
    io.write section_table

    align = @pe_hdr.ioh.FileAlignment
    @sections.each do |section|
      io.seek(align - (io.tell % align), IO::SEEK_CUR) if io.tell % align != 0
      section.hdr.PointerToRawData = io.tell  # fix raw_ptr
      io.write(section.data)
    end

    eof = io.tell

    # 2nd write of section table with correct raw_ptr's
    io.seek section_tbl_offset
    io.write section_table

    io.seek eof
  end

  alias :dump :export
end

###################################################################

if $0 == __FILE__
  require 'pp'
  require 'zhexdump'

  io = open ARGV.first
  ldr = PEdump::Loader.load_minidump io

  File.open(ARGV.first + ".exe", "wb") do |f|
    ldr.sections[100..-1] = []
    ldr.export f
  end
  exit

  va = 0x3a10000+0xceb00-0x300+0x18c
  ZHexdump.dump ldr[va, 0x200], :add => va
  exit

  #puts
  #ZHexdump.dump ldr[x,0x100]

  ldr.find_all(va, :limit => 100_000_000).each do |va0|
    printf "[.] found at VA=%x\n", va0
    5.times do |i|
      puts
      va = ldr.dw(va0+i*4)
      ZHexdump.dump ldr[va,0x30], :add => va if va != 0
    end
  end

  puts "---"
  ldr.find_all(0x3dff970, :limit => 100_000_000).each do |va|
    ldr[va,0x20].hexdump
    puts
  end

end
