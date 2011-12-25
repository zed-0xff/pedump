require 'pedump'
require 'stringio'
require 'pedump/loader/section'

class PEdump::Loader
  attr_accessor :mz_hdr, :dos_stub, :pe_hdr, :sections, :pedump

  # shortcuts
  alias :pe :pe_hdr
  def ep; @pe_hdr.ioh.AddressOfEntryPoint; end
  def ep= v; @pe_hdr.ioh.AddressOfEntryPoint=v; end

  ########################################################################
  # constructors
  ########################################################################

  def initialize io = nil, pedump_params = {}
    @pedump = PEdump.new(io, pedump_params)
    if io
      @mz_hdr     = @pedump.mz
      @dos_stub   = @pedump.dos_stub
      @pe_hdr     = @pedump.pe
      load_sections @pedump.sections, io
    end
  end

  def load_sections section_hdrs, f = nil
    if section_hdrs.is_a?(Array) && section_hdrs.map(&:class).uniq == [PEdump::IMAGE_SECTION_HEADER]
      @sections = section_hdrs.map{ |x| Section.new(x, :deferred_load_io => f) }
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

  ########################################################################
  # VA conversion
  ########################################################################

  def va2section va
    @sections.find{ |x| x.range.include?(va) }
  end

  def va2stream va
    return nil unless section = va2section(va)
    StringIO.new(section.data).tap do |io|
      io.seek va-section.va
    end
  end

  ########################################################################
  # virtual memory read/write
  ########################################################################

  def [] va, size
    section = va2section(va)
    raise "no section for va=0x#{va.to_s 16}" unless section
    offset = va - section.va
    raise "negative offset #{offset}" if offset < 0
    r = section.data[offset,size]
    if r.size < size
      # append some empty data
      r << ("\x00".force_encoding('binary')) * (size - r.size)
    end
    r
  end

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

  ########################################################################
  # generating PE binary
  ########################################################################

  def section_table
    @sections.map do |section|
      section.hdr.SizeOfRawData = section.data.size
      section.hdr.pack
    end.join
  end

  def dump f
    align = @pe_hdr.ioh.FileAlignment

    mz_size = @mz_hdr.pack.size
    raise "odd mz_size #{mz_size}" if mz_size % 0x10 != 0
    @mz_hdr.header_paragraphs = mz_size / 0x10              # offset of dos_stub
    @mz_hdr.lfanew = mz_size + @dos_stub.size               # offset of PE hdr
    f.write @mz_hdr.pack
    f.write @dos_stub
    f.write @pe_hdr.pack
    f.write @pe_hdr.ioh.DataDirectory.map(&:pack).join

    section_tbl_offset = f.tell # store offset for 2nd write of section table
    f.write section_table

    @sections.each do |section|
      f.seek(align - (f.tell % align), IO::SEEK_CUR) if f.tell % align != 0
      section.hdr.PointerToRawData = f.tell  # fix raw_ptr
      f.write(section.data)
    end

    eof = f.tell

    # 2nd write of section table with correct raw_ptr's
    f.seek section_tbl_offset
    f.write section_table

    f.seek eof
  end
end
