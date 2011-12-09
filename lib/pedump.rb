#!/usr/bin/env ruby
require 'logger'

# pedump.rb by zed_0xff
#
#   http://zed.0xff.me
#   http://github.com/zed-0xff

class String
  def xor x
    if x.is_a?(String)
      r = ''
      j = 0
      0.upto(self.size-1) do |i|
        r << (self[i].ord^x[j].ord).chr
        j+=1
        j=0 if j>= x.size
      end
      r
    else
      r = ''
      0.upto(self.size-1) do |i|
        r << (self[i].ord^x).chr
      end
      r
    end
  end
end

class File
  def checked_seek newpos
    @file_range ||= (0..size)
    @file_range.include?(newpos) && (seek(newpos) || true)
  end
end

class PEdump
  attr_accessor :fname, :logger, :force

  def initialize fname, params = {}
    @fname = fname
    @force = params[:force]
    @logger = @@logger = params[:logger] || PEdump::Logger.new(STDERR)
  end

  class Logger < ::Logger
    def initialize *args
      super
      @formatter = proc do |severity,_,_,msg|
        # quick and dirty way to remove duplicate messages
        if @prevmsg == msg && severity != 'DEBUG' && severity != 'INFO'
          ''
        else
          @prevmsg = msg
          "#{msg}\n"
        end
      end
      @level = Logger::WARN
    end
  end

  class << self
    def logger;    @@logger;   end
    def logger= l; @@logger=l; end

    def create_struct fmt, *args
      size = fmt.scan(/([a-z])(\d*)/i).map do |f,len|
        [len.to_i, 1].max *
          case f
          when /[aAC]/ then 1
          when 'v' then 2
          when 'V' then 4
          when 'Q' then 8
          else raise "unknown fmt #{f.inspect}"
          end
      end.inject(&:+)

      Struct.new( *args ).tap do |x|
        x.const_set 'FORMAT', fmt
        x.const_set 'SIZE',  size
        x.class_eval do
          def pack
            to_a.pack self.class.const_get('FORMAT')
          end
          def empty?
            to_a.all?{ |t| t == 0 || t.nil? || t.to_s.tr("\x00","").empty? }
          end
        end
        def x.read file, size = nil
          size ||= const_get 'SIZE'
          data = file.read(size).to_s
          if data.size < size && PEdump.logger
            PEdump.logger.error "[!] #{self.to_s} want #{size} bytes, got #{data.size}"
          end
          new(*data.unpack(const_get('FORMAT')))
        end
      end
    end
  end


  # http://www.delorie.com/djgpp/doc/exe/
  MZ = create_struct( "a2v13Qv2V6",
    :signature,
    :bytes_in_last_block,
    :blocks_in_file,
    :num_relocs,
    :header_paragraphs,
    :min_extra_paragraphs,
    :max_extra_paragraphs,
    :ss,
    :sp,
    :checksum,
    :ip,
    :cs,
    :reloc_table_offset,
    :overlay_number,
    :reserved0,           #  8 reserved bytes
    :oem_id,
    :oem_info,
    :reserved2,           # 20 reserved bytes
    :reserved3,
    :reserved4,
    :reserved5,
    :reserved6,
    :lfanew
  )

  PE = Struct.new(
    :signature,            # "PE\x00\x00"
    :image_file_header,
    :image_optional_header,
    :section_table
  )
  class PE; alias :ifh :image_file_header; end
  class PE; alias :ioh :image_optional_header; end

  # http://msdn.microsoft.com/en-us/library/ms809762.aspx
  IMAGE_FILE_HEADER = create_struct( 'v2V3v2',
    :Machine,              # w
    :NumberOfSections,     # w
    :TimeDateStamp,        # dw
    :PointerToSymbolTable, # dw
    :NumberOfSymbols,      # dw
    :SizeOfOptionalHeader, # w
    :Characteristics       # w
  )
  class IMAGE_FILE_HEADER
    def initialize *args
      super
      self.TimeDateStamp = Time.at(self.TimeDateStamp)
    end
    def method_missing mname
      mname = mname.to_s.capitalize
      self.send(mname) if self.respond_to?(mname)
    end
  end

  # http://msdn.microsoft.com/en-us/library/ms809762.aspx
  IMAGE_OPTIONAL_HEADER = create_struct( 'vC2V9v6V4v2V6',
    :Magic, # w
    :MajorLinkerVersion, :MinorLinkerVersion, # 2b
    :SizeOfCode, :SizeOfInitializedData, :SizeOfUninitializedData, :AddressOfEntryPoint, # 9dw
    :BaseOfCode, :BaseOfData, :ImageBase, :SectionAlignment, :FileAlignment,
    :MajorOperatingSystemVersion, :MinorOperatingSystemVersion, # 6w
    :MajorImageVersion, :MinorImageVersion, :MajorSubsystemVersion, :MinorSubsystemVersion,
    :Reserved1, :SizeOfImage, :SizeOfHeaders, :CheckSum, # 4dw
    :Subsystem, :DllCharacteristics, # 2w
    :SizeOfStackReserve, :SizeOfStackCommit, :SizeOfHeapReserve, :SizeOfHeapCommit, # 6dw
    :LoaderFlags, :NumberOfRvaAndSizes,
    :DataDirectory # readed manually
  )

  # http://msdn.microsoft.com/en-us/library/windows/desktop/ms680339(v=VS.85).aspx)
  IMAGE_OPTIONAL_HEADER64 = create_struct( 'vC2V5QV2v6V4v2Q4V2',
    :Magic, # w
    :MajorLinkerVersion, :MinorLinkerVersion, # 2b
    :SizeOfCode, :SizeOfInitializedData, :SizeOfUninitializedData, :AddressOfEntryPoint, :BaseOfCode, # 5dw
    :ImageBase, # qw
    :SectionAlignment, :FileAlignment, # 2dw
    :MajorOperatingSystemVersion, :MinorOperatingSystemVersion, # 6w
    :MajorImageVersion, :MinorImageVersion, :MajorSubsystemVersion, :MinorSubsystemVersion,
    :Reserved1, :SizeOfImage, :SizeOfHeaders, :CheckSum, # 4dw
    :Subsystem, :DllCharacteristics, # 2w
    :SizeOfStackReserve, :SizeOfStackCommit, :SizeOfHeapReserve, :SizeOfHeapCommit, # 4qw
    :LoaderFlags, :NumberOfRvaAndSizes, #2dw
    :DataDirectory # readed manually
  )

  class IMAGE_OPTIONAL_HEADER
    def self.read file, size = SIZE
      usual_size = 224
      PEdump.logger.warn "[?] unusual size of IMAGE_OPTIONAL_HEADER = #{size} (must be #{usual_size})" if size != usual_size
      new(*file.read([size,SIZE].min).to_s.unpack(FORMAT)).tap do |ioh|
        ioh.DataDirectory = []

        # check if "...this address is outside the memory mapped file and is zeroed by the OS"
        # see http://www.phreedom.org/solar/code/tinype/, section "Removing the data directories"
        ioh.each_pair{ |k,v| ioh[k] = 0 if v.nil? }

        # http://opcode0x90.wordpress.com/2007/04/22/windows-loader-does-it-differently/
        # maximum of 0x10 entries, even if bigger
        [0x10,ioh.NumberOfRvaAndSizes].min.times do |idx|
          ioh.DataDirectory << IMAGE_DATA_DIRECTORY.read(file)
          ioh.DataDirectory.last.type = IMAGE_DATA_DIRECTORY::TYPES[idx]
        end
        #ioh.DataDirectory.pop while ioh.DataDirectory.last.empty?
      end
    end
  end

  class IMAGE_OPTIONAL_HEADER64
    def self.read file, size = SIZE
      usual_size = 240
      PEdump.logger.warn "[?] unusual size of IMAGE_OPTIONAL_HEADER = #{size} (must be #{usual_size})" if size != usual_size
      new(*file.read([size,SIZE].min).unpack(FORMAT)).tap do |ioh|
        ioh.DataDirectory = []

        # check if "...this address is outside the memory mapped file and is zeroed by the OS"
        # see http://www.phreedom.org/solar/code/tinype/, section "Removing the data directories"
        ioh.each_pair{ |k,v| ioh[k] = 0 if v.nil? }

        # http://opcode0x90.wordpress.com/2007/04/22/windows-loader-does-it-differently/
        # maximum of 0x10 entries, even if bigger
        [0x10,ioh.NumberOfRvaAndSizes].min.times do |idx|
          ioh.DataDirectory << IMAGE_DATA_DIRECTORY.read(file)
          ioh.DataDirectory.last.type = IMAGE_DATA_DIRECTORY::TYPES[idx]
        end
        #ioh.DataDirectory.pop while ioh.DataDirectory.last.empty?
      end
    end
  end

  IMAGE_DATA_DIRECTORY = create_struct( "VV", :va, :size, :type )
  IMAGE_DATA_DIRECTORY::TYPES =
    %w'EXPORT IMPORT RESOURCE EXCEPTION SECURITY BASERELOC DEBUG ARCHITECTURE GLOBALPTR TLS LOAD_CONFIG
    Bound_IAT IAT Delay_IAT CLR_Header'
  IMAGE_DATA_DIRECTORY::TYPES.each_with_index do |type,idx|
    IMAGE_DATA_DIRECTORY.const_set(type,idx)
  end

  IMAGE_SECTION_HEADER = create_struct( 'A8V6v2V',
    :Name, # A8 6dw
    :VirtualSize, :VirtualAddress, :SizeOfRawData, :PointerToRawData, :PointerToRelocations, :PointerToLinenumbers,
    :NumberOfRelocations, :NumberOfLinenumbers, # 2w
    :Characteristics # dw
  )
  class IMAGE_SECTION_HEADER
    alias :flags :Characteristics
    def flags_desc
      r = ''
      f = self.flags.to_i
      r << (f & 0x4000_0000 > 0 ? 'R' : '-')
      r << (f & 0x8000_0000 > 0 ? 'W' : '-')
      r << (f & 0x2000_0000 > 0 ? 'X' : '-')
      r << ' CODE'        if f & 0x20 > 0

      # section contains initialized data. Almost all sections except executable and the .bss section have this flag set
      r << ' IDATA'       if f & 0x40 > 0

      # section contains uninitialized data (for example, the .bss section)
      r << ' UDATA'       if f & 0x80 > 0

      r << ' DISCARDABLE' if f & 0x02000000 > 0
      r << ' SHARED'      if f & 0x10000000 > 0
      r
    end
  end

  # http://msdn.microsoft.com/en-us/library/windows/desktop/ms680339(v=VS.85).aspx
  IMAGE_SUBSYSTEMS = %w'UNKNOWN NATIVE WINDOWS_GUI WINDOWS_CUI' + [nil,'OS2_CUI',nil,'POSIX_CUI',nil] +
    %w'WINDOWS_CE_GUI EFI_APPLICATION EFI_BOOT_SERVICE_DRIVER EFI_RUNTIME_DRIVER EFI_ROM XBOX' +
    [nil, 'WINDOWS_BOOT_APPLICATION']

  # http://ntcore.com/files/richsign.htm
  class RichHdr < String
    attr_accessor :offset, :key # xor key

    class Entry < Struct.new(:version,:id,:times)
      def inspect
        "<id=#{id}, version=#{version}, times=#{times}>"
      end
    end

    def self.from_dos_stub stub
      key = stub[stub.index('Rich')+4,4]
      start_idx = stub.index(key.xor('DanS'))
      end_idx   = stub.index('Rich')+8
      if stub[end_idx..-1].tr("\x00",'') != ''
        t = stub[end_idx..-1]
        t = "#{t[0,0x100]}..." if t.size > 0x100
        PEdump.logger.error "[!] non-zero dos stub after rich_hdr: #{t.inspect}"
        return nil
      end
      RichHdr.new(stub[start_idx, end_idx-start_idx]).tap do |x|
        x.key = key
        x.offset = stub.offset + start_idx
      end
    end

    def dexor
      self[4..-9].sub(/\A(#{Regexp::escape(key)})+/,'').xor(key)
    end

    def decode
      x = dexor
      raise "dexored size must be a multiple of 8" unless x.size%8 == 0
      x.unpack('vvV'*(x.size/8)).each_slice(3).map{ |slice| Entry.new(*slice)}
    end
  end

  class DOSStub < String
    attr_accessor :offset
  end

  def logger= l
    @logger = @@logger = l
  end

  def self.dump fname
    new(fname).dump
  end

  def mz f=nil
    @mz ||= f && MZ.read(f).tap do |mz|
      if mz.signature != 'MZ' && mz.signature != 'ZM'
        if @force
          logger.warn  "[?] no MZ signature. want: 'MZ' or 'ZM', got: #{mz.signature.inspect}"
        else
          logger.error "[!] no MZ signature. want: 'MZ' or 'ZM', got: #{mz.signature.inspect}. (not forced)"
          return nil
        end
      end
    end
  end

  def dos_stub f=nil
    @dos_stub ||=
      begin
        return nil unless mz = mz(f)
        dos_stub_offset = mz.header_paragraphs.to_i * 0x10
        dos_stub_size   = mz.lfanew.to_i - dos_stub_offset
        if dos_stub_offset <= 0
          logger.warn "[?] invalid DOS stub offset #{dos_stub_offset}"
          nil
        elsif dos_stub_offset > f.size
          logger.warn "[?] DOS stub offset beyond EOF: #{dos_stub_offset}"
          nil
        elsif dos_stub_size < 0
          logger.warn "[?] invalid DOS stub size #{dos_stub_size}"
          nil
        elsif dos_stub_size == 0
          # no DOS stub, it's ok
          nil
        else
          if dos_stub_size > 0x1000
            logger.warn "[?] DOS stub size too big (#{dos_stub_size}), limiting to 0x1000"
            dos_stub_size = 0x1000
          end
          f.seek dos_stub_offset
          DOSStub.new(f.read(dos_stub_size)).tap do |dos_stub|
            dos_stub.offset = dos_stub_offset
            if dos_stub['Rich']
              if @rich_hdr = RichHdr.from_dos_stub(dos_stub)
                dos_stub[dos_stub.index(@rich_hdr)..-1] = ''
              end
            end
          end
        end
      end
  end

  def rich_hdr f=nil
    dos_stub(f) && @rich_hdr
  end
  alias :rich_header :rich_hdr
  alias :rich        :rich_hdr

  def pe f=nil
    @pe ||=
      begin
        pe_offset = mz(f) && mz(f).lfanew
        if pe_offset.nil?
          logger.fatal "[!] NULL PE offset (e_lfanew). cannot continue."
          nil
        elsif pe_offset > f.size
          logger.fatal "[!] PE offset beyond EOF. cannot continue."
          nil
        else
          f.seek pe_offset
          pe_sig = f.read 4
          logger.error "[!] 'NE' format is not supported!" if pe_sig == "NE\x00\x00"
          if pe_sig != "PE\x00\x00"
            if @force
              logger.warn  "[?] no PE signature (want: 'PE\\x00\\x00', got: #{pe_sig.inspect})"
            else
              logger.error "[?] no PE signature (want: 'PE\\x00\\x00', got: #{pe_sig.inspect}). (not forced)"
              return nil
            end
          end
          PE.new(pe_sig).tap do |pe|
            pe.image_file_header = IMAGE_FILE_HEADER.read(f)
            if pe.ifh.SizeOfOptionalHeader > 0
              if pe.ifh.Machine == 0x8664
                pe.image_optional_header = IMAGE_OPTIONAL_HEADER64.read(f, pe.ifh.SizeOfOptionalHeader)
              else
                pe.image_optional_header = IMAGE_OPTIONAL_HEADER.read(f, pe.ifh.SizeOfOptionalHeader)
              end
            end

            if (nToRead=pe.ifh.NumberOfSections) > 32
              if @force.is_a?(Numeric) && @force > 1
                logger.warn "[!] too many sections (#{pe.ifh.NumberOfSections}). forced. reading all"
              else
                logger.warn "[!] too many sections (#{pe.ifh.NumberOfSections}). not forced, reading first 32"
                nToRead = 32
              end
            end
            pe.section_table = nToRead.times.map do
              IMAGE_SECTION_HEADER.read(f)
            end
          end
        end
      end
  end

  def resource_directory f=nil
    @resource_directory ||= _read_resource_directory_tree(f)
  end

  # OPTIONAL: assigns @mz, @rich_hdr, @pe, etc
  def dump f=nil
    f ? _dump_handle(f) : File.open(@fname){ |f| _dump_handle(f) }
    self
  end

  def _dump_handle h
    rich_hdr(h)  # includes mz(h)
    resources(h) # includes pe(h)
  end

  def data_directory f=nil
    pe(f) && pe.ioh && pe.ioh.DataDirectory
  end

  def sections f=nil
    pe(f) && pe.section_table
  end
  alias :section_table :sections

  IMAGE_RESOURCE_DIRECTORY = create_struct 'V2v4',
    :Characteristics, :TimeDateStamp, # 2dw
    :MajorVersion, :MinorVersion, :NumberOfNamedEntries, :NumberOfIdEntries, # 4w
    :entries # manual
  class IMAGE_RESOURCE_DIRECTORY
    class << self
      attr_accessor :base
      alias :read_without_children :read
      def read f, root=true
        if root
          @@loopchk1 = Hash.new(0)
          @@loopchk2 = Hash.new(0)
          @@loopchk3 = Hash.new(0)
        elsif (@@loopchk1[f.tell] += 1) > 1
          PEdump.logger.error "[!] #{self}: loop1 detected at file pos #{f.tell}" if @@loopchk1[f.tell] < 2
          return nil
        end
        read_without_children(f).tap do |r|
          nToRead = r.NumberOfNamedEntries.to_i + r.NumberOfIdEntries.to_i
          r.entries = []
          nToRead.times do |i|
            if f.eof?
              PEdump.logger.error "[!] #{self}: #{nToRead} entries in directory, but got EOF on #{i}-th."
              break
            end
            if (@@loopchk2[f.tell] += 1) > 1
              PEdump.logger.error "[!] #{self}: loop2 detected at file pos #{f.tell}" if @@loopchk2[f.tell] < 2
              next
            end
            r.entries << IMAGE_RESOURCE_DIRECTORY_ENTRY.read(f)
          end
          #r.entries.uniq!
          r.entries.each do |entry|
            entry.name =
              if entry.Name.to_i & 0x8000_0000 > 0
                # Name is an address of unicode string
                f.seek base + entry.Name & 0x7fff_ffff
                nChars = f.read(2).to_s.unpack("v").first.to_i
                begin
                  f.read(nChars*2).force_encoding('UTF-16LE').encode!('UTF-8')
                rescue
                  PEdump.logger.error "[!] #{self} failed to read entry name: #{$!}"
                  "???"
                end
              else
                # Name is a numeric id
                "##{entry.Name}"
              end
            if entry.OffsetToData && f.checked_seek(base + entry.OffsetToData & 0x7fff_ffff)
              if (@@loopchk3[f.tell] += 1) > 1
                PEdump.logger.error "[!] #{self}: loop3 detected at file pos #{f.tell}" if @@loopchk3[f.tell] < 2
                next
              end
              entry.data =
                if entry.OffsetToData & 0x8000_0000 > 0
                  # child is a directory
                  IMAGE_RESOURCE_DIRECTORY.read(f,false)
                else
                  # child is a resource
                  IMAGE_RESOURCE_DATA_ENTRY.read(f)
                end
            end
          end
          @@loopchk1 = @@loopchk2 = @@loopchk3 = nil if root # save some memory
        end
      end
    end
  end

  IMAGE_RESOURCE_DIRECTORY_ENTRY = create_struct 'V2',
    :Name, :OffsetToData,
    :name, :data

  IMAGE_RESOURCE_DATA_ENTRY = create_struct 'V4',
    :OffsetToData, :Size, :CodePage, :Reserved

  def va2file va
    sections.each do |s|
      if (s.VirtualAddress..(s.VirtualAddress+s.VirtualSize)).include?(va)
        return va - s.VirtualAddress + s.PointerToRawData
      end
    end
    nil
  end

  def _read_resource_directory_tree f
    return nil unless pe(f) && pe(f).ioh && f
    res_dir = @pe.ioh.DataDirectory[IMAGE_DATA_DIRECTORY::RESOURCE]
    return [] if !res_dir || (res_dir.va == 0 && res_dir.size == 0)
    res_va = @pe.ioh.DataDirectory[IMAGE_DATA_DIRECTORY::RESOURCE].va
    res_section = @pe.section_table.find{ |t| t.VirtualAddress == res_va }
    unless res_section
      logger.warn "[?] can't find resource section for va=0x#{res_va.to_s(16)}"
      return []
    end
    f.seek res_section.PointerToRawData
    IMAGE_RESOURCE_DIRECTORY.base = res_section.PointerToRawData
    @resource_data_base = res_section.PointerToRawData - res_section.VirtualAddress
    IMAGE_RESOURCE_DIRECTORY.read(f)
  end

  class Resource < Struct.new(:type, :name, :id, :lang, :file_offset, :size, :cp, :reserved, :data)
    def bitmap_hdr
      bmp_info_hdr = data.find{ |x| x.is_a?(BITMAPINFOHEADER) }
      raise "no BITMAPINFOHEADER for #{self.type} #{self.name}" unless bmp_info_hdr

      bmp_info_hdr.biHeight/=2 if %w'ICON CURSOR'.include?(type)

      colors_used = bmp_info_hdr.biClrUsed
      colors_used = 2**bmp_info_hdr.biBitCount if colors_used == 0 && bmp_info_hdr.biBitCount < 16

      # XXX: one byte in each color is unused!
      @palette_size = colors_used * 4 # each color takes 4 bytes

      # scanlines are DWORD-aligned and padded to DWORD-align with zeroes
      # XXX: some data may be hidden in padding bytes!
      scanline_size = bmp_info_hdr.biWidth * bmp_info_hdr.biBitCount / 8
      scanline_size += (4-scanline_size%4) if scanline_size % 4 > 0

      @imgdata_size = scanline_size * bmp_info_hdr.biHeight
      "BM" + [
        BITMAPINFOHEADER::SIZE + 14 + @palette_size + @imgdata_size,
        0,
        BITMAPINFOHEADER::SIZE + 14 + @palette_size
      ].pack("V3") + bmp_info_hdr.pack
    ensure
      bmp_info_hdr.biHeight*=2 if %w'ICON CURSOR'.include?(type)
    end

    # only valid for types BITMAP, ICON & CURSOR
    def restore_bitmap src_fname
      File.open(src_fname, "rb") do |f|
        parse f
        if data.first == "PNG"
          "\x89PNG" +f.read(self.size-4)
        else
          bitmap_hdr + f.read(@palette_size + @imgdata_size)
        end
      end
    end

    def bitmap_mask src_fname
      File.open(src_fname, "rb") do |f|
        parse f
        bmp_info_hdr = bitmap_hdr
        bitmap_size = BITMAPINFOHEADER::SIZE + @palette_size + @imgdata_size
        return nil if bitmap_size >= self.size

        mask_size = self.size - bitmap_size
        f.seek file_offset + bitmap_size

        bmp_info_hdr = BITMAPINFOHEADER.new(*bmp_info_hdr[14..-1].unpack(BITMAPINFOHEADER::FORMAT))
        bmp_info_hdr.biBitCount = 1
        bmp_info_hdr.biCompression = bmp_info_hdr.biSizeImage = 0
        bmp_info_hdr.biClrUsed = bmp_info_hdr.biClrImportant = 2

        palette = [0,0xffffff].pack('V2')
        @palette_size = palette.size

        "BM" + [
          BITMAPINFOHEADER::SIZE + 14 + @palette_size + mask_size,
          0,
          BITMAPINFOHEADER::SIZE + 14 + @palette_size
        ].pack("V3") + bmp_info_hdr.pack + palette + f.read(mask_size)
      end
    end

    # also sets the file position for restore_bitmap next call
    def parse f
      raise "called parse with type not set" unless self.type
      #return if self.data

      self.data = []
      case type
      when 'BITMAP','ICON'
        f.seek file_offset
        if f.read(4) == "\x89PNG"
          data << 'PNG'
        else
          f.seek file_offset
          data << BITMAPINFOHEADER.read(f)
        end
      when 'CURSOR'
        f.seek file_offset
        data << CURSOR_HOTSPOT.read(f)
        data << BITMAPINFOHEADER.read(f)
      when 'GROUP_CURSOR'
        f.seek file_offset
        data << CUR_ICO_HEADER.read(f)
        data.last.wNumImages.times do
          data << CURDIRENTRY.read(f)
        end
      when 'GROUP_ICON'
        f.seek file_offset
        data << CUR_ICO_HEADER.read(f)
        data.last.wNumImages.times do
          data << ICODIRENTRY.read(f)
        end
      when 'STRING'
        f.seek file_offset
        16.times do
          nChars = f.read(2).unpack('v').first
          data << f.read(nChars*2).force_encoding('UTF-16LE').encode!('UTF-8')
        end
        # XXX: check if readed strings summary length is less than resource data length
      end
    end
  end

  STRING = Struct.new(:id, :lang, :value)

  def strings f=nil
    r = []
    Array(resources(f)).find_all{ |x| x.type == 'STRING'}.each do |res|
      res.data.each_with_index do |string,idx|
        r << STRING.new( ((res.id-1)<<4) + idx, res.lang, string ) unless string.empty?
      end
    end
    r
  end

  # see also http://www.informit.com/articles/article.aspx?p=1186882 about icons format

  BITMAPINFOHEADER = create_struct 'V3v2V6',
    :biSize,          # BITMAPINFOHEADER::SIZE
    :biWidth,
    :biHeight,
    :biPlanes,
    :biBitCount,
    :biCompression,
    :biSizeImage,
    :biXPelsPerMeter,
    :biYPelsPerMeter,
    :biClrUsed,
    :biClrImportant

  # http://www.devsource.com/c/a/Architecture/Resources-From-PE-I/2/
  CUR_ICO_HEADER = create_struct('v3',
    :wReserved, # always 0
    :wResID,    # always 2
    :wNumImages # Number of cursor images/directory entries
  )

  CURDIRENTRY = create_struct 'v4Vv',
    :wWidth,
    :wHeight, # Divide by 2 to get the actual height.
    :wPlanes,
    :wBitCount,
    :dwBytesInImage,
    :wID

  CURSOR_HOTSPOT = create_struct 'v2', :x, :y

  ICODIRENTRY = create_struct 'C4v2Vv',
    :bWidth,
    :bHeight,
    :bColors,
    :bReserved,
    :wPlanes,
    :wBitCount,
    :dwBytesInImage,
    :wID

  ROOT_RES_NAMES = [nil] + # numeration is started from 1
    %w'CURSOR BITMAP ICON MENU DIALOG STRING FONTDIR FONT ACCELERATORS RCDATA' +
    %w'MESSAGETABLE GROUP_CURSOR' + [nil] + %w'GROUP_ICON' + [nil] +
    %w'VERSION DLGINCLUDE' + [nil] + %w'PLUGPLAY VXD ANICURSOR ANIICON HTML MANIFEST'

  def resources f=nil
    @resources ||= _scan_resources(f)
  end

  def _scan_resources f=nil, dir=nil
    dir ||= resource_directory(f)
    return nil unless dir
    dir.entries.map do |entry|
      case entry.data
        when IMAGE_RESOURCE_DIRECTORY
          if dir == @resource_directory # root resource directory
            entry_type =
              if entry.Name & 0x8000_0000 == 0
                # root resource directory & entry name is a number
                ROOT_RES_NAMES[entry.Name] || entry.name
              else
                entry.name
              end
            _scan_resources(f,entry.data).each do |res|
              res.type = entry_type
              res.parse f
            end
          else
            _scan_resources(f,entry.data).each do |res|
              res.name = res.name == "##{res.lang}" ? entry.name : "#{entry.name} / #{res.name}"
              res.id ||= entry.Name if entry.Name.is_a?(Numeric) && entry.Name < 0x8000_0000
            end
          end
        when IMAGE_RESOURCE_DATA_ENTRY
          Resource.new(
            nil,          # type
            entry.name,
            nil,          # id
            entry.Name,   # lang
            entry.data.OffsetToData + @resource_data_base,
            entry.data.Size,
            entry.data.CodePage,
            entry.data.Reserved
          )
        else
          logger.error "[!] invalid resource entry: #{entry.data.inspect}"
          nil
      end
    end.flatten.compact
  end
end

####################################################################################

if $0 == __FILE__
  require 'pp'
  dump = PEdump.new(ARGV.shift).dump
  if ARGV.any?
    ARGV.each do |arg|
      if dump.respond_to?(arg)
        pp dump.send(arg)
      elsif arg == 'restore_bitmaps'
        File.open(dump.fname,"rb") do |fi|
          r = dump.resources.
            find_all{ |r| %w'ICON BITMAP CURSOR'.include?(r.type) }.
            each do |r|
              fname = r.name.tr("/# ",'_')+".bmp"
              puts "[.] #{fname}"
              File.open(fname,"wb"){ |fo| fo << r.restore_bitmap(fi) }
              if mask = r.bitmap_mask(fi)
                fname.sub! '.bmp', '.mask.bmp'
                puts "[.] #{fname}"
                File.open(fname,"wb"){ |fo| fo << r.bitmap_mask(fi) }
              end
            end
        end
        exit
      else
        puts "[?] invalid arg #{arg.inspect}"
      end
    end
    exit
  end
  p dump.mz
  require './lib/hexdump_helper' if File.exist?("lib/hexdump_helper.rb")
  if defined?(HexdumpHelper)
    include HexdumpHelper
    puts hexdump(dump.dos_stub) if dump.dos_stub
    puts
    if dump.rich_hdr
      puts hexdump(dump.rich_hdr)
      puts
      p(dump.rich_hdr.decode)
      puts hexdump(dump.rich_hdr.dexor)
    end
  end
  pp dump.pe
  pp dump.resources
end
