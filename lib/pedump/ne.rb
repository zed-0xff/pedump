class PEdump
  # from wine's winnt.h
  class NE < PEdump.create_struct 'a2CCvvVv4VVv8Vv3CCv4',
    :ne_magic,             # 00 NE signature 'NE'
    :ne_ver,               # 02 Linker version number
    :ne_rev,               # 03 Linker revision number
    :ne_enttab,            # 04 Offset to entry table relative to NE
    :ne_cbenttab,          # 06 Length of entry table in bytes
    :ne_crc,               # 08 Checksum
    :ne_flags,             # 0c Flags about segments in this file
    :ne_autodata,          # 0e Automatic data segment number
    :ne_heap,              # 10 Initial size of local heap
    :ne_stack,             # 12 Initial size of stack
    :ne_csip,              # 14 Initial CS:IP
    :ne_sssp,              # 18 Initial SS:SP
    :ne_cseg,              # 1c # of entries in segment table
    :ne_cmod,              # 1e # of entries in module reference tab.
    :ne_cbnrestab,         # 20 Length of nonresident-name table
    :ne_segtab,            # 22 Offset to segment table
    :ne_rsrctab,           # 24 Offset to resource table
    :ne_restab,            # 26 Offset to resident-name table
    :ne_modtab,            # 28 Offset to module reference table
    :ne_imptab,            # 2a Offset to imported name table
    :ne_nrestab,           # 2c Offset to nonresident-name table
    :ne_cmovent,           # 30 # of movable entry points
    :ne_align,             # 32 Logical sector alignment shift count
    :ne_cres,              # 34 # of resource segments
    :ne_exetyp,            # 36 Flags indicating target OS
    :ne_flagsothers,       # 37 Additional information flags
    :ne_pretthunks,        # 38 Offset to return thunks
    :ne_psegrefbytes,      # 3a Offset to segment ref. bytes
    :ne_swaparea,          # 3c Reserved by Microsoft
    :ne_expver             # 3e Expected Windows version number

    attr_accessor :io, :offset

    DEFAULT_CP = 1252

    def self.cp
      @@cp || DEFAULT_CP
    end

    def self.cp= cp
      @@cp = cp
    end

    def self.read io, *args
      self.cp = DEFAULT_CP
      offset = io.tell
      super.tap do |x|
        x.io, x.offset = io, offset
      end
    end

    class Segment < PEdump.create_struct 'v4',
      :offset, :size, :flags, :min_alloc_size,
      # manual:
      :file_offset
    end

    def segments io=@io
      io.seek ne_segtab+@offset
      ne_cseg.times.map do
        Segment.read(io).tap do |seg|
          seg.file_offset = seg.offset << ne_align
        end
      end
    end

    class ResourceGroup < PEdump.create_struct 'vvV',
      :type_id, :count, :reserved,
      # manual:
      :type, :children

      def self.read io
        super.tap do |g|
          if g.type_id.to_i == 0
            # type_id = 0 means end of resource groups
            return nil
          else
            # read only if type_id is non-zero,
            g.children = []
            g.count.times do
              break if io.eof?
              g.children << ResourceInfo.read(io)
            end
          end
        end
      end
    end

    class ResourceInfo < PEdump.create_struct 'v4V',
      :offset, :size, :flags, :name_offset, :reserved,
      # manual:
      :name
    end

    class Resource < PEdump::Resource
      # NE strings use 8-bit characters
      def parse f, h={}
        self.data = []
        case type
        when 'STRING'
          f.seek file_offset
          16.times do
            break if f.tell >= file_offset+self.size
            nChars = f.getc.ord
            t =
              if nChars + 1 > self.size
                # TODO: if it's not 1st string in table then truncated size must be less
                PEdump.logger.error "[!] string size(#{nChars*2}) > stringtable size(#{self.size}). truncated to #{self.size-2}"
                f.read(self.size-1)
              else
                f.read(nChars)
              end
            data <<
              begin
                t.force_encoding("CP#{h[:cp]}").encode!('UTF-8')
              rescue
                t.force_encoding('ASCII')
              end
          end
        when 'VERSION'
          f.seek file_offset
          data << PEdump::NE::VS_VERSIONINFO.read(f)
        else
          super(f)
        end
      end
    end

    def _id2string id, io, res_base
      if id & 0x8000 == 0
        # offset to name
        io.seek id + res_base
        namesize = (io.getc || 0.chr).ord
        io.read(namesize)
      else
        # numerical id
        "##{id & 0x7fff}"
      end
    end

    def resource_directory io=@io
      @resource_directory ||=
        begin
          res_base = ne_rsrctab+@offset
          io.seek res_base
          res_shift = io.read(2).unpack('v').first
          unless (0..16).include?(res_shift)
            PEdump.logger.error "[!] invalid res_shift = %d" % res_shift
            return []
          end
          PEdump.logger.info "[.] res_shift = %d" % res_shift
          r = []
          while !io.eof? && (g = ResourceGroup.read(io))
            r << g
          end
          r.each do |g|
            g.type = (g.type_id & 0x8000 != 0) && PEdump::ROOT_RES_NAMES[g.type_id & 0x7fff]
            g.type ||= _id2string( g.type_id, io, res_base)
            g.children.each do |res|
              res.name = _id2string(res.name_offset, io, res_base)
              res.offset ||= 0
              res.offset <<= res_shift
              res.size   ||= 0
              res.size   <<= res_shift
            end
          end
          r
        end
    end

    def _detect_codepage a, io=@io
      a.find_all{ |res| res.type == 'VERSION' }.each do |res|
        res.parse(io)
        res.data.each do |vi|
          if vi.respond_to?(:Children) && vi.Children.respond_to?(:each)
            # vi is PEdump::NE::VS_VERSIONINFO
            vi.Children.each do |vfi|
              if vfi.is_a?(PEdump::NE::VarFileInfo) && vfi.Children.is_a?(PEdump::NE::Var)
                var = vfi.Children
                # var is PEdump::NE::Var
                if var.respond_to?(:Value) && var.Value.is_a?(Array) && var.Value.size == 2
                  return var.Value.last
                end
              end
            end
          end
        end
      end
      nil
    end

    def resources io=@io
      a = []
      resource_directory(io).each do |grp|
        grp.children.each do |res|
          a << (r = Resource.new)
          r.id   = (res.name_offset & 0x7fff) if (res.name_offset & 0x8000) != 0
          r.type = grp.type
          r.size = res.size
          r.name = res.name
          r.file_offset = res.offset
          r.reserved = res.reserved
        end
      end

      # try to detect codepage
      cp = _detect_codepage(a, io)
      if cp
        PEdump::NE.cp = cp # XXX HACK
        PEdump.logger.info "[.] detect_codepage: #{cp.inspect}"
      else
        cp = DEFAULT_CP
        PEdump.logger.info "[.] detect_codepage failed, using default #{cp}"
      end

      a.each{ |r| r.parse(io, :cp => cp) }
      a
    end

    def imports io=@io
      io.seek @offset+ne_imptab
      p io.read(0x20)
    end
  end

  def ne f=@io
    return @ne if defined?(@ne)
    @ne ||=
      begin
        ne_offset = mz(f) && mz(f).lfanew
        if ne_offset.nil?
          logger.fatal "[!] NULL NE offset (e_lfanew)."
          nil
        elsif ne_offset > f.size
          logger.fatal "[!] NE offset beyond EOF."
          nil
        else
          f.seek ne_offset
          if f.read(2) == 'NE'
            f.seek ne_offset
            NE.read f
          else
            nil
          end
        end
      end
  end

end
