class PEdump::Loader
  class Section
    attr_accessor :hdr
    attr_writer :data

    EMPTY_DATA = ''.force_encoding('binary')

    def initialize x = nil, args = {}
      if x.is_a?(PEdump::IMAGE_SECTION_HEADER)
        @hdr = x.dup
      end
      @data = EMPTY_DATA.dup
      @deferred_load_io   = args[:deferred_load_io]
      @deferred_load_pos  = args[:deferred_load_pos]  || (@hdr && @hdr.PointerToRawData)
      @deferred_load_size = args[:deferred_load_size] || (@hdr && @hdr.SizeOfRawData)
      @image_base = args[:image_base] || 0
    end

    def name;  @hdr.Name; end
    def va  ;  @hdr.VirtualAddress + @image_base; end
    def rva ;  @hdr.VirtualAddress; end
    def vsize; @hdr.VirtualSize; end
    def flags; @hdr.Characteristics; end
    def flags= f; @hdr.Characteristics= f; end

    def data
      if @data.empty? && @deferred_load_io && @deferred_load_pos && @deferred_load_size.to_i > 0
        begin
          old_pos = @deferred_load_io.tell
          @deferred_load_io.seek @deferred_load_pos
          @data = @deferred_load_io.binmode.read(@deferred_load_size) || EMPTY_DATA.dup
        ensure
          if @deferred_load_io && old_pos
            @deferred_load_io.seek old_pos
            @deferred_load_io = nil # prevent read only on 1st access to data
          end
        end
      end
      @data
    end

    def range
      va...(va+vsize)
    end

    def inspect
      r = "#<Section"
      r << (" name=%-10s" % name.inspect) if name
      r << " va=%8x vsize=%8x rawsize=%8s" % [
        va, vsize,
        @data.size > 0 ? @data.size.to_s(16) : (@deferred_load_io ? "<defer>" : 0)
      ]
      r << (" dlpos=%8x" % @deferred_load_pos) if @deferred_load_pos
      r << ">"
    end
  end
end
