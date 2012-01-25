require 'pedump/composite_io'

class PEdump
  class PE < Struct.new(
    :signature,             # "PE\x00\x00"
    :image_file_header,
    :image_optional_header, # includes data directory
    :section_table
  )
    alias :ifh       :image_file_header
    alias :ioh       :image_optional_header
    alias :sections  :section_table
    alias :sections= :section_table=
    def x64?
      ifh && ifh.Machine == 0x8664
    end
    def dll?
      ifh && ifh.flags.include?('DLL')
    end

    def pack
      signature + ifh.pack + ioh.pack
    end

    def self.read f, args = nil
      force = args.is_a?(Hash) && args[:force]

      pe_offset = f.tell
      pe_sig = f.read 4
      #logger.error "[!] 'NE' format is not supported!" if pe_sig == "NE\x00\x00"
      if pe_sig != "PE\x00\x00"
        if force
          logger.warn  "[?] no PE signature (want: 'PE\\x00\\x00', got: #{pe_sig.inspect})"
        else
          logger.debug "[?] no PE signature (want: 'PE\\x00\\x00', got: #{pe_sig.inspect}). (not forced)"
          return nil
        end
      end
      PE.new(pe_sig).tap do |pe|
        pe.image_file_header = IMAGE_FILE_HEADER.read(f)
        if pe.ifh.SizeOfOptionalHeader > 0
          if pe.x64?
            pe.image_optional_header = IMAGE_OPTIONAL_HEADER64.read(f, pe.ifh.SizeOfOptionalHeader)
          else
            pe.image_optional_header = IMAGE_OPTIONAL_HEADER32.read(f, pe.ifh.SizeOfOptionalHeader)
          end
        end

        if (nToRead=pe.ifh.NumberOfSections) > 0xffff
          if force.is_a?(Numeric) && force > 1
            logger.warn "[!] too many sections (#{pe.ifh.NumberOfSections}). forced. reading all"
          else
            logger.warn "[!] too many sections (#{pe.ifh.NumberOfSections}). not forced, reading first 65535"
            nToRead = 65535
          end
        end
        pe.sections = []
        nToRead.times do
          break if f.eof?
          pe.sections << IMAGE_SECTION_HEADER.read(f)
        end

        if pe.sections.any?
          # zero all missing values of last section
          pe.sections.last.tap do |last_section|
            last_section.each_pair do |k,v|
              last_section[k] = 0 if v.nil?
            end
          end
        end

        pe_end = f.tell
        if s=pe.sections.find{ |s| (pe_offset...pe_end).include?(s.va) }
          if !f.respond_to?(:seek)
            # already called with CompositeIO ?
            logger.error "[!] section with va=0x#{s.va.to_s(16)} overwrites PE header! 2nd time?!"

          elsif pe_end-pe_offset < 0x100_000
            logger.warn "[!] section with va=0x#{s.va.to_s(16)} overwrites PE header! trying to rebuild..."
            f.seek pe_offset
            data = f.read(s.va-pe_offset)
            f.seek s.PointerToRawData
            io = CompositeIO.new(StringIO.new(data), f)
            return PE.read(io, args)
          else
            logger.error "[!] section with va=0x#{s.va.to_s(16)} overwrites PE header! too big to rebuild!"
          end
        end
      end
    end

    def self.logger; PEdump.logger; end
  end

  def pe f=@io
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
          PE.read f, :force => @force
        end
      end
  end

end
