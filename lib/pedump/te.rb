class PEdump
  # https://www.intel.com/content/www/us/en/architecture-and-technology/unified-extensible-firmware-interface/efi-specifications-general-technology.html
  # http://wiki.phoenix.com/wiki/index.php/EFI_TE_IMAGE_HEADER
  # https://formats.kaitai.io/uefi_te/index.html
  # http://ho.ax/tag/efi/
  
  EFI_IMAGE_DATA_DIRECTORY = IOStruct.new( "VV", :va, :size )
  EFI_IMAGE_DATA_DIRECTORY::TYPES = %w'BASERELOC DEBUG'
  EFI_IMAGE_DATA_DIRECTORY::TYPES.each_with_index do |type,idx|
    EFI_IMAGE_DATA_DIRECTORY.const_set(type,idx)
  end

  class EFI_TE_IMAGE_HEADER < IOStruct.new 'vvCCvVVQ',
    :Signature,
    :Machine,
    :NumberOfSections,
    :Subsystem,
    :StrippedSize,
    :AddressOfEntryPoint,
    :BaseOfCode,
    :ImageBase,
    :DataDirectory # readed manually: EFI_IMAGE_DATA_DIRECTORY DataDirectory[2]

    SIZE = superclass::SIZE + EFI_IMAGE_DATA_DIRECTORY::SIZE * 2

    attr_accessor :sections

    def self.read io, args = {}
      super(io).tap do |te|
        te.DataDirectory = 2.times.map do
          EFI_IMAGE_DATA_DIRECTORY.read(io)
        end
        te.sections = PE.read_sections(io, te.NumberOfSections, args)
      end
    end
  end
  TE = EFI_TE_IMAGE_HEADER

  def te f=@io
    return @te if defined?(@te)
    @te ||=
      begin
        te_offset = 0
        f.seek te_offset
        if f.read(2) == 'VZ'
          f.seek te_offset
          EFI_TE_IMAGE_HEADER.read f, :force => @force
        else
          nil
        end
      end
  end
end
