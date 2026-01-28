class PEdump
  # https://www.intel.com/content/www/us/en/architecture-and-technology/unified-extensible-firmware-interface/efi-specifications-general-technology.html
  # http://wiki.phoenix.com/wiki/index.php/EFI_TE_IMAGE_HEADER
  # https://formats.kaitai.io/uefi_te/index.html
  # http://ho.ax/tag/efi/
  # https://github.com/gdbinit/TELoader

  EFI_IMAGE_DATA_DIRECTORY = IOStruct.new("VV", :va, :size)
  EFI_IMAGE_DATA_DIRECTORY::TYPES = %w'BASERELOC DEBUG'
  EFI_IMAGE_DATA_DIRECTORY::TYPES.each_with_index do |type, idx|
    EFI_IMAGE_DATA_DIRECTORY.const_set(type, idx)
  end

  # Using hash format with nested struct array for DataDirectory
  class EFI_TE_IMAGE_HEADER < IOStruct.new(
    fields: {
      Signature:          'uint16_t',
      Machine:            'uint16_t',
      NumberOfSections:   'uint8_t',
      Subsystem:          'uint8_t',
      StrippedSize:       'uint16_t',
      AddressOfEntryPoint: 'uint32_t',
      BaseOfCode:         'uint32_t',
      ImageBase:          'uint64_t',
      DataDirectory:      { type: EFI_IMAGE_DATA_DIRECTORY, count: 2 },
    }
  )
    REAL_SIZE = SIZE

    attr_accessor :sections

    def self.read io, args = {}
      super(io).tap do |te|
        te.sections = PE.read_sections(io, te.NumberOfSections, args)
      end
    end
  end
  TE = EFI_TE_IMAGE_HEADER

  def te_shift
    if @te
      @te.StrippedSize - EFI_TE_IMAGE_HEADER::REAL_SIZE
    else
      0
    end
  end

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
