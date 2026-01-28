class PEdump
  TLS_DIRECTORY_FIELDS = %i[
    StartAddressOfRawData
    EndAddressOfRawData
    AddressOfIndex
    AddressOfCallBacks
    SizeOfZeroFill
    Characteristics
  ].freeze

  # 32-bit: all fields are 32-bit (V6)
  # 64-bit: first 4 fields are 64-bit pointers (Q4), last 2 are 32-bit (V2)
  IMAGE_TLS_DIRECTORY32 = IOStruct.new('V6', *TLS_DIRECTORY_FIELDS)
  IMAGE_TLS_DIRECTORY64 = IOStruct.new('Q4V2', *TLS_DIRECTORY_FIELDS)
end
