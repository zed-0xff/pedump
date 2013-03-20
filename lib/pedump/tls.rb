class PEdump
  IMAGE_TLS_DIRECTORY32 = IOStruct.new 'V6',
    :StartAddressOfRawData,
    :EndAddressOfRawData,
    :AddressOfIndex,
    :AddressOfCallBacks,
    :SizeOfZeroFill,
    :Characteristics

  IMAGE_TLS_DIRECTORY64 = IOStruct.new 'Q4V2',
    :StartAddressOfRawData,
    :EndAddressOfRawData,
    :AddressOfIndex,
    :AddressOfCallBacks,
    :SizeOfZeroFill,
    :Characteristics
end
