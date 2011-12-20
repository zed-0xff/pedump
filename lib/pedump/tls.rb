class PEdump
  IMAGE_TLS_DIRECTORY32 = create_struct 'V6',
    :StartAddressOfRawData,
    :EndAddressOfRawData,
    :AddressOfIndex,
    :AddressOfCallBacks,
    :SizeOfZeroFill,
    :Characteristics

  IMAGE_TLS_DIRECTORY64 = create_struct 'Q4V2',
    :StartAddressOfRawData,
    :EndAddressOfRawData,
    :AddressOfIndex,
    :AddressOfCallBacks,
    :SizeOfZeroFill,
    :Characteristics
end
