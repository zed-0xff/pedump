class PEdump
  def security f=@io
    return nil unless pe(f) && pe(f).ioh && f
    dir = @pe.ioh.DataDirectory[IMAGE_DATA_DIRECTORY::SECURITY]
    return nil if !dir || dir.va == 0

    # IMAGE_DIRECTORY_ENTRY_SECURITY
    # Points to a list of WIN_CERTIFICATE structures, defined in WinTrust.H.
    # Not mapped into memory as part of the image.
    # Therefore, the VirtualAddress field is a file offset, rather than an RVA.
    #
    # http://msdn.microsoft.com/en-us/magazine/bb985997.aspx

    f.seek dir.va
    r = []
    ofs = f.tell
    while !f.eof? && (f.tell-ofs < dir.size)
      r << WIN_CERTIFICATE.read(f)
    end
    r
  end
  alias :signature :security

  # WIN_CERT_TYPE_X509             (0x0001) bCertificate contains an X.509 certificate.
  # WIN_CERT_TYPE_PKCS_SIGNED_DATA (0x0002) bCertificate contains a PKCS SignedData structure.
  # WIN_CERT_TYPE_RESERVED_1       (0x0003) Reserved.
  # WIN_CERT_TYPE_PKCS1_SIGN       (0x0009) bCertificate contains PKCS1_MODULE_SIGN fields.

  # http://msdn.microsoft.com/en-us/library/aa447037.aspx
  class WIN_CERTIFICATE < IOStruct.new 'Vvv',
    :dwLength,
    :wRevision,
    :wCertificateType,
    # manual
    :data

    def self.read f
      super.tap do |x|
        if x.dwLength.to_i < 8
          PEdump.logger.error "[!] #{x.class}: too small length #{x.dwLength}"
        elsif x.dwLength.to_i > 0x100_000
          PEdump.logger.error "[!] #{x.class}: too big length #{x.dwLength}"
        else
          x.data = f.read(x.dwLength - 8)
          begin
            case x.wCertificateType
            when 2
              require 'openssl'
              x.data = OpenSSL::PKCS7.new(x.data)
            end
          rescue
            PEdump.logger.error "[!] #{$!}"
          end
        end
      end
    end
  end
end
