class PEdump; end

class PEdump::NE
  class VS_VERSIONINFO < IOStruct.new( 'v2a16',
    :wLength,
    :wValueLength,
    :szKey,          # ASCII string "VS_VERSION_INFO".
    :Padding1,
    # manual:
    :Value,          # VS_FIXEDFILEINFO
    :Padding2,
    :Children
  )
    def self.read f, size = SIZE
      super.tap do |vi|
        vi.szKey.chomp!("\x00")
        vi.Padding1 = f.tell%4 > 0 ? f.read(4 - f.tell%4) : nil
        vi.Value = VS_FIXEDFILEINFO.read(f,vi.wValueLength)
        # As many zero words as necessary to align the Children member on a 32-bit boundary.
        # These bytes are not included in wValueLength. This member is optional.
        vi.Padding2 = f.tell%4 > 0 ? f.read(4 - f.tell%4) : nil
        vi.Children = [] # An array of zero or one StringFileInfo structures,
                         # and zero or one VarFileInfo structures

        2.times do
          pos = f.tell
          f.seek(pos+4)  # seek 4 bytes forward
          t = f.read(3)
          f.seek(pos)    # return back
          case t
          when "Var"
            vi.Children << VarFileInfo.read(f)
          when "Str"
            vi.Children << StringFileInfo.read(f)
          else
            PEdump.logger.warn "[?] invalid VS_VERSIONINFO child type #{t.inspect}"
            break
          end
        end
      end
    end
  end

  class VS_FIXEDFILEINFO < IOStruct.new( 'V13',
    :dwSignature,
    :dwStrucVersion,
    :dwFileVersionMS,
    :dwFileVersionLS,
    :dwProductVersionMS,
    :dwProductVersionLS,
    :dwFileFlagsMask,
    :dwFileFlags,
    :dwFileOS,
    :dwFileType,
    :dwFileSubtype,
    :dwFileDateMS,
    :dwFileDateLS,
    # manual:
    :valid
  )
    def self.read f, size = SIZE
      super.tap do |ffi|
        ffi.valid = (ffi.dwSignature == 0xFEEF04BD)
      end
    end
  end

  class StringFileInfo < IOStruct.new( 'v2a15',
    :wLength,
    :wValueLength,  # always 0
    :szKey,         # The ASCII string "StringFileInfo"
    :Padding,       # As many zero words as necessary to align the Children member on a 32-bit boundary
    :Children       # An array of one or more StringTable structures
  )
    def self.read f, size = SIZE
      pos0 = f.tell
      super.tap do |x|
        x.szKey.chomp!("\x00")
        x.Padding = f.tell%4 > 0 ? f.read(4 - f.tell%4) : nil
        x.Children = []
        while !f.eof? && f.tell < pos0+x.wLength
          x.Children << StringTable.read(f)
        end
      end
    end
  end

  class StringTable < IOStruct.new( 'v2a9',
    :wLength,       # The length, in bytes, of this StringTable structure,
                    # including all structures indicated by the Children member.
    :wValueLength,  # always 0
    :szKey,         # An 8-digit hexadecimal number stored as a ASCII string
    :Padding,       # As many zero words as necessary to align the Children member on a 32-bit boundary
    :Children       # An array of one or more String structures.
  )
    def self.read f, size = SIZE
      pos0 = f.tell
      super.tap do |x|
        x.szKey.chomp!("\x00")
        x.Padding = f.tell%4 > 0 ? f.read(4 - f.tell%4) : nil
        x.Children = []
        while !f.eof? && f.tell < pos0+x.wLength
          x.Children << VersionString.read(f)
        end
      end
    end
  end

  class VersionString < IOStruct.new( 'v2',
    :wLength,       # The length, in bytes, of this String structure.
    :wValueLength,  # The size, in words, of the Value member
    :szKey,         # An arbitrary ASCII string
    :Padding,       # As many zero words as necessary to align the Value member on a 32-bit boundary
    :Value          # A zero-terminated string. See the szKey member description for more information
  )
    def self.read f, size = SIZE
      pos = f.tell
      super.tap do |x|
        x.szKey   = f.gets("\x00").to_s.chomp("\x00")
        x.Padding = f.tell%4 > 0 ? f.read(4 - f.tell%4) : nil

        value_len = [x.wValueLength*2, x.wLength - (f.tell-pos)].min
        value_len = 0 if value_len < 0

        cp = PEdump::NE.cp # XXX HACK

        x.Value   = f.read(value_len).to_s.chomp("\x00")
        begin
          x.Value.force_encoding("CP#{cp}").encode!('UTF-8').sub!(/\u0000$/,'')
        rescue
          x.Value.force_encoding("CP1250").encode!('UTF-8').sub!(/\u0000$/,'') rescue nil
        end
        if f.tell%4 > 0
          f.read(4-f.tell%4) # undoc padding?
        end
      end
    end
  end

  class VarFileInfo < IOStruct.new( 'v2a12',
    :wLength,
    :wValueLength,  # always 0
    :szKey,         # The ASCII string "VarFileInfo"
    :Padding,       # As many zero words as necessary to align the Children member on a 32-bit boundary
    :Children       # Typically contains a list of languages that the application or DLL supports
  )
    def self.read f, size = SIZE
      super.tap do |x|
        x.szKey.chomp!("\x00")
        x.Padding = f.tell%4 > 0 ? f.read(4 - f.tell%4) : nil
        x.Children = Var.read(f)
      end
    end
  end

  class Var < IOStruct.new( 'v2a12',
    :wLength,
    :wValueLength,  # The length, in bytes, of the Value member
    :szKey,         # The ASCII string "Translation"
    :Padding,       # As many zero words as necessary to align the Children member on a 32-bit boundary
    :Value          # An array of one or more values that are language and code page identifier pairs
  )
    def self.read f, size = SIZE
      super.tap do |x|
        x.szKey.chomp!("\x00")
        x.Padding = f.tell%4 > 0 ? f.read(4 - f.tell%4) : nil
        x.Value = f.read(x.wValueLength).unpack('v*')
      end
    end
  end
end
