#coding: binary

class PEdump
  module CLR
    class Signature
      FIELD    = 6
      PROPERTY = 8

      DEFAULT      = 0
      VARARG       = 5
      GENERIC      = 0x10
      HASTHIS      = 0x20
      EXPLICITTHIS = 0x40

      SENTINEL = 0x41

      # https://github.com/stakx/ecma-335/blob/master/docs/ii.23.1.16-element-types-used-in-signatures.md
      ELEMENT_TYPE_END         = 0
      ELEMENT_TYPE_VOID        = 1
      ELEMENT_TYPE_BOOLEAN     = 2
      ELEMENT_TYPE_CHAR        = 3
      ELEMENT_TYPE_I1          = 4
      ELEMENT_TYPE_U1          = 5
      ELEMENT_TYPE_I2          = 6
      ELEMENT_TYPE_U2          = 7
      ELEMENT_TYPE_I4          = 8
      ELEMENT_TYPE_U4          = 9
      ELEMENT_TYPE_I8          = 0x0a
      ELEMENT_TYPE_U8          = 0x0b
      ELEMENT_TYPE_R4          = 0x0c
      ELEMENT_TYPE_R8          = 0x0d
      ELEMENT_TYPE_STRING      = 0x0e
      ELEMENT_TYPE_PTR         = 0x0f # Followed by type
      ELEMENT_TYPE_BYREF       = 0x10 # Followed by type
      ELEMENT_TYPE_VALUETYPE   = 0x11 # Followed by TypeDef or TypeRef token
      ELEMENT_TYPE_CLASS	     = 0x12 # Followed by TypeDef or TypeRef token
      ELEMENT_TYPE_VAR         = 0x13 # Generic parameter in a generic type definition, represented as number (compressed unsigned integer)
      ELEMENT_TYPE_ARRAY       = 0x14 # type rank boundsCount bound1 … loCount lo1 …
      ELEMENT_TYPE_GENERICINST = 0x15 # Generic type instantiation. Followed by type type-arg-count type-1 … type-n
      ELEMENT_TYPE_TYPEDBYREF  = 0x16
      ELEMENT_TYPE_I	         = 0x18 # System.IntPtr
      ELEMENT_TYPE_U           = 0x19 # System.UIntPtr
      ELEMENT_TYPE_FNPTR	     = 0x1b # Followed by full method signature
      ELEMENT_TYPE_OBJECT      = 0x1c # System.Object
      ELEMENT_TYPE_SZARRAY	   = 0x1d # Single-dim array with 0 lower bound
      ELEMENT_TYPE_MVAR	       = 0x1e # Generic parameter in a generic method definition, represented as number (compressed unsigned integer)
      ELEMENT_TYPE_CMOD_REQD   = 0x1f # Required modifier: followed by a TypeDef or TypeRef token
      ELEMENT_TYPE_CMOD_OPT    = 0x20 # Optional modifier: followed by a TypeDef or TypeRef token
      ELEMENT_TYPE_INTERNAL	   = 0x21 # Implemented within the CLI
      # TODO: 0x40+

      # https://github.com/stakx/ecma-335/blob/master/docs/ii.23.2.10-param.md
      # https://github.com/stakx/ecma-335/blob/master/docs/ii.15.3-calling-convention.md
      def to_s
        a = []
        a << 'instance' if @type & 0x20 != 0
        a << 'explicit' if @type & 0x40 != 0
        a << case @type & 0x0f
              when DEFAULT
                nil # default calling convention
              when 1
                'cdecl'
              when 2
                'stdcall'
              when 3
                'thiscall'
              when 4
                'fastcall'
              when VARARG
                'vararg'
              else
                "0x%02x" % (@type)
              end
        a << @RetType
        a.compact.join(' ')
      end

      def self.read(io, key)
        klass = 
          case key
          when :Field
            FieldSig
          when :Property
            PropertySig
          when :MethodDef
            MethodDefSig
          when :MemberRef
            type = io.getbyte
            io.ungetbyte(type)
            if type == FIELD
              FieldSig
            else
              MethodRefSig
            end
          when :StandAloneSig
            StandAloneMethodSig
          when :TypeSpec
            TypeSpecBlob
          else
            raise "unknown key: #{key.inspect}"
          end
        klass.new(io)
      end

      # https://github.com/stakx/ecma-335/blob/master/docs/ii.23.2.10-param.md
      def _read_Param io
        _read_CustomMod(io)
        case (b = io.getbyte)
        when ELEMENT_TYPE_BYREF
          # TODO "add byref"
          _read_Type(io)
        when ELEMENT_TYPE_TYPEDBYREF
          "TYPEDBYREF"
        else
          io.ungetbyte(b)
          _read_Type(io)
        end
      end

      def _read_Type io
        case b = io.getbyte
        when ELEMENT_TYPE_BOOLEAN     then "bool"
        when ELEMENT_TYPE_CHAR        then "char"
        when ELEMENT_TYPE_CLASS
          a = ['CLASS']
          a << _read_TypeDefOrRefOrSpecEncoded(io).to_s(16)
          a.join(' ')

        when ELEMENT_TYPE_VALUETYPE
          a = ['VALUE']
          a << _read_TypeDefOrRefOrSpecEncoded(io).to_s(16)
          a.join(' ')

        when ELEMENT_TYPE_GENERICINST
          # https://github.com/stakx/ecma-335/blob/f181e4696eebcbbc7c2b1e5d0a2ee289f2884d2d/docs/vi.b.4.3-metadata.md
          a = []
          a << _read_Type(io)
          genArgCount = _read_compressed_uint(io)
          nested_types = genArgCount.times.map{ _read_Type(io).to_s }
          a << '<' + nested_types.join(', ') + '>'
          a.join(' ')

        when ELEMENT_TYPE_I           then "nint"
        when ELEMENT_TYPE_I1          then "sbyte"
        when ELEMENT_TYPE_I2          then "short"
        when ELEMENT_TYPE_I4          then "int"
        when ELEMENT_TYPE_I8          then "long"

        when ELEMENT_TYPE_R4          then "float"
        when ELEMENT_TYPE_R8          then "double"

        when ELEMENT_TYPE_U           then "nuint"
        when ELEMENT_TYPE_U1          then "byte"
        when ELEMENT_TYPE_U2          then "ushort"
        when ELEMENT_TYPE_U4          then "uint"
        when ELEMENT_TYPE_U8          then "ulong"
        when ELEMENT_TYPE_OBJECT      then "object"
        when ELEMENT_TYPE_STRING      then "string"
        when ELEMENT_TYPE_SZARRAY     then "#{_read_Type(io)}[]"
        when ELEMENT_TYPE_VALUETYPE   then _read_TypeDefOrRefOrSpecEncoded(io)
        when ELEMENT_TYPE_VAR, ELEMENT_TYPE_MVAR
          _read_compressed_uint(io).to_s
        when ELEMENT_TYPE_VOID        then "void"
        when ELEMENT_TYPE_END         then "END"
        else
          "0x%02x" % b
        end
      end

      # https://github.com/stakx/ecma-335/blob/master/docs/ii.23.2.11-rettype.md
      def _read_RetType io
        _read_CustomMod(io)
        case (b = io.getbyte)
        when ELEMENT_TYPE_BYREF
          # TODO "add byref"
          _read_Type(io)
        when ELEMENT_TYPE_TYPEDBYREF
          "TYPEDBYREF"
        when ELEMENT_TYPE_VOID
          "void"
        else
          io.ungetbyte(b)
          _read_Type(io)
        end
      end

      # https://github.com/stakx/ecma-335/blob/master/docs/ii.23.2.7-custommod.md
      def _read_CustomMod io
        b = io.getbyte
        if b == ELEMENT_TYPE_CMOD_REQD || b == ELEMENT_TYPE_CMOD_OPT
          @cmod = b
          @cmod_type = _read_TypeDefOrRefOrSpecEncoded(io)
        else
          io.ungetbyte(b)
        end
      end

      # https://github.com/stakx/ecma-335/blob/master/docs/ii.23.2.8-typedeforreforspecencoded.md
      def _read_TypeDefOrRefOrSpecEncoded io
        v = _read_compressed_uint(io)
        table_id = (v & 3)
        idx_in_table = (v >> 2)
        table_id_hi = 
          case table_id
          when 0
            # TypeDef
            0x02_000000
          when 1
            # TypeRef
            0x01_000000
          when 2
            # TypeSpec
            0x1b_000000
          else
            # invalid
            0
          end
        table_id_hi | idx_in_table
      end

      # https://github.com/stakx/ecma-335/blob/master/docs/ii.23.2-blobs-and-signatures.md
      def _read_compressed_uint io
        v = io.read(1).unpack1('C')
        if v & 0x80 == 0
          # 1 byte
          v
        elsif v & 0xC0 == 0x80
          # 2 bytes
           ((v & 0x3F) << 8) | io.read(1).unpack1('C')
        elsif v & 0xE0 == 0xC0
          # 4 bytes
          ((v & 0x1F) << 24) | (io.read(3).unpack1('C') << 16) | (io.read(2).unpack1('C') << 8) | io.read(1).unpack1('C')
        else
          nil
        end
      end
    end # class Signature

    # https://github.com/stakx/ecma-335/blob/master/docs/ii.23.2.4-fieldsig.md
    class FieldSig < Signature
      attr_accessor :type

      def initialize(io)
        sig_type = io.getbyte
        raise "unexpected sig_type #{sig_type}" if sig_type != FIELD

        _read_CustomMod(io)
        @type = _read_Type(io)
      end
    end

    # https://github.com/stakx/ecma-335/blob/master/docs/ii.23.2.5-propertysig.md
    class PropertySig < Signature
      attr_accessor :type, :params

      def initialize(io)
        sig_type = io.getbyte
        raise "unexpected sig_type #{sig_type}" if sig_type != PROPERTY && sig_type != PROPERTY|HASTHIS

        @ParamCount = _read_compressed_uint(io)
        _read_CustomMod(io) # FIXME
        @type = _read_Type(io)
        if @ParamCount < 255 # protect from malformed EXEs
          @params = @ParamCount.times.map{ _read_Param(io) }
        end
      end
    end

    # https://github.com/stakx/ecma-335/blob/master/docs/ii.23.2.2-methodrefsig.md
    class MethodRefSig < Signature
      attr_accessor :ret_type, :params

      def initialize io
        # "The first byte of the Signature holds bits for HASTHIS, EXPLICITTHIS, and the calling convention VARARG. These are ORed together."
        @type = io.read(1).unpack1('C')
        @ParamCount = _read_compressed_uint(io)
        @ret_type = _read_RetType(io)

        if @ParamCount < 255 # protect from malformed EXEs
          @params = @ParamCount.times.map{ _read_Param(io) }
        end
      end
    end

    # https://github.com/stakx/ecma-335/blob/master/docs/ii.23.2.1-methoddefsig.md
    class MethodDefSig < Signature
      attr_accessor :ret_type, :params

      def initialize io
        # "The first byte of the Signature holds bits for HASTHIS, EXPLICITTHIS, and the calling convention VARARG. These are ORed together."
        @type = io.read(1).unpack1('C')
        
        if @type & GENERIC == GENERIC
          @GenParamCount = _read_compressed_uint(io)
        end

        @ParamCount = _read_compressed_uint(io)
        @ret_type = _read_RetType(io)

        if @ParamCount < 255 # protect from malformed EXEs
          @params = @ParamCount.times.map{ _read_Param(io) }
        end
      end
    end

    # https://github.com/stakx/ecma-335/blob/master/docs/ii.23.2.3-standalonemethodsig.md
    class StandAloneMethodSig < MethodRefSig
    end

    # https://github.com/stakx/ecma-335/blob/master/docs/ii.23.2.14-typespec.md
    class TypeSpecBlob < Signature
      def initialize io
        @type = _read_Type(io)
      end
    end

  end
end
