#coding: binary

class PEdump
  class IMAGE_COR20_HEADER < IOStruct.new(
    'V S2 Q VV Q6',
    :cb,
    :MajorRuntimeVersion,
    :MinorRuntimeVersion,
    :MetaData, # IMAGE_DATA_DIRECTORY
    :Flags,
    :EntryPointToken,
    # IMAGE_DATA_DIRECTORies:
    :Resources,
    :StrongNameSignature,
    :CodeManagerTable,
    :VTableFixups,
    :ExportAddressTableJumps,
    :ManagedNativeHeader
  )
    def self.read io
      super.tap do |r|
        %i'MetaData Resources StrongNameSignature CodeManagerTable VTableFixups ExportAddressTableJumps ManagedNativeHeader'.each do |field|
          next unless r[field] # broken CLR header

          r[field] = IMAGE_DATA_DIRECTORY.read([r[field]].pack('Q'))
        end
      end
    end
  end

  module CLR
    class MetadataHeader < IOStruct.new(
      'V S2 VV',
      :Magic,
      :MajorVersion,
      :MinorVersion,
      :ExtraData,
      :VersionLength, # aligned to 4 bytes
      :Version,
      :Flags,         # maybe 1 byte of flags + 1 byte of padding
      :NumberOfStreams
    )
      MAGIC = 0x424A5342 # 'BSJB'

      def valid?
        Magic == MAGIC
      end

      def self.read io
        super.tap do |r|
          r.Version = io.read(r.VersionLength).unpack1('A*')
          r.Flags   = io.read(2).unpack1('S')
          r.NumberOfStreams = io.read(2).unpack1('v')
        end
      end
    end

    class MetadataStreamHeader < IOStruct.new(
      'VV',
      :offset,
      :size,
      :name # a zero-terminated ASCII string no longer than 31 characters. The name might be shorter, case the size of the stream header is correspondingly
            # reduced, padded to the 4-byte boundary.
    )

      def self.read io
        super.tap do |r|
          r.name = ''
          nread = 0
          while !io.eof? && r.name.size < 32
            c = io.read(1)
            nread += 1
            break if c == "\0"

            r.name << c
          end
          if !io.eof? && nread % 4 != 0
            io.read(4 - nread % 4) # padding
          end
        end
      end
    end

    # https://github.com/stakx/ecma-335/blob/master/docs/ii.24.2.6-metadata-stream.md
    class MetadataTableStreamHeader < IOStruct.new('V CC CCQQ', :Reserved, :MajorVersion, :MinorVersion, :HeapSizes, :Reserved2, :Valid, :Sorted, :Rows)
      attr_accessor :sizes_hash

      HEAP_SIZES_MANY_STRINGS = 1 # Size of "#Strings" stream ≥ 216
      HEAP_SIZES_MANY_GUIDS   = 2 # Size of "#GUID" stream ≥ 216
      HEAP_SIZES_MANY_BLOBS   = 4 # Size of "#Blob" stream ≥ 216

      FLAGS = {
        1 => :Module,
        2 => :TypeRef,
        4 => :TypeDef,
        8 => :Reserved1,
        16 => :Field,
        32 => :Reserved2,
        64 => :MethodDef,
        128 => :Reserved3,
        256 => :Param,
        512 => :InterfaceImpl,
        1024 => :MemberRef,
        2048 => :Constant,
        4096 => :CustomAttribute,
        8192 => :FieldMarshal,
        16384 => :DeclSecurity,
        32768 => :ClassLayout,
        65536 => :FieldLayout,
        131072 => :StandAloneSig,
        262144 => :EventMap,
        524288 => :Reserved4,
        1048576 => :Event,
        2097152 => :PropertyMap,
        4194304 => :Reserved5,
        8388608 => :Property,
        16777216 => :MethodSemantics,
        33554432 => :MethodImpl,
        67108864 => :ModuleRef,
        134217728 => :TypeSpec,
        268435456 => :ImplMap,
        536870912 => :FieldRVA,
        1073741824 => :Reserved6,
        2147483648 => :Reserved7,
        4294967296 => :Assembly,
        8589934592 => :AssemblyProcessor,
        17179869184 => :AssemblyOS,
        34359738368 => :AssemblyRef,
        68719476736 => :AssemblyRefProcessor,
        137438953472 => :AssemblyRefOS,
        274877906944 => :File,
        549755813888 => :ExportedType,
        1099511627776 => :ManifestResource,
        2199023255552 => :NestedClass,
        4398046511104 => :GenericParam,
        8796093022208 => :MethodSpec,
        17592186044416 => :GenericParamConstraint,
      }
      REVERSE_FLAGS = FLAGS.invert

      def known_table? key
        REVERSE_FLAGS.key?(key)
      end

      def valid_flags
        FLAGS.find_all{ |k,v| (self.Valid & k) != 0 }.map(&:last)
      end

      def sorted_flags
        FLAGS.find_all{ |k,v| (self.Sorted & k) != 0 }.map(&:last)
      end

      def valid?
        self.Reserved == 0 && self.MajorVersion == 2 && self.MinorVersion == 0
      end

      def self.read io
        super.tap do |r|
          idx = 1
          r.sizes_hash = {}
          n = r.Valid
          while n > 0
            if n & 1 != 0
              key = FLAGS[idx].to_sym
              r.sizes_hash[key] = io.read(4).unpack1('V')
            end
            n >>= 1
            idx <<= 1
          end
          r.Rows = r.sizes_hash.values
        end
      end
    end

    TableDefs = {
      # https://github.com/stakx/ecma-335/blob/master/docs/ii.22.30-module_0x00.md
      Module: {
        Generation: 2,       # a 2-byte value, reserved, shall be zero)
        Name:       :string, # an index into the String heap
        Mvid:       :guid,   # an index into the Guid heap
        EncId:      :guid,   # an index into the Guid heap; reserved, shall be zero
        EncBaseId:  :guid,   # an index into the Guid heap; reserved, shall be zero
      },

      # https://github.com/stakx/ecma-335/blob/master/docs/ii.22.38-typeref-0x01.md
      TypeRef: {
        ResolutionScope: [:Module, :ModuleRef, :AssemblyRef, :TypeRef],
        TypeName:        :string,
        TypeNamespace:   :string,
      },

      # https://github.com/stakx/ecma-335/blob/master/docs/ii.22.37-typedef-0x02.md
      TypeDef: {
        Flags:           4,        # a 4-byte bitmask of TypeAttributes
        TypeName:        :string,
        TypeNamespace:   :string,
        Extends:         [:TypeDef, :TypeRef, :TypeSpec],
        FieldList:       :Field,
        MethodList:      :MethodDef,
      },
      
      # https://github.com/stakx/ecma-335/blob/master/docs/ii.22.15-field-0x04.md
      Field: {
        Flags:           2,        # a 2-byte bitmask of FieldAttributes
        Name:            :string,
        Signature:       :blob,
      },

      # https://github.com/stakx/ecma-335/blob/master/docs/ii.22.26-methoddef-0x06.md
      MethodDef: {
        RVA:             4,        # a 4-byte constant
        ImplFlags:       2,        # a 2-byte bitmask of MethodImplAttributes
        Flags:           2,        # a 2-byte bitmask of MethodAttributes
        Name:            :string,
        Signature:       :blob,
        ParamList:       :Param,
      },

      # https://github.com/stakx/ecma-335/blob/master/docs/ii.22.33-param-0x08.md
      Param: {
        Flags:           2,        # a 2-byte bitmask of ParamAttributes
        Sequence:        2,        # a 2-byte constant
        Name:            :string,
      },

      # https://github.com/stakx/ecma-335/blob/master/docs/ii.22.23-interfaceimpl-0x09.md
      InterfaceImpl: {
        Class:           :TypeDef,
        Interface:       [:TypeDef, :TypeRef, :TypeSpec],
      },

      # https://github.com/stakx/ecma-335/blob/master/docs/ii.22.25-memberref-0x0a.md
      MemberRef: {
        Class:           [:MethodDef, :ModuleRef, :TypeDef, :TypeRef, :TypeSpec],
        Name:            :string,
        Signature:       :blob,
      },

      # https://github.com/stakx/ecma-335/blob/master/docs/ii.22.9-constant-0x0b.md
      Constant: {
        Type:            2,        # a 1-byte constant, followed by a 1-byte padding zero
        Parent:          [:Field, :Param, :Property],
        Value:           :blob,
      },

      # https://github.com/stakx/ecma-335/blob/master/docs/ii.22.10-customattribute-0x0c.md
      CustomAttribute: {
        Parent:          [:MethodDef, :Field, :TypeRef, :TypeDef, :Param, :InterfaceImpl, :MemberRef, :Module, :DeclSecurity, :Property, :Event, :StandAloneSig, :ModuleRef, :TypeSpec, :Assembly, :AssemblyRef, :File, :ExportedType, :ManifestResource, :GenericParam, :GenericParamConstraint, :MethodSpec],
        Type:            [:MethodDef, :MemberRef],
        Value:           :blob,
      },

      # https://github.com/stakx/ecma-335/blob/master/docs/ii.22.17-fieldmarshal-0x0d.md
      FieldMarshal: {
        Parent:          [:Field, :Param],
        NativeType:      :blob,
      },

      # https://github.com/stakx/ecma-335/blob/master/docs/ii.22.11-declsecurity-0x0e.md
      DeclSecurity: {
        Action:          2,        # a 2-byte constant
        Parent:          [:TypeDef, :MethodDef, :Assembly],
        PermissionSet:   :blob,
      },

      # https://github.com/stakx/ecma-335/blob/master/docs/ii.22.8-classlayout-0x0f.md
      ClassLayout: {
        PackingSize:     2,        # a 2-byte constant
        ClassSize:       4,        # a 4-byte constant
        Parent:          :TypeDef,
      },

      # https://github.com/stakx/ecma-335/blob/master/docs/ii.22.16-fieldlayout-0x10.md
      FieldLayout: {
        Offset:          4,        # a 4-byte constant
        Field:           :Field,
      },

      # https://github.com/stakx/ecma-335/blob/master/docs/ii.22.36-standalonesig-0x11.md
      StandAloneSig: {
        Signature:       :blob,
      },

      # https://github.com/stakx/ecma-335/blob/master/docs/ii.22.12-eventmap-0x12.md
      EventMap: {
        Parent:          :TypeDef,
        EventList:       :Event,
      },

      # https://github.com/stakx/ecma-335/blob/master/docs/ii.22.13-event-0x14.md
      Event: {
        EventFlags:      2,        # a 2-byte bitmask of EventAttributes
        Name:            :string,
        EventType:       [:TypeDef, :TypeRef, :TypeSpec],
      },

      # https://github.com/stakx/ecma-335/blob/master/docs/ii.22.35-propertymap-0x15.md
      PropertyMap: {
        Parent:          :TypeDef,
        PropertyList:    :Property,
      },

      # https://github.com/stakx/ecma-335/blob/master/docs/ii.22.34-property-0x17.md
      Property: {
        Flags:           2,        # a 2-byte bitmask of PropertyAttributes
        Name:            :string,
        Type:            :blob,
      },

      # https://github.com/stakx/ecma-335/blob/master/docs/ii.22.28-methodsemantics-0x18.md
      MethodSemantics: {
        Semantics:       2,        # a 2-byte bitmask of MethodSemanticsAttributes
        Method:          :MethodDef,
        Association:     [:Event, :Property],
      },

      # https://github.com/stakx/ecma-335/blob/master/docs/ii.22.27-methodimpl-0x19.md
      MethodImpl: {
        Class:             :TypeDef,
        MethodBody:        [:MethodDef, :MemberRef],
        MethodDeclaration: [:MethodDef, :MemberRef],
      },

      # https://github.com/stakx/ecma-335/blob/master/docs/ii.22.31-moduleref-0x1a.md
      ModuleRef: {
        Name:            :string,
      },

      # https://github.com/stakx/ecma-335/blob/master/docs/ii.22.39-typespec-0x1b.md
      TypeSpec: {
        Signature:       :blob,
      },

      # https://github.com/stakx/ecma-335/blob/master/docs/ii.22.22-implmap-0x1c.md
      ImplMap: {
        MappingFlags:    2,        # a 2-byte bitmask of PInvokeAttributes
        MemberForwarded: [:Field, :MethodDef],
        ImportName:      :string,
        ImportScope:     :ModuleRef,
      },

      # https://github.com/stakx/ecma-335/blob/master/docs/ii.22.18-fieldrva-0x1d.md
      FieldRVA: {
        RVA:             4,        # a 4-byte constant
        Field:           :Field,
      },

      # https://github.com/stakx/ecma-335/blob/master/docs/ii.22.2-assembly-0x20.md
      Assembly: {
        HashAlgId:       4,        # a 4-byte constant
        MajorVersion:    2,        # a 2-byte constant
        MinorVersion:    2,        # a 2-byte constant
        BuildNumber:     2,        # a 2-byte constant
        RevisionNumber:  2,        # a 2-byte constant
        Flags:           4,        # a 4-byte bitmask of AssemblyFlags
        PublicKey:       :blob,
        Name:            :string,
        Culture:         :string,
      },

      # https://github.com/stakx/ecma-335/blob/master/docs/ii.22.4-assemblyprocessor-0x21.md
      AssemblyProcessor: {
        Processor:       4,        # a 4-byte constant
      },

      # https://github.com/stakx/ecma-335/blob/master/docs/ii.22.3-assemblyos-0x22.md
      AssemblyOS: {
        OSPlatformId:    4,        # a 4-byte constant
        OSMajorVersion:  4,        # a 4-byte constant
        OSMinorVersion:  4,        # a 4-byte constant
      },

      # https://github.com/stakx/ecma-335/blob/master/docs/ii.22.5-assemblyref-0x23.md
      AssemblyRef: {
        MajorVersion:     2,        # a 2-byte constant
        MinorVersion:     2,        # a 2-byte constant
        BuildNumber:      2,        # a 2-byte constant
        RevisionNumber:   2,        # a 2-byte constant
        Flags:            4,        # a 4-byte bitmask of AssemblyFlags
        PublicKeyOrToken: :blob,
        Name:             :string,
        Culture:          :string,
        HashValue:        :blob,
      },

      # https://github.com/stakx/ecma-335/blob/master/docs/ii.22.7-assemblyrefprocessor-0x24.md
      AssemblyRefProcessor: {
        Processor:       4,        # a 4-byte constant
        AssemblyRef:     :AssemblyRef,
      },

      # https://github.com/stakx/ecma-335/blob/master/docs/ii.22.6-assemblyrefos-0x25.md
      AssemblyRefOS: {
        OSPlatformId:    4,        # a 4-byte constant
        OSMajorVersion:  4,        # a 4-byte constant
        OSMinorVersion:  4,        # a 4-byte constant
        AssemblyRef:     :AssemblyRef,
      },

      # https://github.com/stakx/ecma-335/blob/master/docs/ii.22.19-file-0x26.md
      File: {
        Flags:           4,        # a 4-byte bitmask of FileAttributes
        Name:            :string,
        HashValue:       :blob,
      },

      # https://github.com/stakx/ecma-335/blob/master/docs/ii.22.24-manifestresource-0x28.md
      ManifestResource: {
        Offset:          4,        # a 4-byte constant
        Flags:           4,        # a 4-byte bitmask of ManifestResourceAttributes
        Name:            :string,
        Implementation:  [:File, :AssemblyRef],
      },

      # https://github.com/stakx/ecma-335/blob/master/docs/ii.22.32-nestedclass-0x29.md
      NestedClass: {
        NestedClass:     :TypeDef,
        EnclosingClass:  :TypeDef,
      },

      # https://github.com/stakx/ecma-335/blob/master/docs/ii.22.20-genericparam-0x2a.md
      GenericParam: {
        Number:          2,        # a 2-byte constant
        Flags:           2,        # a 2-byte bitmask of GenericParamAttributes
        Owner:           [:TypeDef, :MethodDef],
        Name:            :string,
      },

      # https://github.com/stakx/ecma-335/blob/master/docs/ii.22.29-methodspec-0x2b.md
      MethodSpec: {
        Method:          [:MethodDef, :MemberRef],
        Instantiation:   :blob,
      },

      # https://github.com/stakx/ecma-335/blob/master/docs/ii.22.21-genericparamconstraint-0x2c.md
      GenericParamConstraint: {
        Owner:           :GenericParam,
        Constraint:      [:TypeDef, :TypeRef, :TypeSpec],
      }
    }

    # needed only for pedump CLI format guessing
    class TablesHash < Hash
    end

    def self._create_dynamic_class fields, hdr, name: nil
      decl = fields.map do |k,v|
        case v
        when 2
          'S'
        when 4
          'V'
        when :blob
          hdr.HeapSizes & MetadataTableStreamHeader::HEAP_SIZES_MANY_BLOBS != 0 ? 'V' : 'S'
        when :guid
          hdr.HeapSizes & MetadataTableStreamHeader::HEAP_SIZES_MANY_GUIDS != 0 ? 'V' : 'S'
        when :string
          hdr.HeapSizes & MetadataTableStreamHeader::HEAP_SIZES_MANY_STRINGS != 0 ? 'V' : 'S'
        when Array
          # pointer to table i out of n possible tables
          n = v.size
          bits_for_table_idx = Math.log2(n).ceil
          max_rows = 2**(16 - bits_for_table_idx)
          v.each{ |table_id| raise "Unknown table: #{table_id}" unless hdr.known_table?(table_id) }
          v.any?{ |table_id| hdr.sizes_hash[table_id].to_i >= max_rows } ? 'V' : 'S'
        when Symbol
          raise "Unknown table: #{v}" unless hdr.known_table?(v)
          hdr.sizes_hash[v].to_i < 2**16 ? 'S' : 'V'
        else
          raise "Unknown field type #{v.inspect}"
        end
      end.join
      IOStruct.new(decl, *fields.keys, inspect_name_override: name)
    end
  end # module CLR

  def clr_header f=@io
    return nil unless pe(f) && pe(f).ioh && f

    dir = @pe.ioh.DataDirectory[IMAGE_DATA_DIRECTORY::CLR_Header]
    return nil if !dir || (dir.va == 0 && dir.size == 0)

    file_offset = va2file(dir.va)
    return nil unless file_offset

    if f.checked_seek(file_offset)
      IMAGE_COR20_HEADER.read(f)
    else
      logger.warn "[?] CLR header beyond EOF"
      nil
    end
  end

  def clr_metadata f=@io
    return nil unless clr_header(f)

    dir = clr_header(f).MetaData
    return nil if !dir || (dir.va.to_i == 0 || dir.size.to_i == 0)

    file_offset = va2file(dir.va)
    return nil unless file_offset

    if f.checked_seek(file_offset)
      CLR::MetadataHeader.read(f)
    else
      logger.warn "[?] CLR metadata header beyond EOF"
      nil
    end
  end

  def clr_streams f=@io
    return nil unless metadata = clr_metadata(f)

    streams = []
    metadata.NumberOfStreams.times do
      if stream = CLR::MetadataStreamHeader.read(f)
        streams << stream
      else
        logger.warn "[?] Error reading CLR stream header"
        break
      end
    end
    streams
  end

  def clr_tables table_ids_or_f=nil
    f = @io
    table_ids = nil

    case table_ids_or_f
    when IO
      f = table_ids_or_f
    when String
      table_ids = table_ids_or_f.split(/\W/).map(&:to_sym)
    when Array
      table_ids = table_ids_or_f
    end

    return nil unless clr_streams(f)

    @dynamic_classes ||= {}

    tables = CLR::TablesHash.new
    clr_streams.each do |stream|
      next if stream.name != '#~' && stream.name != '#-' # Metadata Table Stream

      if hdr = CLR::MetadataTableStreamHeader.read(f)
        hdr.sizes_hash.each do |key, nrows|
          raise "Unknown table: #{key}" unless hdr.known_table?(key)

          if fields = CLR::TableDefs[key]
            klass = @dynamic_classes[key] ||= CLR::_create_dynamic_class(fields, hdr, name: key)
            tables[key] = []
            nrows.times do
              tables[key] << klass.read(f)
            end
          else
            logger.warn "[?] Unknown CLR table: #{key}"
          end
        end
      else
        logger.warn "[?] Error reading CLR table stream header"
        break
      end
    end
    # tables are layed out sequentially in the file, so ALL of them should be read first, even if only some are requested
    tables.delete_if{ |k,v| !table_ids.include?(k) } if table_ids
    tables
  end
end
