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
        Module:                   0x1,
        TypeRef:                  0x2,
        TypeDef:                  0x4,
        FiedPtr:                  0x8,
        Field:                    0x10,
        MethodPtr:                0x20,
        MethodDef:                0x40,
        ParamPtr:                 0x80,
        Param:                    0x100,
        InterfaceImpl:            0x200,
        MemberRef:                0x400,
        Constant:                 0x800,
        CustomAttribute:          0x1000,
        FieldMarshal:             0x2000,
        DeclSecurity:             0x4000,
        ClassLayout:              0x8000,
        FieldLayout:              0x10000,
        StandAloneSig:            0x20000,
        EventMap:                 0x40000,
        EventPtr:                 0x80000,
        Event:                    0x100000,
        PropertyMap:              0x200000,
        PropertyPtr:              0x400000,
        Property:                 0x800000,
        MethodSemantics:          0x1000000,
        MethodImpl:               0x2000000,
        ModuleRef:                0x4000000,
        TypeSpec:                 0x8000000,
        ImplMap:                  0x10000000,
        FieldRVA:                 0x20000000,
        EnCLog:                   0x40000000,
        EnCMap:                   0x80000000,
        Assembly:                 0x100000000,
        AssemblyProcessor:        0x200000000,
        AssemblyOS:               0x400000000,
        AssemblyRef:              0x800000000,
        AssemblyRefProcessor:     0x1000000000,
        AssemblyRefOS:            0x2000000000,
        File:                     0x4000000000,
        ExportedType:             0x8000000000,
        ManifestResource:         0x10000000000,
        NestedClass:              0x20000000000,
        GenericParam:             0x40000000000,
        MethodSpec:               0x80000000000,
        GenericParamConstraint:   0x100000000000,
        Document:                 0x1000000000000,
        MethodDebugInformation:   0x2000000000000,
        LocalScope:               0x4000000000000,
        LocalVariable:            0x8000000000000,
        LocalConstant:            0x10000000000000,
        ImportScope:              0x20000000000000,
        StateMachineMethod:       0x40000000000000,
        CustomDebugInformation:   0x80000000000000,
      }
      INVERSE_FLAGS = FLAGS.invert

      def known_table? key
        FLAGS.key?(key)
      end

      def valid_flags
        FLAGS.find_all{ |k,v| (self.Valid & v) != 0 }.map(&:first)
      end

      def sorted_flags
        FLAGS.find_all{ |k,v| (self.Sorted & v) != 0 }.map(&:first)
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
              key = INVERSE_FLAGS[idx].to_sym
              r.sizes_hash[key] = io.read(4).unpack1('V')
            end
            n >>= 1
            idx <<= 1
          end
          r.Rows = r.sizes_hash.values
        end
      end
    end

    # reference types
    # https://github.com/stakx/ecma-335/blob/master/docs/ii.24.2.6-metadata-stream.md
    CustomAttributeType = [:not_used, :not_used, :MethodDef, :MemberRef, :not_used] # see spec. last :not used is important for it to be 3 bits in size
    HasConstant         = [:Field, :Param, :Property]
    HasCustomAttribute  = [:MethodDef, :Field, :TypeRef, :TypeDef, :Param, :InterfaceImpl, :MemberRef, :Module, :DeclSecurity, :Property, :Event, :StandAloneSig, :ModuleRef, :TypeSpec, :Assembly, :AssemblyRef, :File, :ExportedType, :ManifestResource, :GenericParam, :GenericParamConstraint, :MethodSpec] # XXX not checked thoroughly
    HasDeclSecurity     = [:TypeDef, :MethodDef, :Assembly]
    HasFieldMarshal     = [:Field, :Param]
    HasSemantics        = [:Event, :Property]
    Implementation      = [:File, :AssemblyRef, :ExportedType]
    MemberForwarded     = [:Field, :MethodDef]
    MemberRefParent     = [:TypeDef, :TypeRef, :ModuleRef, :MethodDef, :TypeSpec]
    MethodDefOrRef      = [:MethodDef, :MemberRef]
    ResolutionScope     = [:Module, :ModuleRef, :AssemblyRef, :TypeRef]
    TypeDefOrRef        = [:TypeDef, :TypeRef, :TypeSpec]
    TypeOrMethodDef     = [:TypeDef, :MethodDef]

    module DynTableMethods
      def get_name(strings)
        h = self.to_h
        if h[:TypeNamespace] || h[:TypeName]
          if h[:TypeNamespace] != 0
            "#{strings[h[:TypeNamespace]]}.#{strings[h[:TypeName]]}"
          else
            strings[h[:TypeName]]
          end
        elsif h[:Name]
          strings[h[:Name]]
        elsif h[:ImportName]
          strings[h[:ImportName]]
        else
          nil
        end
      end
    end

    TableDefs = {
      # undocumented?
      FieldPtr: { Field: :Field },
      MethodPtr: { Method: :MethodDef },
      ParamPtr: { Param: :Param },
      EventPtr: { Event: :Event },
      PropertyPtr: { Property: :Property },

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
        ResolutionScope: ResolutionScope,
        TypeName:        :string,
        TypeNamespace:   :string,
      },

      # https://github.com/stakx/ecma-335/blob/master/docs/ii.22.37-typedef-0x02.md
      TypeDef: {
        Flags:           4,        # a 4-byte bitmask of TypeAttributes
        TypeName:        :string,
        TypeNamespace:   :string,
        Extends:         TypeDefOrRef,
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
        Interface:       TypeDefOrRef,
      },

      # https://github.com/stakx/ecma-335/blob/master/docs/ii.22.25-memberref-0x0a.md
      MemberRef: {
        Class:           MemberRefParent,
        Name:            :string,
        Signature:       :blob,
      },

      # https://github.com/stakx/ecma-335/blob/master/docs/ii.22.9-constant-0x0b.md
      Constant: {
        Type:            2,        # a 1-byte constant, followed by a 1-byte padding zero
        Parent:          HasConstant,
        Value:           :blob,
      },

      # https://github.com/stakx/ecma-335/blob/master/docs/ii.22.10-customattribute-0x0c.md
      CustomAttribute: {
        Parent:          HasCustomAttribute,
        Type:            CustomAttributeType,
        Value:           :blob,
      },

      # https://github.com/stakx/ecma-335/blob/master/docs/ii.22.17-fieldmarshal-0x0d.md
      FieldMarshal: {
        Parent:          HasFieldMarshal,
        NativeType:      :blob,
      },

      # https://github.com/stakx/ecma-335/blob/master/docs/ii.22.11-declsecurity-0x0e.md
      DeclSecurity: {
        Action:          2,        # a 2-byte constant
        Parent:          HasDeclSecurity,
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
        EventType:       TypeDefOrRef,
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
        Association:     HasSemantics,
      },

      # https://github.com/stakx/ecma-335/blob/master/docs/ii.22.27-methodimpl-0x19.md
      MethodImpl: {
        Class:             :TypeDef,
        MethodBody:        MethodDefOrRef,
        MethodDeclaration: MethodDefOrRef,
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
        MemberForwarded: MemberForwarded,
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
        Implementation:  Implementation,
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
        Owner:           TypeOrMethodDef,
        Name:            :string,
      },

      # https://github.com/stakx/ecma-335/blob/master/docs/ii.22.29-methodspec-0x2b.md
      MethodSpec: {
        Method:          MethodDefOrRef,
        Instantiation:   :blob,
      },

      # https://github.com/stakx/ecma-335/blob/master/docs/ii.22.21-genericparamconstraint-0x2c.md
      GenericParamConstraint: {
        Owner:           :GenericParam,
        Constraint:      TypeDefOrRef,
      }
    }

    # needed only for pedump CLI format guessing
    class TablesHash < Hash; end
    class StringsHash < Hash; end

    def self._create_dynamic_class fields, hdr, name: nil
      table_idx_bits = {}
      string_keys = []

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
          string_keys << k
          hdr.HeapSizes & MetadataTableStreamHeader::HEAP_SIZES_MANY_STRINGS != 0 ? 'V' : 'S'
        when Array
          # pointer to table i out of n possible tables
          n = v.size
          table_idx_bits[k] = bits_for_table_idx = Math.log2(n).ceil
          max_rows = 2**(16 - bits_for_table_idx)
          v.each{ |table_id| raise "Unknown table: #{table_id}" unless table_id == :not_used || hdr.known_table?(table_id) }
          v.any?{ |table_id| hdr.sizes_hash[table_id].to_i >= max_rows } ? 'V' : 'S'
        when Symbol
          raise "Unknown table: #{v}" unless hdr.known_table?(v)
          hdr.sizes_hash[v].to_i < 2**16 ? 'S' : 'V'
        else
          raise "Unknown field type #{v.inspect}"
        end
      end.join

      IOStruct.new(decl, *fields.keys, inspect_name_override: name).tap do |klass|
        klass.const_set(:STRING_KEYS, string_keys)
        klass.include(DynTableMethods)
        fields.each do |k,v|
          case v
          when Array
            # define 'decode_...' method
            idx_bits = table_idx_bits[k]
            table_id_mask = (1 << idx_bits) - 1
            klass.instance_eval do
              define_method("decode_#{k}") do
                val = self[k]
                table_id = val & table_id_mask
                table_key = v[table_id]
                val >>= idx_bits
                [table_key, val]
              end
            end
          end
        end
      end
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

    dir = clr_header(f)&.MetaData
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

  def clr_strings f=@io
    return nil unless dir = clr_header(f)&.MetaData
    return nil unless streams = clr_streams(f)

    strings = CLR::StringsHash.new
    streams.each do |stream|
      next unless stream.name == '#Strings'

      unless f.checked_seek(va2file(dir.va) + stream.offset)
        logger.warn "[?] Error seeking to CLR strings stream"
        return nil
      end
      pos = 0
      while pos < stream.size && !f.eof?
        s = f.gets("\0")
        break unless s

        ssize = s.bytesize
        s.chomp!("\0")
        s.force_encoding('utf-8')
        strings[pos] = s
        pos += ssize
      end

      break
    end
    strings
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

    return nil unless dir = clr_header(f)&.MetaData
    return nil unless streams = clr_streams(f)

    @dynamic_classes ||= {}

    tables = CLR::TablesHash.new
    streams.each do |stream|
      next if stream.name != '#~' && stream.name != '#-' # Metadata Table Stream

      unless f.checked_seek(va2file(dir.va) + stream.offset)
        logger.warn "[?] Error seeking to CLR table stream"
        return nil
      end

      if hdr = CLR::MetadataTableStreamHeader.read(f)
        hdr.sizes_hash.each do |key, nrows|
          raise "Unknown table: #{key}" unless hdr.known_table?(key)

          if fields = CLR::TableDefs[key]
            klass = @dynamic_classes[key] ||= CLR::_create_dynamic_class(fields, hdr, name: key)
            tables[key] = [nil] # 1-based index, 0-th element is NULL
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
