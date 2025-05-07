#!/usr/bin/env ruby
#coding: binary

# https://github.com/dotnet/runtime/blob/main/docs/design/coreclr/botr/readytorun-format.md
class PEdump
  module CLR
    class READYTORUN_HEADER < IOStruct.new(
      'LSS',

      :Signature,
      :MajorVersion,
      :MinorVersion,
      :CoreHeader    # READYTORUN_CORE_HEADER - dynamic size!
    )

      MAGIC = 0x00525452 # 'RTR\0'

      def valid?
        self.Signature == MAGIC
      end

      def self.read io
        super.tap do |r|
          r.CoreHeader = READYTORUN_CORE_HEADER.read(io)
        end
      end
    end

    class READYTORUN_CORE_HEADER < IOStruct.new('LL', :Flags, :NumberOfSections, :Sections)
      FLAGS = {
        0x01 => 'PLATFORM_NEUTRAL_SOURCE',    # Set if the original IL image was platform neutral. The platform neutrality is part of assembly name. This flag can be used to reconstruct the full original assembly name.
        0x02 => 'COMPOSITE',                  # The image represents a composite R2R file resulting from a combined compilation of a larger number of input MSIL assemblies.
        0x04 => 'PARTIAL',
        0x08 => 'NONSHARED_PINVOKE_STUBS',    # PInvoke stubs compiled into image are non-shareable (no secret parameter)
        0x10 => 'EMBEDDED_MSIL',              # Input MSIL is embedded in the R2R image.
        0x20 => 'COMPONENT',                  # is a component assembly of a composite R2R image
        0x40 => 'MULTIMODULE_VERSION_BUBBLE', # has multiple modules within its version bubble (For versions before version 6.3, all modules are assumed to possibly have this characteristic)
        0x80 => 'UNRELATED_R2R_CODE'          # has code in it that would not be naturally encoded into this module
      }

      def flags
        FLAGS.find_all{ |k,v| (self.Flags & k) != 0 }.map(&:last)
      end

      def self.read io
        super.tap do |r|
          r.Sections = r.NumberOfSections.times.map do
            READYTORUN_SECTION.read(io)
          end
        end
      end
    end

    # https://github.com/dotnet/runtime/blob/main/docs/design/coreclr/botr/readytorun-format.md#readytorun_section
    class READYTORUN_SECTION < IOStruct.new('L',
                                            :Type,
                                            :Section # IMAGE_DATA_DIRECTORY
                                           )

      SECTION_TYPES = {
        100 => "CompilerIdentifier",        # Image
        101 => "ImportSections",            # Image
        102 => "RuntimeFunctions",          # Image
        103 => "MethodDefEntryPoints",      # Assembly
        104 => "ExceptionInfo",             # Assembly
        105 => "DebugInfo",                 # Assembly
        106 => "DelayLoadMethodCallThunks", # Assembly
        107 => "AvailableTypes",            # (obsolete - used by an older format)
        108 => "AvailableTypes",            # Assembly
        109 => "InstanceMethodEntryPoints", # Image
        110 => "InliningInfo",              # Assembly (added in V2.1)
        111 => "ProfileDataInfo",           # Image (added in V2.2)
        112 => "ManifestMetadata",          # Image (added in V2.3)
        113 => "AttributePresence",         # Assembly (added in V3.1)
        114 => "InliningInfo2",             # Image (added in V4.1)
        115 => "ComponentAssemblies",       # Image (added in V4.1)
        116 => "OwnerCompositeExecutable",  # Image (added in V4.1)
        117 => "PgoInstrumentationData",    # Image (added in V5.2)
        118 => "ManifestAssemblyMvids",     # Image (added in V5.3)
        119 => "CrossModuleInlineInfo",     # Image (added in V6.3)
        120 => "HotColdMap",                # Image (added in V8.0)
        121 => "MethodIsGenericMap",        # Assembly (Added in V9.0)
        122 => "EnclosingTypeMap",          # Assembly (Added in V9.0)
        123 => "TypeGenericInfoMap",        # Assembly (Added in V9.0)
      }

      def to_s
        "<%s Type=%3d va=%8x size=%8x>  %s" % [self.class, self.Type, self.Section.va, self.Section.size, SECTION_TYPES[self.Type] || "?"]
      end

      def self.read io
        super.tap do |r|
          r.Section = IMAGE_DATA_DIRECTORY.read(io)
        end
      end
    end
  end # module CLR

  def clr_readytorun f=@io
    return nil unless hdr = clr_header(f)

    dir = hdr.ManagedNativeHeader
    return nil if !dir || (dir.va.to_i == 0 && dir.size.to_i == 0)

    file_offset = va2file(dir.va)
    return nil unless file_offset

    f.seek(file_offset)
    magic = f.read(4).unpack1('L')
    return nil if magic != CLR::READYTORUN_HEADER::MAGIC

    f.seek(file_offset)
    CLR::READYTORUN_HEADER.read(f)
  end
end
