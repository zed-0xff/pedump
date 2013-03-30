#!/usr/bin/env ruby

require 'iostruct'

class PEdump

  # http://msdn.microsoft.com/en-us/library/windows/desktop/ms680378(v=vs.85).aspx
  class MINIDUMP_HEADER < IOStruct.new 'a4LLLLLQ',
    :Signature,
    :Version,
    :NumberOfStreams,
    :StreamDirectoryRva,
    :CheckSum,
    :TimeDateStamp,
    :Flags

    def valid?
      self.Signature == 'MDMP'
    end
  end

  MINIDUMP_LOCATION_DESCRIPTOR = IOStruct.new 'LL', :DataSize, :Rva

  class MINIDUMP_DIRECTORY < IOStruct.new 'L', :StreamType, :Location
    def self.read io
      r = super
      r.Location = MINIDUMP_LOCATION_DESCRIPTOR.read(io)
      r
    end
  end

  MINIDUMP_MEMORY_INFO = IOStruct.new 'QQLLQLLLL',
    :BaseAddress,
    :AllocationBase,
    :AllocationProtect,
    :__alignment1,
    :RegionSize,
    :State,
    :Protect,
    :Type,
    :__alignment2

  class MINIDUMP_MEMORY_INFO_LIST < IOStruct.new 'LLQ',
    :SizeOfHeader,
    :SizeOfEntry,
    :NumberOfEntries,
    :entries

    def self.read io
      r = super
      r.entries = r.NumberOfEntries.times.map{ MINIDUMP_MEMORY_INFO.read(io) }
      r
    end
  end

  MINIDUMP_MEMORY_DESCRIPTOR64 = IOStruct.new 'QQ',
    :StartOfMemoryRange,
    :DataSize

  class MINIDUMP_MEMORY64_LIST < IOStruct.new 'QQ',
    :NumberOfMemoryRanges,
    :BaseRva,
    :MemoryRanges

    def self.read io
      r = super
      r.MemoryRanges = r.NumberOfMemoryRanges.times.map{ MINIDUMP_MEMORY_DESCRIPTOR64.read(io) }
      r
    end

    def entries; self.MemoryRanges; end
  end

  # http://msdn.microsoft.com/en-us/library/windows/desktop/ms680394(v=vs.85).aspx
  MINIDUMP_STREAM_TYPE = {
         0 => :UnusedStream,
         1 => :ReservedStream0,
         2 => :ReservedStream1,
         3 => :ThreadListStream,
         4 => :ModuleListStream,
         5 => :MemoryListStream,
         6 => :ExceptionStream,
         7 => :SystemInfoStream,
         8 => :ThreadExListStream,
         9 => :Memory64ListStream,           # MINIDUMP_MEMORY64_LIST
        10 => :CommentStreamA,
        11 => :CommentStreamW,
        12 => :HandleDataStream,
        13 => :FunctionTableStream,
        14 => :UnloadedModuleListStream,
        15 => :MiscInfoStream,
        16 => :MemoryInfoListStream,         # MINIDUMP_MEMORY_INFO_LIST
        17 => :ThreadInfoListStream,
        18 => :HandleOperationListStream,
    0xffff => :LastReservedStream
  }

  class Loader
    class Minidump
      attr_accessor :hdr, :streams, :io

      def initialize io
        @io = io
        @hdr = MINIDUMP_HEADER.read(@io)
        raise "invalid minidump" unless @hdr.valid?
      end

      def streams
        @streams ||=
          begin
            @io.seek(@hdr.StreamDirectoryRva)
            @hdr.NumberOfStreams.times.map do
              dir = MINIDUMP_DIRECTORY.read(io)
              dir.Location.empty? ? nil : dir
            end.compact
          end
      end

      def memory_info_list
        # MINIDUMP_MEMORY_INFO_LIST
        stream = streams.find{ |s| s.StreamType == 16 }
        return nil unless stream
        io.seek stream.Location.Rva
        MINIDUMP_MEMORY_INFO_LIST.read io
      end

      def memory_list
        # MINIDUMP_MEMORY64_LIST
        stream = streams.find{ |s| s.StreamType == 9 }
        return nil unless stream
        io.seek stream.Location.Rva
        MINIDUMP_MEMORY64_LIST.read io
      end

      MemoryRange = Struct.new :file_offset, :va, :size

      # set options[:merge] = true to merge adjacent memory ranges
      def memory_ranges options = {}
        ml = memory_list
        file_offset = ml.BaseRva
        r = []
        if options[:merge]
          ml.entries.each do |x|
            if r.last && r.last.va + r.last.size == x.StartOfMemoryRange
              # if section VA == prev_section.VA + prev_section.SIZE
              # then just increase the size of previous section
              r.last.size += x.DataSize
            else
              r << MemoryRange.new( file_offset, x.StartOfMemoryRange, x.DataSize )
            end
            file_offset += x.DataSize
          end
        else
          ml.entries.each do |x|
            r << MemoryRange.new( file_offset, x.StartOfMemoryRange, x.DataSize )
            file_offset += x.DataSize
          end
        end
        r
      end

    end # class Minidump
  end # class Loader
end # module PEdump

##############################################

if $0 == __FILE__
  require 'pp'

  raise "gimme a fname" if ARGV.empty?
  io = open(ARGV.first,"rb")

  md = PEdump::Loader::Minidump.new io
  pp md.hdr
  puts
  puts "[.] #{md.memory_ranges.size} memory ranges"
  puts "[.] #{md.memory_ranges(:merge => true).size} merged memory ranges"
  puts

#  pp md.memory_info_list
#  pp md.memory_list

  md.memory_ranges(:merge => true).each do |mr|
    printf "[.] %8x %8x %8x\n", mr.file_offset, mr.va, mr.size
  end
end
