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

  MINIDUMP_MEMORY_DESCRIPTOR = IOStruct.new 'QLL',
    :StartOfMemoryRange,
    :DataSize,
    :Rva

  class MINIDUMP_MEMORY_LIST < IOStruct.new 'L',
    :NumberOfMemoryRanges,
    :MemoryRanges

    def self.read io
      r = super
      r.MemoryRanges = r.NumberOfMemoryRanges.times.map{ MINIDUMP_MEMORY_DESCRIPTOR.read(io) }
      r
    end

    def entries; self.MemoryRanges; end
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
         5 => :MemoryListStream,             # MINIDUMP_MEMORY_LIST
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
    0xffff => :LastReservedStream,

    # Special types saved by google breakpad
    # https://chromium.googlesource.com/breakpad/breakpad/+/846b6335c5b0ba46dfa2ed96fccfa3f7a02fa2f1/src/google_breakpad/common/minidump_format.h#311
    0x47670001 => :BreakpadInfoStream,
    0x47670002 => :BreakpadAssertionInfoStream,
    0x47670003 => :BreakpadLinuxCpuInfo,
    0x47670004 => :BreakpadLinuxProcStatus,
    0x47670005 => :BreakpadLinuxLsbRelease,
    0x47670006 => :BreakpadLinuxCmdLine,
    0x47670007 => :BreakpadLinuxEnviron,
    0x47670008 => :BreakpadLinuxAuxv,
    0x47670009 => :BreakpadLinuxMaps,
    0x4767000A => :BreakpadLinuxDsoDebug
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

      def stream_by_name(name)
        type = MINIDUMP_STREAM_TYPE.invert[name]
        raise "Unknown type symbol #{name}!" if !type

        streams.find { |s| s.StreamType == type }
      end

      def memory_info_list
        # MINIDUMP_MEMORY_INFO_LIST
        stream = stream_by_name(:MemoryInfoListStream)
        return nil unless stream
        io.seek stream.Location.Rva
        MINIDUMP_MEMORY_INFO_LIST.read io
      end

      def memory_list
        # MINIDUMP_MEMORY_LIST
        stream = stream_by_name(:MemoryListStream)
        return nil unless stream
        io.seek stream.Location.Rva
        MINIDUMP_MEMORY_LIST.read io
      end

      def memory64_list
        # MINIDUMP_MEMORY64_LIST
        stream = stream_by_name(:Memory64ListStream)
        return nil unless stream
        io.seek stream.Location.Rva
        MINIDUMP_MEMORY64_LIST.read io
      end

      MemoryRange = Struct.new :file_offset, :va, :size

      # set options[:merge] = true to merge adjacent memory ranges
      def memory_ranges options = {}
        if memory64_list
          ml = memory64_list
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
          return r
        elsif memory_list
          ml = memory_list
          r = []
          if options[:merge]
            ml.entries.each do |x|
              if r.last && r.last.va + r.last.size == x.StartOfMemoryRange
                # if section VA == prev_section.VA + prev_section.SIZE
                # then just increase the size of previous section
                r.last.size += x.DataSize
              else
                r << MemoryRange.new( x.Rva, x.StartOfMemoryRange, x.DataSize )
              end
            end
          else
            ml.entries.each do |x|
              r << MemoryRange.new( x.Rva, x.StartOfMemoryRange, x.DataSize )
            end
          end
          return r
        else
          raise "Could not find memory ranges"
        end
      end

    end # class Minidump
  end # class Loader
end # module PEdump

##############################################

if $0 == __FILE__
  require 'pp'
  require 'optparse'

  options = {}
  opt_parse = OptionParser.new do |opts|
    opts.banner = "Usage: #{$0} [options] <minidump>"

    opts.on("--all", "Print all of the following sections") do
      options[:all] = true
    end
    opts.on("--header", "Print minidump header") do
      options[:header] = true
    end
    opts.on("--streams", "Print out the streams present") do
      options[:streams] = true
    end
    opts.on("--memory-ranges", "Print out memory ranges included in the minidump") do
      options[:memory_ranges] = true
    end
    opts.on("--breakpad", "Print out breakpad text sections if present") do
      options[:breakpad] = true
    end
    opts.separator ''

    opts.on("--memory <address>", "Print the memory range beginning at address") do |m|
      options[:memory] = m.hex
    end
    opts.separator ''

    opts.on("-h", "--help", "Help") do
      puts opts
      exit 0
    end
  end

  opt_parse.parse!

  if ARGV.empty?
    $stderr.puts opt_parse.help
    exit 1
  end

  io = open(ARGV.first, "rb")
  md = PEdump::Loader::Minidump.new io

  if options[:all] || options[:header]
    pp md.hdr
    puts
  end

  if options[:all] || options[:streams]
    puts "[.] Streams present in the minidump:"
    md.streams.each do |s|
      if s.StreamType
        puts "[.] #{PEdump::MINIDUMP_STREAM_TYPE[s.StreamType]}"
      else
        puts "[.] Unknown stream type #{s.StreamType}"
      end
    end
    puts
  end

  if options[:all] || options[:breakpad]
    [ :BreakpadLinuxCpuInfo, :BreakpadLinuxProcStatus, :BreakpadLinuxMaps,
      :BreakpadLinuxCmdLine, :BreakpadLinuxEnviron ].each { |name|
      stream = md.stream_by_name(name)
      next if !stream

      io.seek stream.Location.Rva
      contents = io.read(stream.Location.DataSize)

      if contents !~ /[^[:print:][:space:]]/
        puts "[.] Section #{name}:"
        puts contents
      else
        puts "[.] Section #{name}: #{contents.inspect}"
      end
      puts
    }
  end

  if options[:all] || options[:memory_ranges]
    puts "[.] #{md.memory_ranges.size} memory ranges"
    puts "[.] #{md.memory_ranges(:merge => true).size} merged memory ranges"
    puts

    printf "[.] %16s %8s\n", "addr", "size"
    md.memory_ranges(:merge => true).sort_by { |mr| mr.va }.each do |mr|
      printf "[.] %16x %8x\n", mr.va, mr.size
    end
  end

  if options[:memory]
    mr = md.memory_ranges(:merge => true).find { |r| r.va == options[:memory] }
    raise "Could not find the specified region" if !mr

    io.seek(mr.file_offset)
    print io.read(mr.size)
  end
end
