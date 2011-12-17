require 'pedump/sig_parser'

class PEdump
  class Packer < Struct.new(:name, :re, :ep_only, :size)

    DATA_ROOT      = File.dirname(File.dirname(File.dirname(__FILE__)))
    BIN_SIGS_FILE  = File.join(DATA_ROOT, "data", "sig.bin")

    class Match < Struct.new(:offset, :packer)
      def name
        packer.name
      end
    end

    class << self
      def all
        @@all ||=
          begin
            r = unmarshal
            unless r
              msg = "[?] #{self}: unmarshal failed, using slow text parsing instead"
              if PEdump.respond_to?(:logger) && PEdump.logger
                PEdump.logger.warn msg
              else
                STDERR.puts msg
              end
              r = SigParser.parse
            end
            r
          end
      end
      alias :load :all

      # default deep-scan flag
      @@deep = false

      def default_deep
        @@deep
      end

      def default_deep= value
        @@deep = value
      end

      def max_size
        @@max_size ||= all.map(&:size).max
      end

      def of data, h = {}
        if data.respond_to?(:read) && data.respond_to?(:seek) && h[:ep_offset]
          of_pe_file data, h
        else
          of_data data
        end
      end

      # try to determine packer of FILE f, ep_offset - offset to entrypoint from start of file
      def of_pe_file f, h
        h[:deep] = @@deep unless h.key?(:deep)
        f.seek(h[:ep_offset])             # offset of PE EntryPoint from start of file
        r = of_data f.read(max_size)
        return r if r && r.any?
        scan_whole_file(f, h[:deep] ? nil : 1048576) # scan only 1st mb unless :deep
      end

      BLOCK_SIZE = 0x10000

      def scan_whole_file f, limit = nil
        limit ||= f.size
        f.seek( pos = 0 )
        buf = ''.force_encoding('binary')
        sigs = self.find_all{ |sig| !sig.ep_only }
        r = []
        while true
          f.read BLOCK_SIZE, buf
          pos += buf.size
          sigs.each do |sig|
            if idx = buf.index(sig.re)
              r << Match.new(f.tell-buf.size+idx, sig)
            end
          end
          break if f.eof? || pos >= limit
          # overlap the read for the case when read buffer boundary breaks signature
          f.seek -max_size-2, IO::SEEK_CUR
          pos -= (max_size+2)
        end
        r
      end

      def of_data data
        r = []
        each do |packer|
          if (idx=data.index(packer.re)) == 0
            r << Match.new(idx, packer)
          end
        end
        r.any? ? r.sort_by{ |x| -x.packer.size } : nil
      end

      def method_missing *args, &block
        all.respond_to?(args.first) ? all.send(*args,&block) : super
      end

      def unmarshal
        File.open(BIN_SIGS_FILE,"rb") do |f|
          Marshal.load(f)
        end
      rescue
        nil
      end

    end
  end
end
