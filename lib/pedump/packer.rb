class PEdump
  class Packer < Struct.new(:name, :re, :ep_only, :size)

    DATA_ROOT      = File.dirname(File.dirname(File.dirname(__FILE__)))
    BIN_SIGS_FILE  = File.join(DATA_ROOT, "data", "sig.bin")
    TEXT_SIGS_FILE = File.join(DATA_ROOT, "data", "sig.txt")

    Match = Struct.new :offset, :packer

    class << self

      def all
        @@all ||=
          begin
            r = unmarshal
            unless r
              if PEdump.respond_to?(:logger) && PEdump.logger
                PEdump.logger.warn "[?] #{self}: unmarshal failed, using slow text parsing instead"
              else
                STDERR.puts "[?] #{self}: unmarshal failed, using slow text parsing instead"
              end
              r = parse
            end
            r
          end
      end
      alias :load :all

      def max_size
        @@max_size ||= all.map(&:size).max
      end

      def of data, ep_offset = nil
        if data.respond_to?(:read) && data.respond_to?(:seek) && ep_offset
          of_file data, ep_offset
        else
          of_data data
        end
      end

      # try to determine packer of FILE f, ep_offset - offset to entrypoint from start of file
      def of_file f, ep_offset
        f.seek(ep_offset)
        of_data f.read(max_size)
      end

      def of_data data
        r = nil
#        r = find_all{ |packer| data.index(packer.re) != nil }
#        r.any?? r : nil
        each do |packer|
          if idx=data.index(packer.re)
            r ||= []
            r << Match.new(idx, packer)
          end
        end
        r
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

      # parse text signatures
      def parse fname = TEXT_SIGS_FILE
        sigs = {}; sig = nil

        File.open(fname,'r:utf-8') do |f|
          while line = f.gets
            line.strip!

            # XXX
            # "B\xE9rczi G\xE1bor".force_encoding('binary').to_yaml:
            # RuntimeError: expected SCALAR, SEQUENCE-START, MAPPING-START, or ALIAS

            case line
            when /^;/,/^$/
              next
            when /^\[(.+)\]$/
              sig = Packer.new($1.sub(/^\*\s+/,'').sub(/\s+\(h\)$/,''))
            when /^signature = (.+)$/
              sig.re = $1
              if sigs[sig.re]
                next if sigs[sig.re].name == sig.name
                printf "[?] dup %-40s, %s\n", sigs[sig.re].name.inspect, sig.name.inspect
              end
              sigs[sig.re] = sig
            when /^ep_only = (.+)$/
              sig.ep_only = ($1.strip.downcase == 'true')
            else raise line
            end
          end
        end

        sigs = sigs.values
        sigs.each do |sig|
          sig.re = Regexp.new(
            sig.re.split(' ').tap do |a|
              sig.size = a.size
            end.map do |x|
              case x
              when '??'
                '.'
              when /[a-f0-9]{2}/i
                Regexp::escape x.to_i(16).chr
              else raise x
              end
            end.join
          )
        end
        sigs
      end
    end
  end
end
