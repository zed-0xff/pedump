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

      # parse text signatures
      def parse args = {}
        args[:fname] ||= TEXT_SIGS_FILE
        sigs = {}; sig = nil

        File.open(args[:fname],'r:utf-8') do |f|
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

        # convert strings to Regexps
        sigs = sigs.values
        sigs.each do |sig|
          sig.re = ( #Regexp.new(
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
            end
          )
          if sig.name[/-+>/]
            a = sig.name.split(/-+>/,2).map(&:strip)
            sig.name = "#{a[0]} (#{a[1]})"
          end
        end

        # false signature
        sigs.delete_if{ |sig| sig.re == /This\ program\ cannot\ be\ run\ in\ DOS\ mo/ }

        optimize sigs if args[:optimize]

        # convert re-arrays to Regexps
        sigs.each do |sig|
          sig.re = Regexp.new(
            sig.re.map do |x|
              if x.is_a?(Array)
                [ '(', x.map(&:join).join('|'), ')' ]
              else
                x
              end
            end.flatten.join, Regexp::MULTILINE
          )
        end

        sigs
      end

      def optimize sigs
        # replaces all duplicate names with references to one name
        # saves ~30k out of ~200k mem
        h = {}
        sigs.each do |sig|
          sig.name = (h[sig.name] ||= sig.name)
        end

        # try to merge signatures with same name, size & ep_only
        sigs.group_by{ |sig|
          [sig.re.size, sig.name, sig.ep_only]
        }.values.each do |a|
          next if a.size == 1
          if merged_re = _merge(a)
            a.each{ |sig| sig.re = merged_re }
          end
        end

        print "[.] sigs merge: #{sigs.size}"
        sigs.uniq!
        puts  " -> #{sigs.size}"

        # merge signatures with same prefix & suffix
        # most ineffecient part :)
        sigs.group_by{ |sig|
          [sig.name, sig.ep_only, sig.re.index{ |x| x.is_a?(Array)}]
        }.values.each do |a|
          next if a.size == 1
          next unless idx = a.first.re.index{ |x| x.is_a?(Array) }
          a.group_by{ |sig| [sig.re[0...idx], sig.re[(idx+1)..-1]] }.each do |k,v|
            # prefix |            infix          | suffix
            # s o m    [[b r e r o] [e w h a t]]   h e r e
            prefix, suffix = k
            infix = v.map{ |sig| sig.re[idx] }
            #infix = [['f','o','o']]
            merged_re = prefix + infix + suffix
            v.each{ |sig| sig.re = merged_re; sig.size = v.map(&:size).max }
          end
        end

        print "[.] sigs merge: #{sigs.size}"
        sigs.uniq!
        puts  " -> #{sigs.size}"

        sigs
      end

      # range of common difference between N given sigs
      def _diff res
        raise "diff sizes" if res.map(&:size).uniq.size != 1
        size = res.first.size

        dstart  = nil
        dend    = size - 1
        prev_eq = true

        size.times do |i|
          eq = res.map{ |re| re[i] }.uniq.size == 1
          if eq != prev_eq
            if eq
              # end of current diff
              dend = i-1
            else
              # start of new diff
              return nil if dstart # return nil if it's a 2nd diff
              dstart = i
            end
          end
          prev_eq = eq
        end
        r = dstart..dend
        r == (0..(size-1)) ? nil : r
      end

      # merge array of signatures into one signature
      def _merge sigs
        sizes = sigs.map(&:re).map(&:size)

        if sizes.uniq.size != 1
          puts "[?] wrong sizes: #{sizes.inspect}"
          return nil
        end

        res = sigs.map(&:re)
        diff = _diff res
        return nil unless diff

        ref = res.first
        ref[0...diff.first] + [res.map{ |re| re[diff] }] + ref[(diff.last+1)..-1]
      end
    end
  end
end
