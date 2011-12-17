class PEdump
  class Packer < Struct.new(:name, :re, :ep_only, :size)

    DATA_ROOT      = File.dirname(File.dirname(File.dirname(__FILE__)))
    BIN_SIGS_FILE  = File.join(DATA_ROOT, "data", "sig.bin")
    TEXT_SIGS_FILES= [
      File.join(DATA_ROOT, "data", "userdb.txt"),
      File.join(DATA_ROOT, "data", "signatures.txt"),
      File.join(DATA_ROOT, "data", "fs.txt")
    ]

    class Match < Struct.new(:offset, :packer)
      def name
        packer.name
      end
    end

    class OrBlock < Array; end

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
              r = parse
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

      # XXX
      # "B\xE9rczi G\xE1bor".force_encoding('binary').to_yaml:
      # RuntimeError: expected SCALAR, SEQUENCE-START, MAPPING-START, or ALIAS

      def _add_sig sigs, sig, args = {}
        raise "null RE: #{sig.inspect}" unless sig.re

        # bad sigs
        return if sig.re[/\A538BD833C0A30:::::/]
        return if sig.name == "Name of the Packer v1.0"
        return if sig.re == "54 68 69 73 20 70 72 6F 67 72 61 6D 20 63 61 6E 6E 6F 74 20 62 65 20 72 75 6E 20 69 6E 20 44 4F 53 20 6D 6F" # dos stub

        sig.name.sub!(/^\*\s+/,    '')
        sig.name.sub!(/\s+\(h\)$/, '')
        sig.name.sub!(/version (\d)/i,"v\\1")
        sig.name.sub!(/Microsoft/i, "MS")
        sig.name.sub!(/ or /i, " / ")
        sig.name.sub! 'RLP ','RLPack '
        sig.name.sub! '.beta', ' beta'
        sig.name.sub! '(com)','[com]'
        sig.name = sig.name.split(/\s*-+>\s*/).join(' -> ') # fix spaces around '->'

        sig.re = sig.re.strip.upcase.tr(':','?')
        sig.re = sig.re.scan(/../).join(' ') if sig.re.split.first.size > 2
        if sigs[sig.re]
          a = [sig, sigs[sig.re]].map{ |x| x.name.upcase.split('->').first.tr('V ','') }
          return if a[0][a[1]] || a[1][a[0]]

          a = [sig, sigs[sig.re]].map{ |x| x.name.split('->').first.split }

          d = [a[0]-a[1], a[1]-a[0]] # different words
          d.map! do |x|
            x - [
              'EXE','[EXE]',
              'vx.x','v?.?',
              'DLL','(DLL)','[DLL]',
              '[LZMA]','(LZMA)','LZMA',
              '-','~','(pack)','(1)','(2)',
              '19??'
            ]
          end
          return if d.all?(&:empty?) # no different words

          # [["(main", "CRT", "Startup)"], ["(_mainCRTStartup)"]]]
          if d[0].size == 1 && d[1].size > 0
            return if d[1].all?{ |x| d[0][0][x.tr('()_','')] }
          elsif d[1].size == 1 && d[0].size > 0
            return if d[0].all?{ |x| d[1][0][x.tr('()_','')] }
          end

          if d.map(&:size) == [1, 1] && false
            old_name = sigs[sig.re].name
            d.flatten!

            # keep old name if it already contains diff substring
            # example: "nbuild v1.0 [soft] / soft"
            return if old_name[d[0]]

            # ignore difference is only in punctuations, dashes, etc
            return if d.map{ |x| x.delete('~()[]-').upcase }.uniq.size == 1

            # MS FORTRAN Library 1901 / 19??
            return if d[1] == '19??'

            new_name = old_name.
              sub('->',' ->').
              split.map do |word|
                if word == d[1]
                  if d[1][d[0]]
                    d[1]            # d[0] is a substring of d[1] => keep d[1]
                  elsif d[0][d[1]]
                    d[0]            # d[1] is a substring of d[0] => keep d[0]
                  else
                    d.sort.join(' / ')
                  end
                else
                  word
                end
              end.join(' ')
            raise "cannot join #{new_name.inspect}, #{d.inspect}" if new_name == old_name
            puts "[.] sig name join: #{new_name}" if args[:verbose]

            sigs[sig.re].name = new_name
            return
          else
            # [["v1.14/v1.20"], ["v1.14,", "v1.20"]]]
            # [["EXEShield", "v0.3b/v0.3", "v0.6"], ["Shield", "v0.3b,", "v0.3"]]]
            2.times do |i|
              return if d[i].all? do |x|
                x = x.downcase.delete(',-').sub(/tm$/,'')
                d[1-i].any? do |y|
                  y = y.downcase.delete(',-').sub(/tm$/,'')
                  y[x]
                end
              end
            end
          end

          a = sigs[sig.re].name.split
          b = sig.name.split
          new_name_head = []
          while a.any? && b.any? && a.first.upcase == b.first.upcase
            new_name_head << a.shift
            b.shift
          end
          new_name_tail = []
          while a.any? && b.any? && a.last.upcase == b.last.upcase
            new_name_tail.unshift a.pop
            b.pop
          end
          new_name = new_name_head
          new_name << [a.join(' '), b.join(' ')].delete_if{|x| x.empty?}.join(' / ')
          new_name += new_name_tail
          new_name = new_name.join(' ')
          puts "[.] sig name join: #{new_name}" if args[:verbose]
          sigs[sig.re].name = new_name
          return
        end
        sigs[sig.re] = sig
      end

      # parse text signatures
      def parse args = {}
        args[:fnames] ||= TEXT_SIGS_FILES
        sigs = {}; sig = nil

        args[:fnames].each do |fname|
          n0 = sigs.size
          File.open(fname,'r:utf-8') do |f|
            while line = f.gets
              case line.strip
              when /^[<;#]/, /^$/ # comments & blank lines
                next
              when /^\[(.+)=(.+)\]$/
                _add_sig(sigs, Packer.new($1, $2, true), args )
              when /^\[([^=]+)\]$/
                sig = Packer.new($1)
              when /^signature = (.+)$/
                sig.re = $1
                _add_sig(sigs, sig, args)
              when /^ep_only = (.+)$/
                sig.ep_only = ($1.strip.downcase == 'true')
              else raise line
              end
            end
          end
          puts "[=] #{sigs.size-n0} sigs from #{File.basename(fname)}\n\n" if args[:verbose]
        end

        # convert strings to Regexps
        sigs = sigs.values
        sigs.each do |sig|
          sig.re =
            sig.re.split(' ').tap do |a|
              sig.size = a.size
            end.map do |x|
              case x
              when /\A\?\?\Z/
                '.'
              when /\A.\?/,/\?.\Z/
                puts "[?] #{x.inspect} -> \"??\" in #{sig.name}"
                '.'
              when /\A[a-f0-9]{2}\Z/i
                x = x.to_i(16).chr
                args[:raw] ? x : Regexp::escape(x)
              else
                puts "[?] unknown re element: #{x.inspect} in #{sig.inspect}" if args[:verbose]
                "BAD_RE"
                break
              end
            end
          if sig.name[/-+>/]
            a = sig.name.split(/-+>/,2).map(&:strip)
            sig.name = "#{a[0]} (#{a[1]})"
          end
          sig.re.pop while sig.re.last == '??'
        end
        sigs.delete_if{ |sig| !sig.re || sig.re.index('BAD_RE') }
        return sigs if args[:raw]

        optimize sigs if args[:optimize]

        # convert re-arrays to Regexps
        sigs.each do |sig|
          sig.re = Regexp.new( _join(sig.re), Regexp::MULTILINE )
        end

        sigs
      end

      def _join a, sep=''
        a.map do |x|
          case x
          when OrBlock
            '(' + _join(x, '|') + ')'
          when Array
            _join x
          when String
            x
          end
        end.join(sep)
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
            a.first.re = merged_re
            a[1..-1].each{ |sig| sig.re = nil }
          end
        end
        print "[.] sigs merge: #{sigs.size}"; sigs.delete_if{ |x| x.re.nil? }; puts  " -> #{sigs.size}"


        # 361 entries of ["VMProtect v1.25 (PolyTech)", true, "h....\xE8...."])
        sigs.group_by{ |sig|
          [sig.name, sig.ep_only, sig.re[0,10].join]
        }.each do |k,entries|
          next if entries.size < 10
          #printf "%5d  %s\n", entries.size, k
          prefix = entries.first.re[0,10]
          infix  = entries.map{ |sig| sig.re[10..-1] }

          entries.first.re   = prefix + [OrBlock.new(infix)]
          entries.first.size = entries.map(&:size).max

          entries[1..-1].each{ |sig| sig.re = nil }
        end
        print "[.] sigs merge: #{sigs.size}"; sigs.delete_if{ |x| x.re.nil? }; puts  " -> #{sigs.size}"


#        # merge signatures with same prefix & suffix
#        # most ineffecient part :)
#        sigs.group_by{ |sig|
#          [sig.name, sig.ep_only, sig.re.index{ |x| x.is_a?(Array)}]
#        }.values.each do |a|
#          next if a.size == 1
#          next unless idx = a.first.re.index{ |x| x.is_a?(Array) }
#          a.group_by{ |sig| [sig.re[0...idx], sig.re[(idx+1)..-1]] }.each do |k,entries|
#            # prefix |            infix          | suffix
#            # s o m    [[b r e r o] [e w h a t]]   h e r e
#            prefix, suffix = k
#            infix = entries.map{ |sig| sig.re[idx] }
#            #infix = [['f','o','o']]
#            merged_re = prefix + infix + suffix
#            max_size = entries.map(&:size).max
#            entries.each{ |sig| sig.re = merged_re; sig.size = max_size }
#          end
#        end
#        print "[.] sigs merge: #{sigs.size}"; sigs.uniq!; puts  " -> #{sigs.size}"

         # stats
#        aa = []
#        6.upto(20) do |len|
#          sigs.group_by{ |sig| [sig.re[0,len].join, sig.name, sig.ep_only] }.each do |a,b|
#            aa << [b.size, a[0], [b.map(&:size).min, b.map(&:size).max].join(' .. ') ] if b.size > 2
#          end
#        end
#        aa.sort_by(&:first).each do |sz,prefix,name|
#          printf "%5d  %-50s %s\n", sz, prefix.inspect, name
#        end

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
        ref[0...diff.first] + [OrBlock.new(res.map{ |re| re[diff] })] + ref[(diff.last+1)..-1]
      end
    end
  end
end
