class PEdump
  module SigParser

    DATA_ROOT       = File.dirname(File.dirname(File.dirname(__FILE__)))

    TEXT_SIGS_FILES = [
      File.join(DATA_ROOT, "data", "userdb.txt"),
      File.join(DATA_ROOT, "data", "signatures.txt"),
      File.join(DATA_ROOT, "data", "jc-userdb.txt"),
      File.join(DATA_ROOT, "data", "fs.txt"),         # has special parse options!
    ]

    SPECIAL_PARSE_OPTIONS = {
      File.join(DATA_ROOT, "data", "fs.txt") => {:fix1 => true}
    }

    class OrBlock < Array; end

    class << self

      # parse text signatures
      def parse args = {}
        args[:fnames] ||= TEXT_SIGS_FILES
        sigs = {}; sig = nil

        args[:fnames].each do |fname|
          n0 = sigs.size; add_sig_args = args.dup
          add_sig_args.merge!(SPECIAL_PARSE_OPTIONS[fname] || {})
          File.open(fname,'r:utf-8') do |f|
            while line = f.gets
              case line.strip
              when /^[<;#]/, /^$/ # comments & blank lines
                next
              when /^\[(.+)=(.+)\]$/
                _add_sig(sigs, Packer.new($1, $2, true), add_sig_args )
              when /^\[([^=]+)\](\s+\/\/.+)?$/
                sig = Packer.new($1)
              when /^signature = (.+)$/
                sig.re = $1
                _add_sig(sigs, sig, add_sig_args)
              when /^ep_only = (.+)$/
                sig.ep_only = ($1.strip.downcase == 'true')
              else raise line
              end
            end
          end
          puts "[=] #{sigs.size-n0} sigs from #{File.basename(fname)}\n\n" if args[:verbose]
        end

        bins = Hash.new{ |k,v| k[v] = ''.force_encoding('binary') }

        # convert strings to Regexps
        sigs = sigs.values
        sigs.each_with_index do |sig,idx|
          sig.re =
            sig.re.split(' ').tap do |a|
              sig.size = a.size
            end.map do |x|
              case x
              when /\A\?\?\Z/
                bins[sig] << '.'
                '.'
              when /\A.\?/,/\?.\Z/
                puts "[?] #{x.inspect} -> \"??\" in #{sig.name}" if args[:verbose]
                bins[sig] << '.'
                '.'
              when /\A[a-f0-9]{2}\Z/i
                x = x.to_i(16).chr
                bins[sig] << x
                if args[:raw]
                  x
                elsif args[:raword]
                  x.ord
                else
                  Regexp::escape(x)
                end
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
          sig.re.pop while sig.re && sig.re.last == '??'
        end
        sigs.delete_if{ |sig| !sig.re || sig.re.index('BAD_RE') }
        return sigs if args[:raw] || args[:raword]

#        require 'awesome_print'
#        bins.each do |bin_sig, bin|
#          next if bin.size < 5
#          #next unless bin_sig.name['UPX']
#
#          bin_re = Regexp.new(bin_sig.re.join, Regexp::MULTILINE)
#          was = false
#          sigs.each do |sig|
#            next if sig.size < 5 || sig == bin_sig
#            #next unless sig.name['UPX']
#
#            re = Regexp.new(sig.re.join, Regexp::MULTILINE)
#            if bin.index(re) == 0
#              rd = _re_diff(bin_re.source, re.source)
#              if rd.any? && rd.size <= 4
#                #if sig.name.split.first.upcase != bin_sig.name.split.first.upcase
#                  puts "\n[.] #{bin_sig.name.yellow}\n#{bin_re.source.inspect.red}" unless was
#                  puts "[=] #{sig.name}"
#                  puts re.source.inspect.green
#                  p rd
#                  was = true
#                #end
#              end
#            end
#          end
#        end


        optimize sigs if args[:optimize]

        # convert re-arrays to Regexps
        sigs.each do |sig|
          sig.re = Regexp.new( _join(sig.re), Regexp::MULTILINE )
        end

        sigs
      end

      # XXX
      # "B\xE9rczi G\xE1bor".force_encoding('binary').to_yaml:
      # RuntimeError: expected SCALAR, SEQUENCE-START, MAPPING-START, or ALIAS

      def _add_sig sigs, sig, args = {}
        raise "null RE: #{sig.inspect}" unless sig.re

        # bad sigs
        return if sig.re[/\A538BD833C0A30:::::/]
        return if sig.name == "Name of the Packer v1.0"
        return if sig.name == "Alias PIX/Vivid IMG Graphics format"
        return if sig.name == "JAR Archive"
        return if sig.name == "Turbo / Borland Pascal v7.x Unit"
        return if sig.re == "54 68 69 73 20 70 72 6F 67 72 61 6D 20 63 61 6E 6E 6F 74 20 62 65 20 72 75 6E 20 69 6E 20 44 4F 53 20 6D 6F" # dos stub

        sig.name.sub!(/^\*\s+/,    '')
        sig.name.sub!(/\s+\(h\)$/, '')
        sig.name.sub!(/version (\d)/i,"v\\1")
        sig.name.sub!(/Microsoft/i, "MS")
        sig.name.sub!(/ or /i, " / ")
        sig.name.sub! 'RLP ','RLPack '
        sig.name.sub! '.beta', ' beta'
        sig.name.sub! '(com)','[com]'
        sig.name.gsub!(/ V(\d)/, " v\\1") # V1.1 -> v1.1
        sig.name = sig.name.split(/\s*-+>\s*/).join(' -> ') # fix spaces around '->'
        sig.name = sig.name.split(' ').delete_if do |x|
          # delete words: vX.X, v?.?, ?.?, x.x
          x =~ /\Av?[?x]\.[?x]\Z/i
        end.join(' ')

        sig.re = sig.re.strip.upcase.tr(':','?')
        sig.re = sig.re.scan(/../).join(' ') if sig.re.split.first.size > 2

        # sig contains entirely zeroes or masks or only both
        a_bad = [%w'00', %w'??', %w'00 ??', %w'90', %w'90 ??']
        # ?a, 0? => ??, ??
        a_cur = sig.re.split.map{ |x| x['?'] ? '??' : x }.uniq.sort
        return if a_bad.include?(a_cur)

        # first byte is unique and all others are zeroes or masks
        a_cur = sig.re.split[1..-1].map{ |x| x['?'] ? '??' : x }.uniq.sort
        return if a_bad.include?(a_cur)

        # too short signatures
        if sig.re.split.delete_if{ |x| x['?'] }.size < 3
          require 'awesome_print'
          puts sig.inspect.red
        end

        # fs.txt contains a lot of signatures that copied from other sources
        # BUT have all 01 replaced with '??'
        # // replaced the file with filtered one (see 'fs-good' below) // zzz
        if args[:fix1]
          sigs.keys.each do |re|
            if re.gsub("01","??") == sig.re
              puts "[.] fix1: rejecting #{sig.name} - already present with 01 in place" if args[:verbose]
              return
            end
          end
#          File.open("fs-good.txt","a") do |f|
#            f << "[#{sig.name}=#{sig.re.tr(' ','')}]\n"
#          end
        end

        if sigs[sig.re]
          a = [sig, sigs[sig.re]].map{ |x| x.name.upcase.split('->').first.tr('V ','') }
          return if a[0][a[1]] || a[1][a[0]]

          new_name = _merge_names(sigs[sig.re].name, sig.name)
          if new_name && new_name != sig.name && new_name != sigs[sig.re].name
            puts "[.] sig name join: #{new_name}" if args[:verbose]
            sigs[sig.re].name = new_name
          end
        else
          # new sig
          sigs[sig.re] = sig
        end
      end

      def _merge_names name1, name2
        a = [name1, name2].map{ |x| x.split('->').first.split }

        d = [a[0]-a[1], a[1]-a[0]] # different words
        d.map! do |x|
          x - [
            'EXE','[EXE]',
            'DLL','(DLL)','[DLL]',
            '[LZMA]','(LZMA)','LZMA',
            '-','~','(pack)','(1)','(2)',
            '19??',
            'with:', 'with?'
          ]
        end
        return if d.all?(&:empty?) # no different words => can keep ANY name


#        if name1 =~ /pecompact/i
#          require 'awesome_print'
#          puts "[d] #{name1}".yellow
#          puts "[d] #{name2}".yellow
#        end

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

#        require 'awesome_print'
#        puts "[d] #{name1.yellow} #{name2.green}"

        a = name1.split
        b = name2.split

        # merge common head
        new_name_head = []
        while a.any? && b.any? && a.first.upcase == b.first.upcase
          new_name_head << a.shift
          b.shift
        end

        # merge common tail
        new_name_tail = []
        while a.any? && b.any? && a.last.upcase == b.last.upcase
          new_name_tail.unshift a.pop
          b.pop
        end

        # rm common words from middle
        separators = [ "/", "->" ]
        was = true
        while was
          was = false
          b.each do |bw|
            next if bw == "/" || bw == "->"
            if a.include?(bw) || a.include?(bw+")") || a.include?("("+bw) || a.include?("(#{bw})")
              b -= [bw]
              was = true
              break
            end
          end
        end
        while separators.include?(b.last)
          b.pop
        end

        new_name = new_name_head
        new_name << [a.join(' '), b.join(' ')].delete_if{|x| x.empty?}.join(' / ')
        new_name += new_name_tail
#        if name1 =~ /pecompact/i
#          p a
#          p b
#          p new_name_tail
#        puts "[=] #{new_name.inspect}".red
#        end
        new_name = new_name.join(' ')
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

      def _re_diff a,b, max_cnt = 1000
        r = []
        [a,b].map(&:size).max.times.map do |i|
          if a[i] != b[i]
            r << [a[i],b[i]]
            return nil if r.size > max_cnt
          end
        end
        r
      end

      def _optimize sigs
        nfound   = 0
        min_sz   = 6
        max_diff = 6
        sigs.each_with_index do |sig1,idx|
          #break if idx == 100
          next if sig1.re.size < min_sz
          next if sig1.name['PseudoSigner']

          sigs[(idx+1)..-1].each do |sig2|
            next if sig2.re.size < min_sz
            next if sig2.name['PseudoSigner']

            if rd = _re_diff(sig1.re, sig2.re, max_diff)
              if    rd.all?{ |x| x[0].nil? || x[0] == '.' } && sig2.re.size >= sig1.re.size
                if new_name = _merge_names(sig2.name, sig1.name)
#                  require 'pp'
#                  pp ["FIRST", sig1.name, sig2.name, new_name, sig1.re.join, sig2.re.join] if new_name =~ /pecompact/i
                  sig1.name = new_name
                end
                sig2.ep_only ||= sig1.ep_only
                sig2.re = []
              elsif rd.all?{ |x| x[1].nil? || x[1] == '.' } && sig1.re.size >= sig2.re.size
                if new_name = _merge_names(sig2.name, sig1.name)
#                  require 'pp'
#                  pp ["SECOND", sig1.name, sig2.name, new_name, sig1.re.join, sig2.re.join] if new_name =~ /pecompact/i
                  sig2.name = new_name
                end
                sig1.re = []
                sig1.ep_only ||= sig2.ep_only
                break
              else
                next
              end
              nfound += 1
            end
          end
        end

        sigs.delete_if{ |sig| sig.re.empty? }
      end

      def _name2wordonly name
        name.downcase.split(/[^a-z0-9_.]+/).join(' ').strip
      end

      def optimize_names sigs
        # replaces all duplicate names with references to one name
        # saves ~30k out of ~200k mem
        h = {}

        # find shortest names
        sigs.each do |sig|
          t = _name2wordonly(sig.name)
          if h[t]
            # keep shortest name
            if h[t] != sig.name
              #print "[d] #{[h[t], sig.name].inspect} -> "
              h[t] = [h[t], sig.name].sort_by(&:size).first
              #puts h[t]
            else
              # fully identical names
            end
          else
            h[t] = sig.name
          end
        end

        # assign names back to sigs
        sigs.each{ |sig| sig.name = h[_name2wordonly(sig.name)] }

        puts "[.] sigs merge: #{h.size} unique names"
      end

      def optimize sigs
        optimize_names sigs

        # XXX no optimize from now, prefer more precise sigs
        #print "[.] sigs merge: #{sigs.size}"; _optimize(sigs); puts  " -> #{sigs.size}"

        # try to merge signatures with same name, size & ep_only
        sigs.group_by{ |sig| [sig.re.size, sig.name, sig.ep_only] }.
          values.each do |a|
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
        dstart ||= 0
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
