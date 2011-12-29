require 'pedump'
require 'pedump/loader'

########################################################################
# comparing 2 binaries
########################################################################

class PEdump::Comparer
  attr_accessor :verbose
  attr_accessor :ignored_data_dirs, :ignored_sections

  METHODS = [:sections, :data_dirs, :imports, :resources, :pe_hdr]

  def initialize ldr1, ldr2
    @ldr1,@ldr2 = ldr1,ldr2
    @ignored_data_dirs = []
    @ignored_sections  = []
  end

  def equal?
    METHODS.map{ |m| send("cmp_#{m}") }.uniq == [true]
  end

  def diff
    METHODS.map{ |m| send("cmp_#{m}") ? nil : m }.compact
  end

  def cmp_pe_hdr
    @ldr1.pe.ioh.AddressOfEntryPoint == @ldr2.pe.ioh.AddressOfEntryPoint &&
    @ldr1.pe.ioh.ImageBase           == @ldr2.pe.ioh.ImageBase
  end

  def cmp_resources
    PEdump.quiet do
      #@ldr1.pedump.resources == @ldr2.pedump.resources
      @ldr1.pedump.resources.each_with_index do |r1,idx|
       r2 = @ldr2.pedump.resources[idx]
       if (r1.to_a - [r1.file_offset]) != (r2.to_a - [r2.file_offset])
         p r1
         p r2
         return false
       end
      end
    end
    true
  end

  def cmp_sections
    r = true
    @ldr1.sections.each_with_index do |s1,idx|
      next if @ignored_sections.include?(s1.name)
      s2 = @ldr2.sections[idx]

      if !s2
        r = false
        printf "[!] extra section %-12s in %s\n".red, s1.name.inspect, f1
      elsif s1.data == s2.data
        printf "[.] section: %s == %s\n".green, s1.name, s2.name if @verbose
      else
        r = false
        printf "[!] section: %s != %s\n".red, s1.name, s2.name
        self.class.cmp_ios *[s1,s2].map{ |section| StringIO.new(section.data) }
      end
    end
    r
  end

  def cmp_data_dirs
    r = true
    @ldr1.pe.ioh.DataDirectory.each_with_index do |d1,idx|
      break if idx == 15
      d2 = @ldr2.pe.ioh.DataDirectory[idx]

      case idx
        when PEdump::IMAGE_DATA_DIRECTORY::BASERELOC
          # total 8-byte size relocs == no relocs at all
          next if [d1.va, d2.va].min == 0 && [d1.size, d2.size].max == 8
      end

      next if @ignored_data_dirs.include?(idx)

      if d1.va != d2.va && d1.size != d2.size
        r = false
        printf "[!] data_dir: %-12s:  SIZE & VA: %6x %6x  |  %6x %6x\n".red, d1.type,
          d1.va, d1.size, d2.va, d2.size
      elsif d1.va != d2.va
        r = false
        printf "[!] data_dir: %-12s:  VA       : %x != %x\n".red, d1.type, d1.va, d2.va
      elsif d1.size != d2.size
        r = false
        printf "[!] data_dir: %-12s:  SIZE     : %x != %x\n".red, d1.type, d1.size, d2.size
      end
    end
    r
  end

  def cmp_imports
    @ldr1.pedump.imports.each_with_index do |iid1,idx|
      iid2 = @ldr2.pedump.imports[idx]
      if iid1 != iid2
        puts "[!] diff imports".red
        return false
      end
    end
    true
  end

  class << self
    # arguments can be:
    #   a) filenames
    #   b) IO instances
    #   c) PEdump::Loader instances
    def cmp *args
      handles = []
      if args.all?{|x| x.is_a?(String)}
        handles = args.map{|x| File.open(x,"rb")}
        _cmp(*handles.map{|h| PEdump::Loader.new(h)})
      else
        _cmp(*args)
      end
    ensure
      handles.each(&:close)
    end

    # each arg is a PEdump::Loader
    def _cmp ldr1, ldr2
      new(ldr1, ldr2).equal?
    end

    def cmp_ios *ios
      ndiff = 0
      while !ios.any?(&:eof)
        bytes = ios.map(&:readbyte)
        if bytes.uniq.size > 1
          ndiff += 1
          printf ("\t%08x:"+" %02x"*ios.size).yellow+"\n", ios[0].pos-1, *bytes
          if ndiff >= 5
            puts "\t...".yellow
            break
          end
        end
      end
      puts if ndiff > 0
    end

  end
end
