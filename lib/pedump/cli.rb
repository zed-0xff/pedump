require 'pedump'
require 'pedump/packer'
require 'pedump/rich'
require 'pedump/version_info'
require 'optparse'

begin
  require 'shellwords' # from ruby 1.9.3
rescue LoadError
  unless ''.respond_to?(:shellescape)
    class String
      # File shellwords.rb, line 72
      def shellescape
        # An empty argument will be skipped, so return empty quotes.
        return "''" if self.empty?

        str = self.dup

        # Process as a single byte sequence because not all shell
        # implementations are multibyte aware.
        str.gsub!(/([^A-Za-z0-9_\-.,:\/@\n])/, "\\\\\\1")

        # A LF cannot be escaped with a backslash because a backslash + LF
        # combo is regarded as line continuation and simply ignored.
        str.gsub!(/\n/, "'\n'")

        str
      end
    end
  end
end

class PEdump::CLI
  attr_accessor :data, :argv

  KNOWN_ACTIONS = (
    %w'mz dos_stub rich pe ne te data_directory sections tls security' +
    %w'strings resources resource_directory imports exports version_info packer web console packer_only' +
    %w'extract' # 'disasm'
  ).map(&:to_sym)

  DEFAULT_ALL_ACTIONS = KNOWN_ACTIONS - %w'resource_directory web packer_only console extract disasm'.map(&:to_sym)

  URL_BASE = "https://pedump.me"

  def initialize argv = ARGV
    @argv = argv
  end

  def run
    @actions = []
    @options = { :format => :table, :verbose => 0 }
    optparser = OptionParser.new do |opts|
      opts.banner = "Usage: pedump [options]"

      opts.on "--version", "Print version information and exit" do
        puts PEdump::VERSION
        exit
      end
      opts.on "-v", "--verbose", "Run verbosely","(can be used multiple times)" do |v|
        @options[:verbose] += 1
      end
      opts.on "-q", "--quiet", "Silent any warnings","(can be used multiple times)" do |v|
        @options[:verbose] -= 1
      end
      opts.on "-F", "--force", "Try to dump by all means","(can cause exceptions & heavy wounds)" do |v|
        @options[:force] ||= 0
        @options[:force] += 1
      end
      opts.on "-f", "--format FORMAT", [:binary, :c, :dump, :hex, :inspect, :json, :table, :yaml],
        "Output format: bin,c,dump,hex,inspect,json,table,yaml","(default: table)" do |v|
        @options[:format] = v
      end
      KNOWN_ACTIONS.each do |t|
        a = [
          "--#{t.to_s.tr('_','-')}",
          eval("lambda{ |_| @actions << :#{t.to_s.tr('-','_')} }")
        ]
        a.unshift(a[0][1,2].upcase) if a[0] =~ /--(((ex|im)port|section|resource)s|version-info)/
        a.unshift(a[0][1,2]) if a[0] =~ /--strings/
        opts.on *a
      end

      opts.on "--deep", "packer deep scan, significantly slower" do
        @options[:deep] ||= 0
        @options[:deep] += 1
        PEdump::Packer.default_deep = @options[:deep]
      end

      opts.on '-P', "--packer-only", "packer/compiler detect only,","mimics 'file' command output" do
        @actions << :packer_only
      end

      opts.on '-r', "--recursive", "recurse dirs in packer detect" do
        @options[:recursive] = true
      end

      opts.on "--all", "Dump all but resource-directory (default)" do
        @actions = DEFAULT_ALL_ACTIONS
      end

      opts.separator ''

#      opts.on "--disasm [X]", "Disassemble a symbol/VA" do |v|
#        @actions << [:disasm, v]
#      end
      opts.on("--extract ID", "Extract a resource/section/data_dir",
              "ID: datadir:EXPORT     - datadir by type",
              "ID: resource:0x98478   - resource by offset",
              "ID: resource:ICON/#1   - resource by type & name",
              "ID: section:.text      - section by name",
              "ID: section:rva/0x1000 - section by RVA",
              "ID: section:raw/0x400  - section by RAW_PTR",
             ) do |v|
        @actions << [:extract, v]
      end
      opts.on "--va2file VA", "Convert RVA to file offset" do |va|
        @actions << [:va2file, va]
      end

      opts.on "--set-os-version VER", "Patch OS version in PE header" do |ver|
        @actions << [:set_os_version, ver]
      end
      opts.on "--set-dll-char X", "Patch IMAGE_OPTIONAL_HEADER32.DllCharacteristics" do |x|
        @actions << [:set_dll_char, x]
      end

      opts.separator ''

      opts.on "-W", "--web", "Uploads files to a #{URL_BASE}","for a nice HTML tables with image previews,","candies & stuff" do
        @actions << :web
      end
      opts.on "-C", "--console", "opens IRB console with specified file loaded" do
        @actions << :console
      end
    end

    if (@argv = optparser.parse(@argv)).empty?
      puts optparser.help
      return
    end

    if (@actions-KNOWN_ACTIONS).any?{ |x| !x.is_a?(Array) }
      puts "[?] unknown actions: #{@actions-KNOWN_ACTIONS}"
      @actions.delete_if{ |x| !KNOWN_ACTIONS.include?(x) }
    end
    @actions = DEFAULT_ALL_ACTIONS if @actions.empty?

    if @actions.include?(:packer_only)
      raise "[!] can't mix --packer-only with other actions" if @actions.size > 1
      dump_packer_only(argv)
      return
    end

    argv.each_with_index do |fname,idx|
      @need_fname_header = (argv.size > 1)
      @file_idx  = idx
      @file_name = fname

      File.open(fname,'rb') do |f|
        @pedump = create_pedump f

        next if !@options[:force] && !@pedump.supported_file?(f)

        @actions.each do |action|
          case action
          when :web; upload f
          when :console; console f
          else
            dump_action action,f
          end
        end
      end
    end
  rescue Errno::EPIPE
    # output interrupt, f.ex. when piping output to a 'head' command
    # prevents a 'Broken pipe - <STDOUT> (Errno::EPIPE)' message
  end

  def create_pedump io
    PEdump.new(io, :force => @options[:force]).tap do |x|
      x.logger.level =
        case @options[:verbose]
        when -100..-3
          Logger::FATAL + 1
        when -2
          Logger::FATAL
        when -1
          Logger::ERROR
        when 0
          Logger::WARN  # default
        when 1
          Logger::INFO
        when 2..100
          Logger::DEBUG
        end
    end
  end

  def dump_packer_only fnames
    max_fname_len = fnames.map(&:size).max
    fnames.each do |fname|
      if File.directory?(fname)
        if @options[:recursive]
          dump_packer_only(Dir[File.join(fname.shellescape,"*")])
        else
          STDERR.puts "[?] #{fname} is a directory, and recursive flag is not set"
        end
      else
        File.open(fname,'rb') do |f|
          @pedump = create_pedump fname
          packers = @pedump.packers(f)
          pname = Array(packers).first.try(:packer).try(:name)
          pname ||= "unknown" if @options[:verbose] > 0
          printf("%-*s %s\n", max_fname_len+1, "#{fname}:", pname) if pname
        end
      end
    end
  end

  class ProgressProxy
    def initialize file, prefix = "[.] uploading: ", io = $stdout
      @file   = file
      @io     = io
      @prefix = prefix
    end
    def read *args
      @io.write("\r#{@prefix}#{@file.tell}/#{@file.size} ")
      @io.flush
      @file.read *args
    end
    def method_missing *args
      @file.send *args
    end
    def respond_to? *args
      @file.respond_to?(args.first) || super(*args)
    end

    def finish!
      @io.write("\r#{@prefix}#{@file.size}/#{@file.size} \n")
    end
  end

  def upload f
    if @pedump.mz(f).signature != 'MZ'
      @pedump.logger.error "[!] refusing to upload a non-MZ file"
      return
    end

    require 'digest/md5'
    require 'open-uri'
    require 'net/http'
    require 'net/http/post/multipart'

    stdout_sync = $stdout.sync
    $stdout.sync = true

    md5 = Digest::MD5.file(f.path).hexdigest
    @pedump.logger.info "[.] md5: #{md5}"
    file_url = "#{URL_BASE}/#{md5}/"

    @pedump.logger.warn "[.] checking if file already uploaded.."
    uri = URI.parse URL_BASE
    Net::HTTP.start(uri.host, uri.port, use_ssl: (uri.scheme == 'https')) do |http|
      http.open_timeout = 10
      http.read_timeout = 10
      # doing HTTP HEAD is a lot faster than open-uri
      h = http.head("/#{md5}/")
      if h.code.to_i == 200 && h.content_type.to_s.strip.downcase == "text/html"
        @pedump.logger.warn "[.] file already uploaded: #{file_url}"
        return
      elsif h.code.to_i != 404 # 404 means that there's no such file and we're OK to upload
        @pedump.logger.fatal "[!] invalid server response: \"#{h.code} #{h.msg}\" (#{h.content_type})"
        exit(1)
      end
    end

    f.rewind

    # upload with progress
    post_url = URI.parse(URL_BASE+'/upload')
    # UploadIO is from multipart-post
    uio = UploadIO.new(f, "application/octet-stream", File.basename(f.path))
    ppx = ProgressProxy.new(uio)
    req = Net::HTTP::Post::Multipart.new post_url.path, "file" => ppx
    res = Net::HTTP.start(post_url.host, post_url.port, use_ssl: (post_url.scheme == 'https')) do |http|
      http.request(req)
    end
    ppx.finish!

    unless [200, 302, 303].include?(res.code.to_i)
      @pedump.logger.fatal "[!] invalid server response: #{res.code} #{res.msg}"
      @pedump.logger.fatal res.body unless res.body.empty?
      exit(1)
    end

    puts "[.] uploaded: #{file_url}"
  ensure
    $stdout.sync = stdout_sync
  end

  def console f
    require 'pedump/loader'
    require 'pp'

    ARGV.clear # clear ARGV so IRB is not confused
    require 'irb'
    f.rewind
    ldr = @ldr = PEdump::Loader.new(f)

    # override IRB.setup, called from IRB.start
    m0 = IRB.method(:setup)
    IRB.define_singleton_method :setup do |*args|
      m0.call *args
      conf[:IRB_RC] = Proc.new do |context|
        context.main.instance_variable_set '@ldr', ldr
        context.main.define_singleton_method(:ldr){ @ldr }
      end
    end

    puts "[.] ldr = PEdump::Loader.new(open(#{f.path.inspect}))".gray
    IRB.start
  end

  def action_title action
    if @need_fname_header
      @need_fname_header = false
      puts if @file_idx > 0
      puts "# -----------------------------------------------"
      puts "# #@file_name"
      puts "# -----------------------------------------------"
    end

    s = action.to_s.upcase.tr('_',' ')
    s += " Header" if [:mz, :pe, :rich].include?(action)
    s = "Packer / Compiler" if action == :packer
    "\n=== %s ===\n\n" % s
  end

  def dump_action action, f
    if action.is_a?(Array)
      case action[0]
      when :disasm
        return
      when :extract
        return extract action[1]
      when :set_os_version
        return set_os_version action[1]
      when :set_dll_char
        return set_dll_char action[1]
      when :va2file
        @pedump.sections(f)
        va = action[1] =~ /(^0x)|(h$)/i ? action[1].to_i(16) : action[1].to_i
        file_offset = @pedump.va2file(va)
        printf "va2file(0x%x) = 0x%x  (%d)\n", va, file_offset, file_offset
        return
      else raise "unknown action #{action.inspect}"
      end
    end

    data = @pedump.send(action, f)
    return if !data || (data.respond_to?(:empty?) && data.empty?)

    puts action_title(action) unless @options[:format] == :binary

    return dump(data) if [:inspect, :table, :json, :yaml].include?(@options[:format])

    dump_opts = {:name => action}
    case action
      when :pe
        data = @pedump.pe.pack
      when :resources
        return dump_resources(data)
      when :strings
        return dump_strings(data)
      when :imports
        return dump_imports(data)
      when :exports
        return dump_exports(data)
      when :version_info
        return dump_version_info(data)
      else
        if data.is_a?(Struct) && data.respond_to?(:pack)
          data = data.pack
        elsif data.is_a?(Array) && data.all?{ |x| x.is_a?(Struct) && x.respond_to?(:pack)}
          data = data.map(&:pack).join
        end
    end
    dump data, dump_opts
  end

  def dump data, opts = {}
    case opts[:format] || @options[:format] || :dump
    when :dump, :hexdump
      data.hexdump
    when :hex
      puts data.each_byte.map{ |x| "%02x" % x }.join(' ')
    when :binary
      print data
    when :c
      name = opts[:name] || "foo"
      puts "// #{data.size} bytes total"
      puts "unsigned char #{name}[] = {"
      data.unpack('C*').each_slice(12) do |row|
        puts "  " + row.map{ |c| "0x%02x," % c}.join(" ")
      end
      puts "};"
    when :inspect
      require 'pp'
      pp data
    when :table
      dump_table data
    when :yaml
      require 'yaml'
      puts data.to_yaml
    when :json
      require 'json'
      puts data.to_json
    end
  end

  COMMENTS = {
    :Machine => {
      0x014c => 'x86',
      0x0200 => 'Intel Itanium',
      0x8664 => 'x64',
      'default' => '???'
    },
    :Magic => {
      0x010b => '32-bit executable',
      0x020b => '64-bit executable',
      0x0107 => 'ROM image',
      'default' => '???'
    },
    :Subsystem => PEdump::IMAGE_SUBSYSTEMS
  }

  def _flags2string flags
    return '' if !flags || flags.empty?
    a = [flags.shift.dup]
    flags.each do |f|
      if (a.last.size + f.size) < 40
        a.last << ", " << f
      else
        a << f.dup
      end
    end
    a.join("\n"+ ' '*58)
  end

  def dump_generic_table data
    data.each_pair do |k,v|
      next if [:DataDirectory, :section_table].include?(k)
      case v
      when Numeric
        case k
        when /\AMajor.*Version\Z/
          printf "%30s: %24s\n", k.to_s.sub('Major',''), "#{v}.#{data[k.to_s.sub('Major','Minor')]}"
        when /\AMinor.*Version\Z/
        when /TimeDateStamp/
          printf "%30s: %24s\n", k, Time.at(v).utc.strftime('"%Y-%m-%d %H:%M:%S"')
        else
          comment = ''
          if COMMENTS[k]
            comment = COMMENTS[k][v] || (COMMENTS[k].is_a?(Hash) ? COMMENTS[k]['default'] : '') || ''
          elsif data.is_a?(PEdump::IMAGE_FILE_HEADER) && k == :Characteristics
            comment = _flags2string(data.flags)
          elsif k == :DllCharacteristics
            comment = _flags2string(data.flags)
          end
          comment.strip!
          comment = "  #{comment}" unless comment.empty?
          printf "%30s: %10d  %12s%s\n", k, v, v<10 ? v : ("0x"+v.to_s(16)), comment
        end
      when Struct
        # IMAGE_FILE_HEADER:
        # IMAGE_OPTIONAL_HEADER:
        printf "\n# %s:\n", v.class.to_s.split('::').last
        dump_table v
      when Time
        printf "%30s: %24s\n", k, v.strftime('"%Y-%m-%d %H:%M:%S"')
      else
        printf "%30s: %24s\n", k, v.to_s.inspect
      end
    end
  end

  def dump_table data
    if data.is_a?(Struct)
      return dump_res_dir(data) if data.is_a?(PEdump::IMAGE_RESOURCE_DIRECTORY)
      return dump_exports(data) if data.is_a?(PEdump::IMAGE_EXPORT_DIRECTORY)
      dump_generic_table data
    elsif data.is_a?(Enumerable) && data.map(&:class).uniq.size == 1
      case data.first
      when PEdump::IMAGE_DATA_DIRECTORY
        dump_data_dir data
      when PEdump::EFI_IMAGE_DATA_DIRECTORY
        dump_efi_data_dir data
      when PEdump::IMAGE_SECTION_HEADER
        dump_sections data
      when PEdump::Resource
        dump_resources data
      when PEdump::STRING
        dump_strings data
      when PEdump::IMAGE_IMPORT_DESCRIPTOR, PEdump::ImportedFunction
        dump_imports data
      when PEdump::Packer::Match
        dump_packers data
      when PEdump::VS_VERSIONINFO, PEdump::NE::VS_VERSIONINFO
        dump_version_info data
      when PEdump::IMAGE_TLS_DIRECTORY32, PEdump::IMAGE_TLS_DIRECTORY64
        dump_tls data
      when PEdump::WIN_CERTIFICATE
        dump_security data
      when PEdump::NE::Segment
        dump_ne_segments data
      else
        puts "[?] don't know how to dump: #{data.inspect[0,50]}" unless data.empty?
      end
    elsif data.is_a?(PEdump::DOSStub)
      data.hexdump
    elsif data.is_a?(PEdump::RichHdr)
      dump_rich_hdr data
    else
      puts "[?] Don't know how to display #{data.inspect[0,50]}... as a table"
    end
  end

  def dump_security data
    return unless data
    data.each do |win_cert|
      if win_cert.data.respond_to?(:certificates)
        win_cert.data.certificates.each do |cert|
          puts cert.to_text
          puts
        end
      else
        @pedump.logger.error "[?] no certificates in #{win_cert.class}"
      end
    end
  end

  def dump_tls data
    fmt = "%10x %10x %8x  %8x  %8x  %8x\n"
    printf fmt.tr('x','s'), *%w'RAW_START RAW_END INDEX CALLBKS ZEROFILL FLAGS'
    data.each do |tls|
      printf fmt,
        tls.StartAddressOfRawData.to_i,
        tls.EndAddressOfRawData.to_i,
        tls.AddressOfIndex.to_i,
        tls.AddressOfCallBacks.to_i,
        tls.SizeOfZeroFill.to_i,
        tls.Characteristics.to_i
    end
  end

  def dump_version_info data
    if @options[:format] != :table
      File.open(@file_name,'rb') do |f|
        @pedump.resources.find_all{ |r| r.type == 'VERSION'}.each do |res|
          f.seek res.file_offset
          data = f.read(res.size)
          dump data
        end
      end
      return
    end

    fmt = "  %-20s:  %s\n"
    data.each do |vi|
      puts "# VS_FIXEDFILEINFO:"

      if @options[:verbose] > 0 || vi.Value.dwSignature != 0xfeef04bd
        printf(fmt, "Signature", "0x#{vi.Value.dwSignature.to_i.to_s(16)}")
      end

      printf fmt, 'FileVersion', [
        vi.Value.dwFileVersionMS.to_i >> 16,
        vi.Value.dwFileVersionMS.to_i &  0xffff,
        vi.Value.dwFileVersionLS.to_i >> 16,
        vi.Value.dwFileVersionLS.to_i &  0xffff
      ].join('.')

      printf fmt, 'ProductVersion', [
        vi.Value.dwProductVersionMS.to_i >> 16,
        vi.Value.dwProductVersionMS.to_i &  0xffff,
        vi.Value.dwProductVersionLS.to_i >> 16,
        vi.Value.dwProductVersionLS.to_i &  0xffff
      ].join('.')

      vi.Value.each_pair do |k,v|
        next if k[/[ML]S$/] || k == :valid || k == :dwSignature
        printf fmt, k.to_s.sub(/^dw/,''), v.to_i > 9 ? "0x#{v.to_s(16)}" : v
      end

      vi.Children.each do |file_info|
        case file_info
        when PEdump::StringFileInfo, PEdump::NE::StringFileInfo
          file_info.Children.each do |string_table|
            puts "\n# StringTable #{string_table.szKey}:"
            string_table.Children.each do |string|
              printf fmt, string.szKey, string.Value.inspect
            end
          end
        when PEdump::VarFileInfo, PEdump::NE::VarFileInfo
          puts
          printf fmt, "VarFileInfo", '[ 0x' + file_info.Children.Value.map{|v| v.to_s(16)}.join(", 0x") + ' ]'
        else
          puts "[?] unknown child type: #{file_info.inspect}, use -fi to inspect"
        end
      end
    end
  end

  def dump_packers data
    if @options[:verbose] > 0
      data.each do |p|
        printf "%8x %4d %s\n", p.offset, p.packer.size, p.packer.name
      end
    else
      # show only largest detected unless verbose output requested
      puts "  #{data.first.packer.name}"
    end
  end

  def dump_exports data
    printf "# module %s\n", data.name.inspect
    printf "# description %s\n", data.description.inspect if data.description

    if data.Characteristics || data.TimeDateStamp || data.MajorVersion || data.MinorVersion || data.Base
      printf "# flags=0x%x  ts=%s  version=%d.%d  ord_base=%d\n",
        data.Characteristics.to_i,
        Time.at(data.TimeDateStamp.to_i).utc.strftime('"%Y-%m-%d %H:%M:%S"'),
        data.MajorVersion.to_i, data.MinorVersion.to_i,
        data.Base.to_i
    end

    if @options[:verbose] > 0
      [%w'Names', %w'EntryPoints Functions', %w'Ordinals NameOrdinals'].each do |x|
        va  = data["AddressOf"+x.last]
        ofs = @pedump.va2file(va) || '?'
        printf("# %-12s rva=0x%08x  file_offset=%8s\n", x.first, va, ofs) if va
      end
    end

    if data.NumberOfFunctions || data.NumberOfNames
      printf "# nFuncs=%d  nNames=%d\n", data.NumberOfFunctions.to_i, data.NumberOfNames.to_i
    end

    if data.functions && data.functions.any?
      puts
      if @pedump.ne?
        printf "%5s %9s  %s\n", "ORD", "SEG:OFFS", "NAME"
        data.functions.each do |f|
          printf "%5x %4x:%04x  %s\n", f.ord, f.va>>16, f.va&0xffff, f.name
        end
      else
        printf "%5s %8s  %s\n", "ORD", "ENTRY_VA", "NAME"
        data.functions.each do |f|
          printf "%5x %8x  %s\n", f.ord, f.va, f.name
        end
      end
    end
  end

  def dump_imports data
    fmt = "%-15s %5s %5s  %s\n"
    printf fmt, "MODULE_NAME", "HINT", "ORD", "FUNCTION_NAME"
    data.each do |x|
      case x
      when PEdump::IMAGE_IMPORT_DESCRIPTOR
        (Array(x.original_first_thunk) + Array(x.first_thunk)).uniq.each do |f|
          next unless f
          # imported function
          printf fmt,
            x.module_name,
            f.hint ? f.hint.to_s(16) : '',
            f.ordinal ? f.ordinal.to_s(16) : '',
            f.name
        end
      when PEdump::ImportedFunction
        printf fmt,
          x.module_name,
          x.hint ? x.hint.to_s(16) : '',
          x.ordinal ? x.ordinal.to_s(16) : '',
          x.name
      else
        raise "invalid #{x.inspect}"
      end
    end
  end

  def dump_strings data
    printf "%5s %5s  %4s  %s\n", "ID", "ID", "LANG", "STRING"
    prev_lang = nil
    data.sort_by{|s| [s.lang, s.id] }.each do |s|
      #puts if prev_lang && prev_lang != s.lang
      printf "%5d %5x  %4s  %s\n", s.id, s.id, s.lang && s.lang.to_s(16), s.value.inspect
      prev_lang = s.lang
    end
  end

  def dump_res_dir entry, level = 0
    if entry.is_a?(PEdump::IMAGE_RESOURCE_DIRECTORY)
      # root entry
      printf "dir? %8s %8s %5s %5s",    "FLAGS", "TIMESTMP", "VERS", 'nEnt'
      printf " | %-15s %8s | ",         "NAME", "OFFSET"
      printf "data? %8s %8s %5s %8s\n", 'DATA_OFS', 'DATA_SZ', 'CP', 'RESERVED'
    end

    dir =
      case entry
      when PEdump::IMAGE_RESOURCE_DIRECTORY
        entry
      when PEdump::IMAGE_RESOURCE_DIRECTORY_ENTRY
        entry.data
      end

    fmt1  = "DIR: %8x %8x %5s %5d"
    fmt1s = fmt1.tr("xd\nDIR:","ss ") % ['','','','']

    if dir.is_a?(PEdump::IMAGE_RESOURCE_DIRECTORY)
      printf fmt1,
        dir.Characteristics, dir.TimeDateStamp,
        [dir.MajorVersion,dir.MinorVersion].join('.'),
        dir.NumberOfNamedEntries + dir.NumberOfIdEntries
    else
      print fmt1s
    end

    name =
      case level
      when 0 then "ROOT"
      when 1 then PEdump::ROOT_RES_NAMES[entry.Name] || entry.name
      else entry.name
      end

    printf " | %-15s", name
    printf("\n%s   %15s",fmt1s,'') if name.size > 15
    printf " %8x | ", entry.respond_to?(:OffsetToData) ? entry.OffsetToData : 0

    if dir.is_a?(PEdump::IMAGE_RESOURCE_DIRECTORY)
      puts
      dir.entries.each do |child|
        dump_res_dir child, level+1
      end
    elsif dir
      printf "DATA: %8x %8x %5s %8x\n", dir.OffsetToData, dir.Size, dir.CodePage, dir.Reserved
    else
      puts # null dir
    end
  end

#  def dump_res_dir0 dir, level=0, dir_entry = nil
#    dir_entry ||= PEdump::IMAGE_RESOURCE_DIRECTORY_ENTRY.new
#    printf "%-10s %8x %8x %8x %5s %5d\n", dir_entry.name || "ROOT", dir_entry.OffsetToData.to_i,
#      dir.Characteristics, dir.TimeDateStamp,
#      [dir.MajorVersion,dir.MinorVersion].join('.'),
#      dir.NumberOfNamedEntries + dir.NumberOfIdEntries
#    dir.entries.each do |child|
#      if child.data.is_a?(PEdump::IMAGE_RESOURCE_DIRECTORY)
#        dump_res_dir child.data, level+1, child
#      else
#        print "  "*(level+1) + "CHILD"
#        child.data.each_pair do |k,v|
#          print " #{k[0,2]}=#{v}"
#        end
#        puts
#        #p child
#      end
#    end
#  end

  def dump_resources data
    keys = []; fmt = []
    fmt << "%11x " ; keys << :file_offset
    fmt << "%5d "  ; keys << :cp
    fmt << "%5x "  ; keys << :lang
    fmt << "%8d  " ; keys << :size
    fmt << "%-13s "; keys << :type
    fmt << "%s\n"  ; keys << :name
    printf fmt.join.tr('dx','s'), *keys.map(&:to_s).map(&:upcase)
    data.each do |res|
      fmt.each_with_index do |f,i|
        if v = res.send(keys[i])
          if f['x']
            printf f.tr('x','s'), v.to_i < 10 ? v.to_s : "0x#{v.to_s(16)}"
          else
            printf f, v
          end
        else
          # NULL value
          printf f.tr('xd','s'), ''
        end
      end
    end
  end

  def dump_sections data
    printf "  %-8s %8s %8s %8s %8s %5s %8s %5s %8s  %8s\n",
      'NAME', 'RVA', 'VSZ','RAW_SZ','RAW_PTR','nREL','REL_PTR','nLINE','LINE_PTR','FLAGS'
    data.each do |s|
      name = s.Name[/[^a-z0-9_.]/i] ? s.Name.inspect : s.Name
      name = "#{name}\n          " if name.size > 8
      printf "  %-8s %8x %8x %8x %8x %5x %8x %5x %8x  %8x  %s\n", name.to_s,
        s.VirtualAddress.to_i,      s.VirtualSize.to_i,
        s.SizeOfRawData.to_i,       s.PointerToRawData.to_i,
        s.NumberOfRelocations.to_i, s.PointerToRelocations.to_i,
        s.NumberOfLinenumbers.to_i, s.PointerToLinenumbers.to_i,
        s.flags.to_i,               s.flags_desc
    end
  end

  def dump_ne_segments data
    fmt = "%2x %6x %6x %9x %9x %6x  %s\n"
    printf fmt.tr('x','s'), *%w'# OFFSET SIZE MIN_ALLOC FILE_OFFS FLAGS', ''
    data.each_with_index do |seg,idx|
      printf fmt, idx+1, seg.offset, seg.size, seg.min_alloc_size, seg.file_offset, seg.flags,
        seg.flags_desc
    end
  end

  def dump_data_dir data
    data.each do |row|
      printf "  %-12s  rva:0x%8x   size:0x %8x\n", row.type, row.va.to_i, row.size.to_i
    end
  end

  def dump_efi_data_dir data
    data.each_with_index do |row, idx|
      printf "  %-12s  rva:0x%8x   size:0x %8x\n", PEdump::EFI_IMAGE_DATA_DIRECTORY::TYPES[idx], row.va.to_i, row.size.to_i
    end
  end

  def dump_rich_hdr data
    if decoded = data.decode
      puts "   ID   VER         COUNT  DESCRIPTION"
      decoded.each do |row|
#        printf " %5d  %4x    %7d  %4x   %12d %8x\n",
#          row.id, row.id, row.version, row.version, row.times, row.times
        printf " %4x  %4x  %12d  %s\n",
          row.id, row.version, row.times, ::PEdump::RICH_IDS[(row.id<<16) + row.version]
      end
    else
      puts "# raw:"
      data.hexdump
      puts
      puts "# dexored:"
      data.dexor.hexdump
    end
  end

  def disasm x
    puts "TODO"
  end

  def extract x
    a = x.split(':',2)
    case a[0]
    when 'datadir'
      extract_datadir a[1]
    when 'resource'
      extract_resource a[1]
    when 'section'
      extract_section a[1]
    else
      raise "invalid #{x.inspect}"
    end
  end

  def extract_datadir id
    entry = @pedump.data_directory.find{ |x| x.type == id }
    unless entry
      @pedump.logger.fatal "[!] entry #{id.inspect} not found"
      exit(1)
    end
    if entry.size != 0
      _copy_stream @pedump.io, $stdout, entry.size, @pedump.va2file(entry.va)
    end
  end

  def extract_resource id
    res = nil
    if id =~ /\A0x\h+\Z/
      needle = id.to_i(16)
      res = @pedump.resources.find{ |r| r.file_offset == needle }
    elsif id =~ /\A\d+\Z/
      needle = id.to_i(10)
      res = @pedump.resources.find{ |r| r.file_offset == needle }
    elsif id['/']
      type, name = id.split('/', 2)
      res = @pedump.resources.find{ |r| r.type == type && r.name == name }
    else
      @pedump.logger.fatal "[!] invalid resource id #{id.inspect}"
      exit(1)
    end
    unless res
      @pedump.logger.fatal "[!] resource #{id.inspect} not found"
      exit(1)
    end
    _copy_stream @pedump.io, $stdout, res.size, res.file_offset
  end

  def extract_section id
    section = nil
    if id['/']
      a = id.split('/',2)
      if a[0] == 'rva'
        value = a[1].to_i(0) # auto hex/dec, but also can parse oct and bin
        section = @pedump.sections.find{ |s| s.VirtualAddress == value }
      elsif a[0] == 'raw'
        value = a[1].to_i(0) # auto hex/dec, but also can parse oct and bin
        section = @pedump.sections.find{ |s| s.PointerToRawData == value }
      else
        @pedump.logger.fatal "[!] invalid section id #{id.inspect}"
        exit(1)
      end
    else
      section = @pedump.sections.find{ |s| s.Name == id }
    end
    unless section
      @pedump.logger.fatal "[!] section #{id.inspect} not found"
      exit(1)
    end
    _copy_stream @pedump.io, $stdout, section.SizeOfRawData, section.PointerToRawData
  end

  def set_dll_char x
    @pedump.pe.image_optional_header.DllCharacteristics = x.to_i(0)
    io = @pedump.io.reopen(@file_name,'rb+')
    io.seek @pedump.pe.ioh_offset
    io.write @pedump.pe.image_optional_header.pack
    io.close
  end

  def set_os_version ver
    raise "[!] invalid version #{ver.inspect}" unless ver =~ /\A(\d+)\.(\d+)\Z/
    raise "[!] no IMAGE_OPTIONAL_HEADER" if @pedump.pe.ifh.SizeOfOptionalHeader.to_i == 0
    major = $1.to_i
    minor = $2.to_i
    ver = "#{major}.#{minor}"
    ioh = @pedump.pe.image_optional_header

    prev_os_ver = "#{ioh.MajorOperatingSystemVersion}.#{ioh.MinorOperatingSystemVersion}"
    prev_ss_ver = "#{ioh.MajorSubsystemVersion}.#{ioh.MinorSubsystemVersion}"

    if prev_os_ver == ver && prev_ss_ver == ver
      @pedump.logger.warn "[?] already has #{ver}"
      return
    end

    if prev_os_ver != ver
      ioh.MajorOperatingSystemVersion = major
      ioh.MinorOperatingSystemVersion = minor
      @pedump.logger.warn "[.] MajorOperatingSystemVersion: #{prev_os_ver} -> #{ver}"
    end

    if prev_ss_ver != ver
      ioh.MajorSubsystemVersion = major
      ioh.MinorSubsystemVersion = minor
      @pedump.logger.warn "[.] MajorSubsystemVersion:       #{prev_ss_ver} -> #{ver}"
    end

    io = @pedump.io.reopen(@file_name,'rb+')
    io.seek @pedump.pe.ioh_offset
    io.write ioh.pack
    io.close
  end

  private

  # https://github.com/zed-0xff/pedump/issues/44
  # https://redmine.ruby-lang.org/issues/12280
  def _copy_stream(src, dst, src_length = nil, src_offset = 0)
    IO::copy_stream(src, dst, src_length, src_offset)
  rescue NotImplementedError # `copy_stream': pread() not implemented (NotImplementedError)
    src_length ||= src.size - src_offset
    bufsize = 16384
    buf = ("\x00".force_encoding('binary')) * bufsize
    src.binmode
    dst.binmode
    saved_pos = src.tell
    src.seek(src_offset)
    bytes_copied = 0
    while src_length > 0 && buf.size != 0
      src.read([bufsize, src_length].min, buf)
      dst.write(buf)
      src_length -= buf.size
      bytes_copied += buf.size
    end
    src.seek(saved_pos)
    bytes_copied
  end
end # class PEdump::CLI
