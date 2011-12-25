#!/usr/bin/env ruby
# coding: binary
require 'pedump/loader'
require 'pedump/cli'

# TODO: RelTbl
# TODO: FlgE8E9
# TODO: restore section flags, if any
# TODO: autocompile unlzx

module PEdump::Unpacker; end

class PEdump::Unpacker::ASPack
  attr_accessor :logger

  def self.code2re code
    idx = -1
    was_any = false
    Regexp.new(
      code.strip.
      split("\n").map{|line| line.strip.split('    ',2).first}.join("\n").
      gsub(/\.{2,}/){ |x| x.split('').join(' ') }.
      split.map do |x|
        idx += 1
        case x
        when /\A[a-f0-9]{2}\Z/i
          x = x.to_i(16)
          if block_given?
            x = yield(x,idx)
            if x == :any
              was_any = true
              '.'
            else
              Regexp.escape(x.chr)
            end
          else
            Regexp.escape(x.chr)
          end
        else
          if was_any && (x.count('.') > 1 || x[/[+*?{}]/])
            raise "[!] cannot use :any with more-than-1-char-long #{x.inspect}"
          end
          x
        end
      end.join, Regexp::MULTILINE
    )
  end
  def code2re code, &block; self.class.code2re(code, &block); end

  def code2re_dw code, shift=0
    raise "shift must be in 0..3, got #{shift.inspect}" unless (0..3).include?(shift)
    Regexp.new(
      (
        'X '*shift +
        code.strip.
        split("\n").map{|line| line.strip.split('    ',2).first}.join("\n")
      ).split.each_slice(4).map do |a|
        a.map! do |x|
          case x
          when /\A[a-f0-9]{2}\Z/i
            x.to_i(16)
          else
            x
          end
        end
        dw = a.reverse.inject(0){ |x,y| (x<<8) + (y.is_a?(Numeric) ? y : 0)}
        dw = yield(dw) << 8
        a.map do |x|
          dw >>= 8
          x.is_a?(Numeric) ? Regexp::escape((dw & 0xff).chr) : x
        end
      end.join[shift..-1], Regexp::MULTILINE
    )
  end

  @@xordetect_codes = []

  OBJ_TBL_CODE = <<-EOC
    8D B5 (....)            lea     esi, [ebp+442A5Ah]  ; obj_tbl
    83 3E 00                cmp     dword ptr [esi], 0
    0F 84 . . 00 00         jz      no_obj_tbl
    .{0,6}                  lea     esi, [ebp+442A5Ah]  ; obj_tbl
    6A 04                   push    4
    68 00 10 00 00          push    1000h
    68 00 18 00 00          push    1800h
    6A 00                   push    0
    FF .{2,5}               call    dword ptr [ebp+4429B9h] ; [41503d]
    89 85 ....              mov     [ebp+4429B5h], eax      ; [415039]
    8B 46 04                mov     eax, [esi+4]
  EOC

  VIRTUALPROTECT_RE = code2re <<-EOC
    50                      push    eax
    FF .{2,5}               call    dword ptr [ebp+6Ah] ; VirtualProtect
    59                      pop     ecx
    AD                      lodsd
    AD                      lodsd
    89 47 24                mov     [edi+24h], eax
  EOC

#  CODE1 = <<-EOC
#    8B 44 24 10             mov     eax, [esp+arg_C]
#    81 EC 54 03 00 00       sub     esp, 354h
#    8D 4C 24 04             lea     ecx, [esp+354h+var_350]
#    50                      push    eax
#    E8 A8 03 00 00          call    sub_465A28
#    8B 8C 24 5C 03 00 00    mov     ecx, [esp+354h+arg_4]
#    8B 94 24 58 03 00 00    mov     edx, [esp+354h+arg_0]
#    51                      push    ecx
#    52                      push    edx
#    8D 4C 24 0C             lea     ecx, [esp+35Ch+var_350]
#    E8 0D 04 00 00          call    sub_465AA6
#    84 C0                   test    al, al
#    75 0A                   jnz     short loc_4656A7
#    83 C8 FF                or      eax, 0FFFFFFFFh
#    81 C4 54 03 00 00       add     esp, 354h
#    C3                      retn
#  EOC

  E8_CODE = <<-EOC
    8B 06                   mov     eax, [esi]
    EB (.)                  jmp     short ??                ; ModE8E9
    80 3E (.)               cmp     byte ptr [esi], ??      ; CmpE8E9
    75 F3                   jnz     short loc_450141
    24 00                   and     al, 0
    C1 C0 18                rol     eax, 18h
    2B C3                   sub     eax, ebx
    89 06                   mov     [esi], eax
    83 C3 05                add     ebx, 5
    83 C6 04                add     esi, 4
    83 E9 05                sub     ecx, 5
    EB CE                   jmp     short loc_450130
  EOC
  E8_RE = code2re E8_CODE
  @@xordetect_codes << E8_CODE

  OEP_CODE1 = <<-EOC
    B8 (....)               mov     eax, 101Ah
    50                      push    eax
    03 85 ....              add     eax, [ebp+444A28h]
    59                      pop     ecx
    0B C9                   or      ecx, ecx
    89 85 ....              mov     [ebp+443CF1h], eax
    61                      popa
    75 08                   jnz     short loc_40A3C0
    B8 01 00 00 00          mov     eax, 1
    C2 0C 00                retn    0Ch
  EOC
  OEP_RE1 = code2re OEP_CODE1
  @@xordetect_codes << OEP_CODE1

  OEP_CODE2 = <<-EOC
    8B 85 (....)            mov     eax, [ebp+442A4Eh]  ; 004150D2
    50                      push    eax
    03 85 ....              add     eax, [ebp+4437E0h]  ; [415e64] = self_base
    59                      pop     ecx
    0B C9                   or      ecx, ecx
    89 85 ....              mov     [ebp+442E7Bh], eax  ; offset of '0' of 'push 0' after 'retn 0Ch'
    61                      popa
    75 08                   jnz     short loc_4154FE
    B8 01 00 00 00          mov     eax, 1
    C2 0C 00                retn    0Ch
  EOC
  OEP_RE2 = code2re OEP_CODE2
  @@xordetect_codes << OEP_CODE2

  IMPORTS_CODE1 = <<-EOC
    EB F1                   jmp ...
    BE (....)               mov     esi, 55000h       ; immediate imports rva
    8B 95 ....              mov     edx, [ebp+422h]
    03 F2                   add     esi, edx
    8B 46 0C                mov     eax, [esi+0Ch]
    85 C0                   test    eax, eax
    0F 84 . . 00 00         jz      ep_rva
    03 C2                   add     eax, edx
    8B D8                   mov     ebx, eax
    50                      push    eax
    FF 95 (....)            call    dword ptr [ebp+0F4Dh]
    85 C0                   test    eax, eax
  EOC
  IMPORTS_RE1 = code2re IMPORTS_CODE1
  @@xordetect_codes  << IMPORTS_CODE1

  IMPORTS_CODE2 = <<-EOC
    EB F1                   jmp ...
    8B B5 (....)            mov     esi, [ebp+442A4Ah]  ; [0x4150CE] = imports_rva
    8B 95 ....              mov     edx, [ebp+4437E0h]  ; [0x415e64] = image_base
    03 F2                   add     esi, edx
    8B 46 0C                mov     eax, [esi+0Ch]
    85 C0                   test    eax, eax
    0F 84 . . 00 00         jz      ep_rva
    03 C2                   add     eax, edx
    8B D8                   mov     ebx, eax
    50                      push    eax
    FF 95 (....)            call    dword ptr [ebp+4438F4h] ; 415f78 = GetModuleHandleA
    85 C0                   test    eax, eax
  EOC
  IMPORTS_RE2 = code2re IMPORTS_CODE2
  @@xordetect_codes  << IMPORTS_CODE2

  SECTION_INFO = PEdump.create_struct 'V3', :va, :size, :flags

  ########################################################################

  def initialize io, params = {}
    params[:logger] ||= PEdump::Logger.create(params)
    @logger = params[:logger]
    @ldr = PEdump::Loader.new(io, params)

    @e8e9_mode = @e8e9_cmp = @e8e9_flag = @ebp = nil
  end

  def _decrypt
    @data = @data.dup
    @data.size.times do |j|
      @data[j] = (yield(@data[j].ord,j)&0xff).chr
    end
    @data
  end

  def _decrypt_dw shift=0
    orig_size = @data.size
    @data = @data.dup
    i = shift
    while i < @data.size
      t = @data[i,4]
      t<<"\x00" while t.size < 4
      dw = t.unpack('V').first
      dw = yield(dw)
      @data[i,4] = [dw].pack('V')
      i += 4
    end
    @data = @data[0,orig_size] if @data.size != orig_size
    @data
  end

  def check_re data, comment = '', re = E8_RE
    if m = data.match(re)
      logger.debug "[.] E8_RE %s found at %4x : %-20s" % [comment, m.begin(0), m[1..-1].inspect]
      m
    end
  end

  def decrypt
    r=nil
    # check raw
    return r if r=check_re(@data)

    (1..255).each do |i|
      # check byte add
      if check_re(@data, "[add b,#{i}]", code2re(E8_CODE){ |x| (x+i)&0xff })
        return check_re(_decrypt{|x| x-i})
      end

      # check byte xor
      if check_re(@data, "[xor b,#{i}]", code2re(E8_CODE){ |x| x^i })
        return check_re(_decrypt{|x| x^i})
      end
    end

    # check dword dec
    4.times do |shift|
      re = code2re_dw(E8_CODE,shift){ |dw| dw+1 }
      if r=check_re(@data, "[dec dw:#{shift}]", re)
        shift = (r.begin(0)-shift)%4
        return check_re(_decrypt_dw(shift){ |x| x-1 })
      end
    end

    h = xordetect
    if h && h.size == 4
      h.keys.permutation.each do |xor_bytes|
        xor_dw = xor_bytes.inject{ |x,y| (x<<8) + y}
        re = code2re_dw(E8_CODE){ |dw| dw^xor_dw }
        if r=check_re(@data, "[xor dw:#{xor_dw.to_s(16)}]", re)
          return check_re(_decrypt_dw(r.begin(0)%4){ |dw| dw^xor_dw })
        end
      end
    end

    # failed
    false
  end

  # detects if code is crypted by a dword-xor
  # @data must be original, not modified!
  def xordetect
    logger.info "[*] trying to guess DWORD-XOR key..."
    h = Hash.new{ |k,v| k[v] = 0 }
    @@xordetect_codes.each do |code|
      4.times do |shift|
        0x100.times do |x1|
          re = code2re(code.tr('()','')){ |x,idx| idx%4 == shift ? x^x1 : :any }
          @data.scan(re).each do
            logger.debug "[.] %02x: %6x : %s" % [x1, $~.begin(0), re.inspect]
            h[x1] += 1
          end
        end
      end
    end
    case h.size
    when 0
      logger.debug "[?] %s: zero hash" % __method__
    when 1..3
      logger.info  "[?] %s: not xored, or %d-byte xor key: %s" % [__method__, h.size, h.inspect]
    when 4
      logger.info  "[*] %s: FOUND xor key bytes: [%02x %02x %02x %02x]" % [__method__, *h.keys].flatten
    else
      logger.info  "[?] %s: %d possible bytes: %s" % [__method__, h.size, h.inspect]
    end
    h
  end


  def _scan_obj_tbl
    unless @ebp
      logger.warn "[?] %s: EBP undefined, skipping" % __method__
      return
    end

    re = code2re OBJ_TBL_CODE
    va = nil
    if m = @data.match(re)
      a = m[1..-1].map{|x| x.unpack('V').first }
      logger.debug "[d] OBJ_TBL_RE found at %4x : %s" % [m.begin(0), a.map{|x| x.to_s(16)}.join(', ')]
      va = (a[0] + @ebp) & 0xffff_ffff
      logger.debug "[.] obj_tbl VA = %4x (using EBP)" % va
    else
      logger.error "[!] cannot find obj_tbl"
      return
    end

    # obj_tbl contains flags if there is a call to VirtualProtect in loader code
    record_size = (@data['VirtualProtect'] && @data[VIRTUALPROTECT_RE]) ? 4*3 : 4*2

    r = []
    while true
      obj = SECTION_INFO.new(*@ldr[va, record_size].unpack(SECTION_INFO::FORMAT))
      break if obj.va == 0
      unless @ldr.va2section(obj.va)
        logger.error "[!] can't get section for obj %4x : %4x" % [obj.va, obj.size]
      end
      va += record_size
      r << obj
      if r.size > 0x200
        logger.error "[!] stopped obj_tbl parsing. too many sections!"
        break
      end
    end
    r
  end

  ########################################################################

  def find_e8e9
    if m = check_re(@data)
      @e8e9_flag, @e8e9_cmp = m[1], m[2]
      logger.debug "[.] E8/E9: flag=%02x, cmp=%02x" % [@e8e9_flag.ord, @e8e9_cmp.ord]
    else
      logger.error "[!] can't find E8/E9 patch sub! unpacked code may be invalid!"
    end
  end

  def find_obj_tbl
    if @obj_tbl = _scan_obj_tbl
      if logger.level <= ::Logger::INFO
        @obj_tbl.each do |obj|
          if obj.flags
            logger.info "[.] ASP::SECTION va: %8x  size: %8x  flags: %8x" % [obj.va, obj.size, obj.flags]
          else
            logger.info "[.] ASP::SECTION va: %8x  size: %8x" % [obj.va, obj.size]
          end
        end
      end
    end
  end

  def find_oep
    @oep = nil
    if m = @data.match(OEP_RE1)
      logger.debug "[.] OEP_RE1 found at %4x" % m.begin(0)
      @oep = m[1].unpack('V').first
    elsif @ebp && m = @data.match(OEP_RE2)
      logger.debug "[.] OEP_RE2 found at %4x (using EBP)" % m.begin(0)
      offset = m[1].unpack('V').first
      @oep = @ldr[(@ebp + offset) & 0xffff_ffff, 4].unpack('V').first
    end

    if @oep
      logger.info "[.] OEP = %8x" % @oep
    else
      logger.error "[!] cannot find EntryPoint"
    end
  end

  def find_imports
    @imports_rva = nil
    if m = @data.match(IMPORTS_RE1)
      a = m[1..-1].map{|x| x.unpack('V').first }
      @imports_rva = a[0]
    elsif m = @data.match(IMPORTS_RE2)
      a = m[1..-1].map{|x| x.unpack('V').first }
    else
      logger.error "[!] cannot find imports"
      return
    end
    logger.debug "[d] IMPORTS_REx found at %4x : %s" % [m.begin(0), a.map{|x| x.to_s(16)}.join(', ')]

    # actually following code is not necessary for IMPORTS_RE1
    # using it to get EBP register value

    f = @ldr.pedump.imports.map(&:first_thunk).flatten.compact.find{ |x| x.name == "GetModuleHandleA"}
    unless f
      logger.error "[!] GetModuleHandleA not found"
      return
    end
    vaGetModuleHandle = f.va
    logger.debug "[d] GetModuleHandle is at %x" % vaGetModuleHandle
    @ebp = (f.va - a[1]) & 0xffff_ffff
    logger.debug "[d] assume EBP = %x" % @ebp

    # @imports_rva may already be filled by IMPORTS_RE1
    @imports_rva ||= @ldr[(@ebp + a[0]) & 0xffff_ffff, 4].unpack('V').first
    logger.info "[.] imports RVA = %x" % @imports_rva
  end

  def unpack
    if section = @ldr.va2section(@ldr.ep)
      section.data # force loading, if deferred (optional)
      logger.debug "[.] EP section: #{section.inspect}"
    else
      logger.fatal "[!] cannot determine EP section"
      return
    end

    @data = section.data

    decrypt
    #xordetect

    find_e8e9    # must find e8/e9 before any other b/c it also decrypts @data
    find_imports # must find imports BEFORE OEP, b/c OEP find uses @ebp filled in imports
    find_obj_tbl
    find_oep
  end
end

##########################################################################

if __FILE__ == $0
  fnames =
    if ARGV.empty?
      Dir['samples/*.{dll,exe,bin,ocx}']
    else
      ARGV
    end

  require 'pp'
  fnames.each do |fname|
    @fname = fname
    File.open(fname,"rb") do |f|
      pedump = PEdump.new :log_level => Logger::DEBUG
      next unless packer = Array(pedump.packer(f)).first
      next unless packer.name =~ /aspack/i

      puts "\n=== #{fname}".green

      f.rewind
      unpacker = PEdump::Unpacker::ASPack.new(f, :log_level => Logger::DEBUG)
      unpacker.unpack
    end
  end
end

