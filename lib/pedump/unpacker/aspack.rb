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
    Regexp.new(
      code.strip.
      split("\n").map{|line| line.strip.split('    ',2).first}.join("\n").
      split.map do |x|
        idx += 1
        case x
        when /\A[a-f0-9]{2}\Z/i
          x = x.to_i(16)
          Regexp.escape((block_given? ? yield(x,idx) : x).chr)
        else
          x
        end
      end.join, Regexp::MULTILINE
    )
  end
  def code2re code, &block; self.class.code2re(code, &block); end

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
  E8_RE = code2re(E8_CODE)

  OEP_RE1 = code2re <<-EOC
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

  OEP_RE2 = code2re <<-EOC
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

  IMPORTS_RE1 = code2re <<-EOC
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

  IMPORTS_RE2 = code2re <<-EOC
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
#    75 07                   jnz     short loc_4153E9
#    53                      push    ebx
#    FF 95 (....)            call    dword ptr [ebp+4438F8h] ; 415f7c = LoadLibraryA

  XOR_RE = code2re <<-EOC
    81 B2 .... (....)       xor     dword ptr [edx-1C6B33E9h], 0F773AEA7h
    E9 1C 00 00 00          jmp     loc_40A53C
  EOC

  SECTION_INFO = PEdump.create_struct 'V3', :va, :size, :flags

  def initialize io, params = {}
    params[:logger] ||= PEdump::Logger.create(params)
    @logger = params[:logger]
    @ldr = PEdump::Loader.new(io, params)

    @e8e9_mode = @e8e9_cmp = @e8e9_flag = @ebp = nil
  end

  def check_re data, comment = '', re = E8_RE
    if m = data.match(re)
      #printf "[=] %-40s %-12s : %8d  %s\n", @fname, comment, m.begin(0), m[1..-1].inspect
      logger.debug "[.] E8_RE %s found at %4x : %-20s" % [comment, m.begin(0), m[1..-1].inspect]
#      re = code2re CODE1
#      if m = data.match(re)
#        printf "[.] CODE1  found at %4x\n", m.begin(0)
#        pos = m.begin(0) - 0xf0
#        printf "[.] OBJTBL %8x %8x\n", *data[pos,8].unpack('V*')
#      else
#        puts "[?] no step2"
#      end
#      puts
      m
    end
  end

  def _scan_e8e9
    r=nil
    # check raw
    return r if r=check_re(@data)

    (1..255).each do |i|
      # check byte add
      return r if r=check_re(@data, "[add b,#{i}]", code2re(E8_CODE){ |x| (x+i)&0xff })
      # check byte xor
      return r if r=check_re(@data, "[xor b,#{i}]", code2re(E8_CODE){ |x| x^i })
    end

    # check dword add
    4.times do |octet|
      re = code2re(E8_CODE){ |x,idx| (idx%4) == octet ? ((x+1)&0xff) : x }
      return r if r=check_re(@data, "[dec dw:#{octet}]", re)
    end

    # check dword xor [INCOMPLETE]
    if m = @data.match(XOR_RE)
      xor = m[1] #.unpack('V').first
      printf "[^] %-40s %-12s : %8d  %x\n", @fname, '[xor dw]', m.begin(0), xor.unpack('V').first
      4.times do |octet|
        re = code2re(E8_CODE){ |x,idx| x^xor[(idx+octet)%4].ord }
        return r if r=check_re(@data, "[xor dw:#{octet}]", re)
      end
      return
    end
  end

#  def _scan_obj_tbl0
#    re = code2re CODE1
#    pos = nil
#    if m = @data.match(re)
#      logger.debug "[d] CODE1  found at %4x" % m.begin(0)
#      pos = m.begin(0) - 0xf0
#    else
#      return
#    end
#
#    a = @data[pos, 4*4].unpack('V*')
#    if a[0] == @ldr.sections[0].va && a[1] <= @ldr.sections[0].vsize &&
#       a[2] == @ldr.sections[1].va && a[3] <= @ldr.sections[0].vsize
#
#      r = []
#      while true
#        obj = ASP_OBJ.new(*@data[pos, ASP_OBJ::SIZE].unpack(ASP_OBJ::FORMAT))
#        break if obj.va == 0
#        r << obj
#        pos += ASP_OBJ::SIZE
#      end
#      r
#    else
#      logger.error "[!] %s FAIL at %4x: %s" % [__method__, pos, a.map{|x| x.to_s(16)}.join(', ')]
#      nil
#    end
#  end

  def _scan_obj_tbl
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

#    a = @ldr[va, 4*2*3].unpack('V*'); record_size = nil
#    if a[0] == @ldr.sections[0].va && a[1] <= @ldr.sections[0].vsize &&
#       a[2] == @ldr.sections[1].va && a[3] <= @ldr.sections[0].vsize
#
#      # va, size
#      record_size = 4*2
#    elsif a[0] == @ldr.sections[0].va && a[1] <= @ldr.sections[0].vsize &&
#          a[3] == @ldr.sections[1].va && a[4] <= @ldr.sections[0].vsize
#
#      # va, size, flags
#      record_size = 4*3
#    else
#      logger.error "[!] %s FAIL at %8x: %s" % [__method__, va, a.map{|x| x.to_s(16)}.join(', ')]
#      @ldr.sections.each do |s|
#        logger.error "\toriginal:    %-10s %8x%8x" % [s.name, s.va, s.vsize]
#      end
#      return nil
#    end

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
    if m = _scan_e8e9
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

    find_imports # must find imports BEFORE OEP, b/c OEP find uses @ebp filled in imports
    find_e8e9
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
      next unless packer = pedump.packer(f).first
      next unless packer.name =~ /aspack/i

      puts "\n=== #{fname}"

      f.rewind
      unpacker = PEdump::Unpacker::ASPack.new(f, :log_level => Logger::DEBUG)
      unpacker.unpack
    end
  end
end

