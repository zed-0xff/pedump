#!/usr/bin/env ruby
#require './lib/pedump'
require 'pedump/loader'
require 'pedump/cli'

# TODO: ObjTbl
# TODO: RelTbl
# TODO: ImpTbl
# TODO: OepOfs
# TODO: FlgE8E9

def code2re code
  idx = -1
  Regexp.new(
    code.gsub(/#.*$/,'').split.map do |x|
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

def code2re_dw code, shift=0
  raise "shift must be in 0..3, got #{shift.inspect}" unless (0..3).include?(shift)
  Regexp.new(
    ('X '*shift+code).gsub(/#.*$/,'').split.each_slice(4).map do |a|
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

E8_CODE = <<EOC
  8B 06     #  mov     eax, [esi]
  EB (.)    #  jmp     short ??                ; ModE8E9
  80 3E (.) #  cmp     byte ptr [esi], ??      ; CmpE8E9
  75 F3     #  jnz     short loc_450141
  24 00     #  and     al, 0
  C1 C0 18  #  rol     eax, 18h
  2B C3     #  sub     eax, ebx
  89 06     #  mov     [esi], eax
  83 C3 05  #  add     ebx, 5
  83 C6 04  #  add     esi, 4
  83 E9 05  #  sub     ecx, 5
  EB CE     #  jmp     short loc_450130
EOC

E8_RE = code2re(E8_CODE)

XOR_RE = code2re <<EOC
  81 B2 .... (....)    #   xor     dword ptr [edx-1C6B33E9h], 0F773AEA7h
  E9 1C 00 00 00       #   jmp     loc_40A53C
EOC

#SUB_XOR_RE = code2re <<EOC
#  8B 18                #       mov     ebx, [eax]
#  .{0,6}               #       xor     dh, 11h
#  81 EB (....)         #       sub     ebx, 4F22789h
#  81 F3 (....)         #       xor     ebx, 401CC38Eh
#  .{0,6}               #       mov     dx, 0AE4Eh
#  81 F3 (....)         #       xor     ebx, 5DA8B7AFh
#  .{0,6}               #       movsx   ecx, ax
#  53                   #       push    ebx
#  .{0,6}               #       mov     ecx, 186577BDh
#  8F 00                #       pop     dword ptr [eax]
#EOC

def check_re data, comment = '', re = E8_RE
  if m = data.match(re)
    printf "[=] %-40s %-12s : %8d  %s\n", @fname, comment, m.begin(0), m[1..-1].inspect
    true
  else
    false
  end
end

def scan data
  # check raw
  return if check_re(data)

  (1..255).each do |i|
    # check byte add
    return if check_re(data, "[add b,#{i}]", code2re(E8_CODE){ |x| (x+i)&0xff })
    # check byte xor
    return if check_re(data, "[xor b,#{i}]", code2re(E8_CODE){ |x| x^i })
  end

  # check dword add
  4.times do |octet|
    re = code2re(E8_CODE){ |x,idx| idx%4 == octet ? ((x+1)&0xff) : x }
    return if check_re(data, "[dec dw:#{octet}]", re)
  end

  # check dword xor [INCOMPLETE]
  if m = data.match(XOR_RE)
    xor = m[1].unpack('V').first
    printf "[^] %-40s %-12s : %8d  %x\n", @fname, '[xor dw]', m.begin(0), xor
    4.times do |shift|
      re = code2re_dw(E8_CODE,shift){ |dw| dw ^ xor }
      return if check_re(data, "[xor dw:#{shift}]", re)
    end
    return
  end

  # check dword sub+xor [INCOMPLETE]
#  if m = data.match(SUB_XOR_RE)
#    a = m[1..-1].map{|x| x.unpack('V').first}
#    printf "[^] %-40s %-12s : %8d  %s\n", @fname, '[sub+xor dw]', m.begin(0),
#      a.map{|x| x.to_s(16)}.join(', ')
#    4.times do |shift|
#      re = code2re_dw(E8_CODE,shift) do |dw|
#        dw = (dw^0x581DA039^0x396D3000)-0x0F9B9683
#        dw = (dw^a[1]^a[2]) + a[0]
#      end
#      return if check_re(data, "[xor dw:#{shift}]", re)
#    end
#    return
#  end

  printf "[?] %-40s %-12s\n", @fname, "???"
end

fnames =
  if ARGV.empty?
    Dir['samples/*.{dll,exe,bin,ocx}']
  else
    ARGV
  end

require 'pp'
fnames.each do |fname|
  @fname = File.basename(fname)
  File.open(fname,"rb") do |f|
    pedump = PEdump.new
    next unless packer = pedump.packer(f).first
    next unless packer.name =~ /aspack/i
    #ldr = PEdump::Loader.new(f)
    ldr = PEdump::Loader.new(pedump, f)
    if section = ldr.va2section(ldr.ep)
      section.data # force loading, if deferred (optional)
      #puts "[.] EP section: #{section.inspect}"
    else
      puts "[!] cannot determine EP section"
      next
    end

    scan section.data
  end
end
