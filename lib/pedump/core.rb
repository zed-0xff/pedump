require 'logger'
require 'pedump/version'
require 'pedump/logger'

class String
  def xor x
    if x.is_a?(String)
      r = ''
      j = 0
      0.upto(self.size-1) do |i|
        r << (self[i].ord^x[j].ord).chr
        j+=1
        j=0 if j>= x.size
      end
      r
    else
      r = ''
      0.upto(self.size-1) do |i|
        r << (self[i].ord^x).chr
      end
      r
    end
  end
end

class File
  def checked_seek newpos
    @file_range ||= (0..size)
    @file_range.include?(newpos) && (seek(newpos) || true)
  end
end

class PEdump

  module Readable
    def read file, size = nil
      size ||= const_get 'SIZE'
      data = file.read(size).to_s
      if data.size < size && PEdump.logger
        PEdump.logger.error "[!] #{self.to_s} want #{size} bytes, got #{data.size}"
      end
      new(*data.unpack(const_get('FORMAT')))
    end
  end

  class << self
    def logger;    @@logger;   end
    def logger= l; @@logger=l; end

    def create_struct fmt, *args
      size = fmt.scan(/([a-z])(\d*)/i).map do |f,len|
        [len.to_i, 1].max *
          case f
          when /[aAC]/ then 1
          when 'v' then 2
          when 'V' then 4
          when 'Q' then 8
          else raise "unknown fmt #{f.inspect}"
          end
      end.inject(&:+)

      Struct.new( *args ).tap do |x|
        x.const_set 'FORMAT', fmt
        x.const_set 'SIZE',  size
        x.class_eval do
          def pack
            to_a.pack self.class.const_get('FORMAT')
          end
          def empty?
            to_a.all?{ |t| t == 0 || t.nil? || t.to_s.tr("\x00","").empty? }
          end
        end
        x.extend Readable
      end
    end
  end
end
