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
  class << self
    def logger;    @@logger;   end
    def logger= l; @@logger=l; end
  end
end
