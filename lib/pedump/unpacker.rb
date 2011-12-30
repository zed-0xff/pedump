require 'pedump'
require 'pedump/unpacker/aspack'
require 'pedump/unpacker/upx'

module PEdump::Unpacker
  class << self
    def find io
      if io.is_a?(String)
        return File.open(io,"rb"){ |f| find(f) }
      end

      pedump = PEdump.new(io)
      packer = Array(pedump.packers).first
      return nil unless packer

      case packer.name
      when /UPX/
        UPX
      when /ASPack/i
        ASPack
      else
        nil
      end
    end
  end
end
