#!/usr/bin/env ruby
# coding: binary
require 'pedump/loader'
require 'pedump/cli'

module PEdump::Unpacker; end

class PEdump::Unpacker::UPX
  def self.unpack src_fname, dst_fname, log = ''
    log << `upx -dqq #{src_fname} -o #{dst_fname} 2>&1`
    $?.success?
  end
end
