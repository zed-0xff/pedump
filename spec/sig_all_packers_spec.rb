#coding: binary
require File.expand_path(File.dirname(__FILE__) + '/spec_helper')
require File.expand_path(File.dirname(__FILE__) + '/../lib/pedump/packer')

describe "PEdump::Packer" do
  describe "matchers" do
    PEdump::SigParser.parse(:raw => true).each do |sig|
      data = sig.re.map do |el|
        case el
        when /\A\[\\x(\h\h).+\]\z/
          $1.to_i(16).chr
        else
          el
        end
      end.join
      next if data == "This program cannot be run in DOS mo"

      it "should find #{sig.name}" do
        a = PEdump::Packer.of(data)
        a.should_not be_nil
        a.size.should > 0

        names = a.map(&:name)
        names = sig.name.split - names.join(' ').split - ['Exe','PE']
        names.delete_if{ |x| x[/[vV\.\/()\[\]]/] }
        p names if names.size > 1
        names.size.should < 2
      end
    end
  end
end
