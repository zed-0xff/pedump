require File.expand_path(File.dirname(__FILE__) + '/spec_helper')
require File.expand_path(File.dirname(__FILE__) + '/../lib/pedump/packer')

describe "PEdump::Packer" do
  describe "matchers" do
    if ENV['SLOW']
      PEdump::SigParser.parse(:raw => true).each do |sig|
        data = sig.re.join
        next if data == "This program cannot be run in DOS mo"
        it "should find #{sig.name}" do
          a = PEdump::Packer.of(data).map(&:name)
          a.size.should > 0

          a = sig.name.split - a.join(' ').split - ['Exe','PE']
          a.delete_if{ |x| x[/[vV\.\/()\[\]]/] }
          p a if a.size > 1
          a.size.should < 2
        end
      end
    else
      pending "SLOW"
    end
  end
end
