require File.expand_path(File.dirname(__FILE__) + '/spec_helper')
require File.expand_path(File.dirname(__FILE__) + '/../lib/pedump/packer')

describe "PEdump::Packer" do
  describe "matchers" do
    PEdump::Packer.parse(:raw => true).each do |sig|
      data = sig.re.join
      next if data == "This program cannot be run in DOS mo"
      it "should find #{sig.name}" do
        PEdump::Packer.of(data).map(&:name).should include(sig.name)
      end
    end
  end
end
