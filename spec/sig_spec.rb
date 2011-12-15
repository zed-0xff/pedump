require File.expand_path(File.dirname(__FILE__) + '/spec_helper')
require File.expand_path(File.dirname(__FILE__) + '/../lib/pedump/packer')

describe "PEdump::Packer" do
  it "should have enough signatures" do
    PEdump::Packer.count.should > 1000
  end

  it "should not match" do
    maxlen = PEdump::Packer.map(&:size).max
    s = 'x'*maxlen
    PEdump::Packer.of_data(s).should be_nil
  end

  it "should parse" do
    a = PEdump::Packer.parse
    a.should be_instance_of(Array)
    a.map(&:class).uniq.should == [PEdump::Packer]
  end

  it "should not react to DOS signature" do
    data = "This program cannot be run in DOS mode"
    PEdump::Packer.of(data).should be_nil
  end
end
