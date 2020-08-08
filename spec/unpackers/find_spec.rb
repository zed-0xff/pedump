root = File.expand_path(File.dirname(File.dirname(File.dirname(__FILE__))))
require "#{root}/spec/spec_helper"
require "#{root}/lib/pedump/unpacker"

describe PEdump::Unpacker do
  it "finds UPX" do
    described_class.find("#{root}/samples/calc_upx.exe").should == described_class::UPX
  end

  it "finds ARM UPX" do
    described_class.find("#{root}/samples/arm_upx.exe").should == described_class::UPX
  end

  it "finds ASPack" do
    described_class.find("#{root}/samples/calc.asp212.exe").should == described_class::ASPack
  end

  it "finds nothing" do
    described_class.find("#{root}/samples/calc.exe").should be_nil
  end
end
