root = File.expand_path(File.dirname(File.dirname(File.dirname(__FILE__))))
require "#{root}/spec/spec_helper"
require "#{root}/lib/pedump/unpacker"

describe PEdump::Unpacker do
  it "finds UPX" do
    PEdump::Unpacker.find("#{root}/samples/calc_upx.exe").should == PEdump::Unpacker::UPX
  end

  it "finds ARM UPX" do
    PEdump::Unpacker.find("#{root}/samples/arm_upx.exe").should == PEdump::Unpacker::UPX
  end

  it "finds ASPack" do
    PEdump::Unpacker.find("#{root}/samples/calc.asp212.exe").should == PEdump::Unpacker::ASPack
  end

  it "finds nothing" do
    PEdump::Unpacker.find("#{root}/samples/calc.exe").should be_nil
  end
end
