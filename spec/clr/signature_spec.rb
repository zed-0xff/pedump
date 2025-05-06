#coding: binary
require_relative "../../spec/spec_helper"

describe PEdump::CLR::MethodRefSig do
  it "decodes System.String.get_Length" do
    data = "20 00 08 05".split.map{ |x| x.to_i(16).chr }.join
    sig = described_class.new(StringIO.new(data))
    sig.params.should == []
    sig.ret_type.should == 'int'
  end

  it "decodes System.String.op_Equality" do
    data = "00 02 02 0e 0e 04".split.map{ |x| x.to_i(16).chr }.join
    sig = described_class.new(StringIO.new(data))
    sig.params.should == ["string", "string"]
    sig.ret_type.should == 'bool'
  end

  it "decodes System.Drawing.Color.get_Blue" do
    data = "00 00 11 09 03".split.map{ |x| x.to_i(16).chr }.join
    sig = described_class.new(StringIO.new(data))
    sig.params.should == []
    sig.ret_type.should == "VALUE 1000002"
  end

  it "decodes System.Windows.Forms.Control.Invalidate" do
    data = "20 00 01 04".split.map{ |x| x.to_i(16).chr }.join
    sig = described_class.new(StringIO.new(data))
    sig.params.should == []
    sig.ret_type.should == "void"
  end
end
