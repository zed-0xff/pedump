require 'spec_helper'
require 'pedump/loader'

describe PEdump::Loader do
  before do
    io = open("samples/calc.exe","rb")
    @ldr = PEdump::Loader.new io
  end

  it "should read names from imports" do
    @ldr.names.should_not be_nil
    @ldr.names.should_not be_empty
    @ldr.names.size.should >= 343
    @ldr.names[0x10010d0].should == 'GetStartupInfoA'
  end
end
