require File.expand_path(File.dirname(__FILE__) + '/spec_helper')
require File.expand_path(File.dirname(__FILE__) + '/../lib/pedump')
require File.expand_path(File.dirname(__FILE__) + '/../lib/pedump/cli')
require 'digest/md5'

describe "--extract" do
  it "should extract resource by hex offset" do
    output = capture_stdout do
      PEdump::CLI.new("samples/calc.exe --extract resource:0x98478".split).run
    end
    Digest::MD5.hexdigest(output).should == "84e38f8bb6e3c6f35380f3373050c013"
  end

  it "should extract resource by decimal offset" do
    output = capture_stdout do
      PEdump::CLI.new("samples/calc.exe --extract resource:623736".split).run
    end
    Digest::MD5.hexdigest(output).should == "84e38f8bb6e3c6f35380f3373050c013"
  end

  it "should extract resource by type & name" do
    output = capture_stdout do
      PEdump::CLI.new("samples/calc.exe --extract resource:BITMAP/IDT_BTN_STR_STATISTICS".split).run
    end
    Digest::MD5.hexdigest(output).should == "baafb42dcb9d9e817b168b51de013312"
  end

  it "should extract resource by type & ordinal" do
    output = capture_stdout do
      PEdump::CLI.new("samples/calc.exe --extract resource:VERSION/#1".split).run
    end
    Digest::MD5.hexdigest(output).should == "64ded21a538a442dcf90e280acb28496"
  end
end
