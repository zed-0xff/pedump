require File.expand_path(File.dirname(__FILE__) + '/spec_helper')
require File.expand_path(File.dirname(__FILE__) + '/../lib/pedump')
require File.expand_path(File.dirname(__FILE__) + '/../lib/pedump/cli')
require 'digest/md5'

class CLIReturn < Struct.new(:status, :output)
  def md5
    Digest::MD5.hexdigest(self.output.to_s)
  end
end

def cli args
  output = capture_stdout do
    PEdump::CLI.new(args.split).run
  end
  CLIReturn.new(0, output)
rescue SystemExit
  CLIReturn.new($!.status, "")
end

describe "--extract resource" do
  it "should set errorlevel to 1 if resource is not found" do
    cli("samples/calc.exe --extract resource:0x12345").status.should == 1
  end
  it "should extract resource by hex offset" do
    cli("samples/calc.exe --extract resource:0x98478").md5.should == "84e38f8bb6e3c6f35380f3373050c013"
  end
  it "should extract resource by decimal offset" do
    cli("samples/calc.exe --extract resource:623736").md5.should == "84e38f8bb6e3c6f35380f3373050c013"
  end
  it "should extract resource by type & name" do
    cli(
      "samples/calc.exe --extract resource:BITMAP/IDT_BTN_STR_STATISTICS"
       ).md5.should == "baafb42dcb9d9e817b168b51de013312"
  end
  it "should extract resource by type & ordinal" do
    cli("samples/calc.exe --extract resource:VERSION/#1").md5.should == "64ded21a538a442dcf90e280acb28496"
  end
end

describe "--extract section" do
  it "should set errorlevel to 1 if section is not found" do
    cli("samples/calc.exe --extract section:foo").status.should == 1
  end
  it "should extract section by name" do
    cli("samples/calc.exe --extract section:.text").md5.should == "b7347dffd3d096f0b02ef8e1fe586b97"
  end
  it "should extract section by RVA" do
    cli("samples/calc.exe --extract section:rva/0x1000").md5.should == "b7347dffd3d096f0b02ef8e1fe586b97"
  end
  it "should extract section by RAW_PTR" do
    cli("samples/calc.exe --extract section:raw/0x400").md5.should == "b7347dffd3d096f0b02ef8e1fe586b97"
  end
end

describe "--extract datadir" do
  it "should set errorlevel to 1 if datadir is not found" do
    cli("samples/calc.exe --extract datadir:foo").status.should == 1
  end
  it "should extract empty datadir" do
    cli("samples/calc.exe --extract datadir:EXPORT").output.should == ""
    cli("samples/calc.exe --extract datadir:EXPORT").status.should == 0
  end
  it "should extract datadir by RVA" do
    cli("samples/calc.exe --extract datadir:IMPORT").md5.should == "de0ef456633e7a605a3b5d34921edf0d"
  end
end

describe "--imphash" do
  it "outputs nothing if no imports" do
    cli("samples/bad_imports.exe --imphash").output.should == ""
  end
  it "outputs a line per file" do
    cli("samples/calc.exe samples/notepad.exe --imphash").output.should == "15424d7bd976766dc8b2452077f79c09 samples/calc.exe\n419c3fe8c1eefea9336b96f74f0951dd samples/notepad.exe\n"
  end
end
