require File.expand_path(File.dirname(__FILE__) + '/spec_helper')
require File.expand_path(File.dirname(__FILE__) + '/../lib/pedump')

describe "corkami/manyimportsW7.exe" do
  before :all do
    @sample = sample
  end

  it "should have 2 imports" do
    @sample.imports.size.should == 2
    @sample.imports.map(&:module_name).should == %w'kernel32.dll msvcrt.dll'
    @sample.imports.map do |iid|
      (iid.original_first_thunk + iid.first_thunk).uniq.map(&:name)
    end.flatten.should == ["ExitProcess", "printf"]
  end

  it "should have 1 TLS" do
    @sample.tls.size.should == 1
    @sample.tls.first.AddressOfIndex.should == 0x401148
    @sample.tls.first.AddressOfCallBacks.should == 0x401100
  end
end
