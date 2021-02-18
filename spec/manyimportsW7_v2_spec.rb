#coding: binary
require File.expand_path(File.dirname(__FILE__) + '/spec_helper')
require File.expand_path(File.dirname(__FILE__) + '/../lib/pedump')

# uploaded by someone: https://pedump.me/1cfd896e77173e512e1627804e03317a/
describe "corkami/manyimportsW7.v2.exe" do
  before :all do
    @sample = sample
  end

  it "should have 2 imports" do
    @sample.imports.size.should == 3
    @sample.imports.map(&:module_name).should == ["kernel32.dll", "msvcrt.dll", "<\x11"]
    @sample.imports.map do |iid|
      (iid.original_first_thunk + iid.first_thunk).uniq.map(&:name)
    end.flatten[0,2].should == ["ExitProcess", "printf"]
  end

  it "should have 1 TLS" do
    @sample.tls.size.should == 1
    @sample.tls.first.AddressOfIndex.should == 0x501148
    @sample.tls.first.AddressOfCallBacks.should == 0x401080
  end
end
