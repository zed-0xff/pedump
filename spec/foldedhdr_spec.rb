require File.expand_path(File.dirname(__FILE__) + '/spec_helper')
require File.expand_path(File.dirname(__FILE__) + '/../lib/pedump')

[ 'corkami/foldedhdr.exe', 'corkami/foldedhdrW7.exe' ].each do |fname|
  describe fname do
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

    it "should have 1 section" do
      @sample.sections.size.should == 1
      s = @sample.sections.first
      s.VirtualSize.should == 0x1000
      s.VirtualAddress.should == 0x1000
      s.SizeOfRawData.should == 0x200
      s.PointerToRawData.should == 0x200
      s.flags.should == 0xa0000000
    end
  end
end
