require File.expand_path(File.dirname(__FILE__) + '/spec_helper')
require File.expand_path(File.dirname(__FILE__) + '/../lib/pedump')

describe 'corkami/imports_vterm.exe' do
  # http://code.google.com/p/corkami/source/browse/trunk/asm/PE/imports_vterm.asm
  #describe "import terminator in virtual space" do
  before :all do
    @imports = sample.imports
  end

  it "should have 2 IMAGE_IMPORT_DESCRIPTORs" do
    @imports.size.should == 2
  end

  it "should have only IMAGE_IMPORT_DESCRIPTORs" do
    @imports.map(&:class).uniq.should == [PEdump::IMAGE_IMPORT_DESCRIPTOR]
  end

#  it "should have all entries thunks equal" do
#    @imports.each do |iid|
#      iid.first_thunk.should == iid.original_first_thunk
#    end
#  end

  describe "1st image_import_descriptor" do
    it "should be from kernel32.dll" do
      @imports[0].module_name.should == "kernel32.dll"
    end
    it "should have 1 function" do
      @imports[0].first_thunk.size.should == 1
    end
    it "should have ExitProcess" do
      @imports[0].first_thunk.first.name.should == "ExitProcess"
      @imports[0].first_thunk.first.hint.should == 0
      @imports[0].first_thunk.first.ordinal.should be_nil
    end
  end

  describe "2nd image_import_descriptor" do
    it "should be from msvcrt.dll" do
      @imports[1].module_name.should == "msvcrt.dll"
    end
    it "should have 1 function" do
      @imports[1].first_thunk.size.should == 1
    end
    it "should have printf" do
      @imports[1].first_thunk.first.name.should == "printf"
      @imports[1].first_thunk.first.hint.should == 0
      @imports[1].first_thunk.first.ordinal.should be_nil
    end
  end
end
