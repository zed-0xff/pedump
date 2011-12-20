require File.expand_path(File.dirname(__FILE__) + '/spec_helper')
require File.expand_path(File.dirname(__FILE__) + '/../lib/pedump')

describe 'corkami/virtsectblXP.exe' do
  it "should have 2 imports" do
    sample.imports.size.should == 2
    sample.imports.map(&:module_name).should == %w'kernel32.dll msvcrt.dll'
    sample.imports.map do |iid|
      (iid.original_first_thunk + iid.first_thunk).uniq.map(&:name)
    end.flatten.should == ["ExitProcess", "printf"]
  end
end
