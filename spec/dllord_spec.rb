require File.expand_path(File.dirname(__FILE__) + '/spec_helper')
require File.expand_path(File.dirname(__FILE__) + '/../lib/pedump')

describe 'corkami/dllord.dll' do
  it "should have 1 import" do
    sample.imports.size.should == 1
    sample.imports.map(&:module_name).should == %w'msvcrt.dll'
    sample.imports.map do |iid|
      (iid.original_first_thunk + iid.first_thunk).uniq.map(&:name)
    end.flatten.should == ["printf"]
  end

  it "exports at least 2 entries" do
    sample.exports.Base.should == 0x313
    sample.exports.name.should be_nil
    sample.exports.names.should be_empty
    sample.exports.name_ordinals.should be_empty
    sample.exports.entry_points[0].should == 0xffff_ffff
    sample.exports.entry_points[1].should == 0x1008
  end
end
