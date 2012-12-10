require File.expand_path(File.dirname(__FILE__) + '/spec_helper')
require File.expand_path(File.dirname(__FILE__) + '/../lib/pedump')

describe 'bad_imports.exe' do
  before :all do
    @imports = sample.imports
  end

  it "should have IMAGE_IMPORT_DESCRIPTOR" do
    @imports.size.should == 1
  end

  it "should have only IMAGE_IMPORT_DESCRIPTORs" do
    @imports.map(&:class).uniq.should == [PEdump::IMAGE_IMPORT_DESCRIPTOR]
  end

  it "should not detect packer" do
    sample.packer.should be_nil
  end
end
