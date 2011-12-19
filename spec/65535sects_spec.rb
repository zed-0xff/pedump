require File.expand_path(File.dirname(__FILE__) + '/spec_helper')
require File.expand_path(File.dirname(__FILE__) + '/../lib/pedump')

describe 'a PE file with 65535 sections' do
  before :all do
    fname = File.expand_path(File.dirname(__FILE__) + '/../samples/65535sects.exe')
    File.open(fname,"rb") do |f|
      @pedump = PEdump.new(fname)
      @sections = @pedump.sections(f)
    end
  end

  it "should have 65535 sections" do
    @sections.size.should == 65535
  end
end
