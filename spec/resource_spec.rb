require File.expand_path(File.dirname(__FILE__) + '/spec_helper')
require File.expand_path(File.dirname(__FILE__) + '/../lib/pedump')

describe 'PEdump' do
  it "should get all resources" do
    fname = File.expand_path(File.dirname(__FILE__) + '/../samples/calc.exe')
    File.open(fname,"rb") do |f|
      @pedump = PEdump.new(fname)
      @resources = @pedump.resources(f)
    end
    @resources.size.should == 71
  end
end
