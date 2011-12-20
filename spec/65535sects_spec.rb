require File.expand_path(File.dirname(__FILE__) + '/spec_helper')
require File.expand_path(File.dirname(__FILE__) + '/../lib/pedump')

describe 'corkami/65535sects.exe' do
  it "should have 65535 sections" do
    sample.sections.size.should == 65535
  end
end
