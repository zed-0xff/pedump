require File.expand_path(File.dirname(__FILE__) + '/spec_helper')
require File.expand_path(File.dirname(__FILE__) + '/../lib/pedump')

4.times do |i|
  describe "ne#{i}.exe" do
    it "should have NE header" do
      sample do |f|
        f.ne.should_not be_nil
      end
    end

    it "should have NE segments" do
      sample do |f|
  #      p f.ne.segments
        f.ne.segments.size.should == f.ne.ne_cseg
      end
    end

    it "should have NE resources" do
      sample do |f|
        pp f.ne.resources
      end
    end
  end
end
