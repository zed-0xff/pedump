require File.expand_path(File.dirname(__FILE__) + '/spec_helper')

describe "PEdump" do
  describe "#ordlookup" do
    it "should lookup known ordinals" do
      PEdump.ordlookup("ws2_32.dll", 1).should == "accept"
    end

    it "should return nil for unknown ordinals" do
      PEdump.ordlookup("ws2_32.dll", 9999).should be_nil
    end
  end

  context "make_name = true" do
    it "should make name for unknown ordinals" do
      PEdump.ordlookup("ws2_32.dll", 9999, make_name: true).should == "ord9999"
    end
  end

  context "make_name = false" do
    it "should return nil for unknown ordinals" do
      PEdump.ordlookup("ws2_32.dll", 9999, make_name: false).should be_nil
    end
  end
end
