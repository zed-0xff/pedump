require File.expand_path(File.dirname(__FILE__) + '/spec_helper')

describe "PEdump#dump" do
  describe "should save packer" do
    it "when arg is a filename" do
      dump = PEdump.dump("samples/arm_upx.exe", :log_level => Logger::FATAL)
      dump.packers.size.should == 1
      dump.packers.first.name.should =~ /UPX/
    end

    it "when arg is an IO" do
      File.open("samples/arm_upx.exe", "rb") do |f|
        dump = PEdump.dump(f, :log_level => Logger::FATAL)
        dump.packers.size.should == 1
        dump.packers.first.name.should =~ /UPX/
      end
    end
  end
end
