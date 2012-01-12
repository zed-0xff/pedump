require File.expand_path(File.dirname(__FILE__) + '/spec_helper')
require File.expand_path(File.dirname(__FILE__) + '/../lib/pedump')

%w'calc_upx.exe arm_upx.exe'.each do |fname|
  describe fname do
    before :all do
      File.open(File.join("samples",fname),"rb") do |f|
        @packer = PEdump.new(f).packer.first
      end
    end

    it "should detect UPX" do
      @packer.should_not be_nil
      @packer.name.should include 'UPX'
    end
  end
end
