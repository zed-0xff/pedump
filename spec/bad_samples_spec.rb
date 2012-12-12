require File.expand_path(File.dirname(__FILE__) + '/spec_helper')
require File.expand_path(File.dirname(__FILE__) + '/../lib/pedump')

PEDUMP_BINARY = File.expand_path(File.dirname(__FILE__) + '/../bin/pedump')

Dir[File.join(SAMPLES_DIR,"bad","*.exe")].each do |fname|
  describe fname do
    it "should not cause exception" do
      system "#{PEDUMP_BINARY} -qqq #{fname} > /dev/null"
      $?.should be_success
    end
  end
end
