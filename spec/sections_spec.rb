require File.expand_path(File.dirname(__FILE__) + '/spec_helper')
require File.expand_path(File.dirname(__FILE__) + '/../lib/pedump')
require 'yaml'

['calc.exe', 'bad/data_dir_15_entries.exe'].each do |fname|
  describe fname do
    it "should match saved sections info" do
      sections = nil
      begin
        # tested with ruby 3.0.3
        sections = YAML::load_file(
          File.join(DATA_DIR,"#{File.basename(fname)}_sections.yml"),
          permitted_classes: [Symbol, PEdump::IMAGE_SECTION_HEADER]
        )
      rescue
        # old ruby?
        sections = YAML::load_file(
          File.join(DATA_DIR,"#{File.basename(fname)}_sections.yml")
        )
      end
      sample.sections.should == sections
    end
  end
end
