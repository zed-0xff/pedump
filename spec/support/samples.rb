SAMPLES_DIR = File.expand_path(File.dirname(__FILE__) + '/../../samples/')

def sample
  @pedump ||=
    begin
      fname =
        if self.example
          # called from it(...)
          self.example.full_description.split.first
        else
          # called from before(:all)
          self.class.metadata[:example_group][:description_args].first
        end
      fname = File.join(SAMPLES_DIR, fname)
      File.open(fname,"rb") do |f|
        if block_given?
          yield PEdump.new(f)
        else
          PEdump.new(f).dump
        end
      end
    end
end

