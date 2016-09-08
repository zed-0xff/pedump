SAMPLES_DIR = File.expand_path(File.dirname(__FILE__) + '/../../samples/')

def sample
  @pedump ||=
    begin
      fname = self.class.description
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

