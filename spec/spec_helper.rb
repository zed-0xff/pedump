$LOAD_PATH.unshift(File.join(File.dirname(__FILE__), '..', 'lib'))
$LOAD_PATH.unshift(File.dirname(__FILE__))
require 'rspec'
require 'pedump'

# Requires supporting files with custom matchers and macros, etc,
# in ./support/ and its subdirectories.
Dir["#{File.dirname(__FILE__)}/support/**/*.rb"].each {|f| require f}

RSpec.configure do |config|
end

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
      fname = File.expand_path(File.dirname(__FILE__) + '/../samples/' + fname)
      File.open(fname,"rb") do |f|
        PEdump.new(fname).dump
      end
    end
end
