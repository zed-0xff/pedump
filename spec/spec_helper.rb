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
      fname = self.example.full_description.split.first
      fname = File.expand_path(File.dirname(__FILE__) + '/../samples/' + fname)
      File.open(fname,"rb") do |f|
        PEdump.new(fname).dump
      end
    end
end
