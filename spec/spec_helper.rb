$LOAD_PATH.unshift(File.join(File.dirname(__FILE__), '..', 'lib'))
$LOAD_PATH.unshift(File.dirname(__FILE__))
require 'rspec'
require 'pedump'

# Requires supporting files with custom matchers and macros, etc,
# in ./support/ and its subdirectories.
Dir["#{File.dirname(__FILE__)}/support/**/*.rb"].each {|f| require f}

RSpec.configure do |config|
  config.before :suite do
    Dir[File.join(SAMPLES_DIR,"*.7z")].each do |fname|
      system "7zr", "x", "-y", "-o#{SAMPLES_DIR}", fname
    end
  end
end
