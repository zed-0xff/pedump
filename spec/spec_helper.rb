$LOAD_PATH.unshift(File.join(File.dirname(__FILE__), '..', 'lib'))
$LOAD_PATH.unshift(File.dirname(__FILE__))
require 'rspec'
require 'pedump'
require 'fileutils'

DATA_DIR = File.join(File.dirname(__FILE__), "data")
Dir["#{File.dirname(__FILE__)}/support/**/*.rb"].each {|f| require f}

def unarchive_samples fname
  flag_fname = File.join(File.dirname(fname), ".#{File.basename(fname)}_unpacked")
  # check if already unpacked
  return if File.exist?(flag_fname)
  system "7zr", "x", "-y", "-o#{SAMPLES_DIR}", fname
  FileUtils.touch(flag_fname) if $?.success?
end

RSpec.configure do |config|
  config.before :suite do
    Dir[File.join(SAMPLES_DIR,"*.7z")].each do |fname|
      unarchive_samples fname
    end
  end
end
