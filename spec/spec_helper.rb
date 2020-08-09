$LOAD_PATH.unshift(File.join(File.dirname(__FILE__), '..', 'lib'))
$LOAD_PATH.unshift(File.dirname(__FILE__))
require 'rspec'
require 'fileutils'
require 'pedump'
require 'stringio'

DATA_DIR = File.join(File.dirname(__FILE__), "data")
Dir["#{File.dirname(__FILE__)}/support/**/*.rb"].each {|f| require f}

def unarchive_samples fname
  flag_fname = File.join(File.dirname(fname), ".#{File.basename(fname)}_unpacked")
  # check if already unpacked
  return if File.exist?(flag_fname)
  system "7zr", "x", "-y", "-o#{SAMPLES_DIR}", fname
  FileUtils.touch(flag_fname) if $?.success?
end

def capture_stdout(&blk)
  old = $stdout
  $stdout = fake = StringIO.new
  blk.call
  fake.string
ensure
  $stdout = old
end

RSpec.configure do |config|
  # http://rspec.info/blog/2012/06/rspecs-new-expectation-syntax/
  config.expect_with :rspec do |c|
    c.syntax = :should
  end
  config.before :suite do
    Dir[File.join(SAMPLES_DIR,"*.7z")].each do |fname|
      unarchive_samples fname
    end
  end
end
