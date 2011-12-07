# encoding: utf-8

require 'rubygems'
require 'bundler'
begin
  Bundler.setup(:default, :development)
rescue Bundler::BundlerError => e
  $stderr.puts e.message
  $stderr.puts "Run `bundle install` to install missing gems"
  exit e.status_code
end
require 'rake'

require 'jeweler'
Jeweler::Tasks.new do |gem|
  # gem is a Gem::Specification... see http://docs.rubygems.org/read/chapter/20 for more options
  gem.name = "pedump"
  gem.homepage = "http://github.com/zed-0xff/pedump"
  gem.license = "MIT"
  gem.summary = %Q{dump win32 PE executable files with a pure ruby}
  gem.description = %Q{dump headers, sections, extract resources}
  gem.email = "zed.0xff@gmail.com"
  gem.authors = ["Andrey \"Zed\" Zaikin"]
  gem.executables = %w'pedump'
  gem.files.include "lib/**/*.rb"
  # dependencies defined in Gemfile
end
Jeweler::RubygemsDotOrgTasks.new

require 'rspec/core'
require 'rspec/core/rake_task'
RSpec::Core::RakeTask.new(:spec) do |spec|
  spec.pattern = FileList['spec/**/*_spec.rb']
end

RSpec::Core::RakeTask.new(:rcov) do |spec|
  spec.pattern = 'spec/**/*_spec.rb'
  spec.rcov = true
end

task :default => :spec

#require 'rake/rdoctask'
#Rake::RDocTask.new do |rdoc|
#  version = File.exist?('VERSION') ? File.read('VERSION') : ""
#
#  rdoc.rdoc_dir = 'rdoc'
#  rdoc.title = "pedump #{version}"
#  rdoc.rdoc_files.include('README*')
#  rdoc.rdoc_files.include('lib/**/*.rb')
#end
