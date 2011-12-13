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
  gem.description = %Q{dump headers, sections, extract resources of win32 PE exe,dll,etc}
  gem.email = "zed.0xff@gmail.com"
  gem.authors = ["Andrey \"Zed\" Zaikin"]
  gem.executables = %w'pedump'
  gem.files.include "lib/**/*.rb"
  gem.files.include "data/sig.bin"
  gem.files.include "data/sig.txt"
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

class Jeweler::Commands::Version::Base
  alias :commit_version_old :commit_version
  def commit_version
    code = <<-EOF
class PEdump
  module Version
    MAJOR = #{version_helper.major}
    MINOR = #{version_helper.minor}
    PATCH = #{version_helper.patch}
    BUILD = nil

    STRING = [MAJOR, MINOR, PATCH, BUILD].compact.join('.')
  end
end
    EOF
    vfile = working_subdir.join("lib/pedump/version.rb")
    File.open(vfile,"w"){ |f| f << code }
    self.repo.add vfile if self.repo
    commit_version_old
  end
end

namespace :test do
  desc "test on all files in given path"
  task :all_files do
    require './lib/pedump'
    require './lib/pedump/cli'
    path = ENV['path'] || raise("run me with path=...")
    `find #{path} -type f`.split("\n").each do |fname|
      puts "\n### #{fname}\n"
      PEdump::CLI.new(fname).run
    end
  end

  namespace :all_files do
    desc "output file name to stderr, use with stdout redirection"
    task :stderr do
      require './lib/pedump'
      require './lib/pedump/cli'
      path = ENV['path'] || raise("run me with path=...")
      `find #{path} -type f`.split("\n").each do |fname|
        STDERR.puts "\n### #{fname}\n"
        PEdump::CLI.new(fname).run
      end
    end
  end
end

namespace :sig do
  desc "update packers db from http://research.pandasecurity.com/blogs/images/userdb.txt"
  task :update do
    require './lib/pedump/packer'
    fname = PEdump::Packer::TEXT_SIGS_FILE
    url   = "http://research.pandasecurity.com/blogs/images/userdb.txt"

    require 'digest/md5'
    require 'open-uri'
    existing_md5 = Digest::MD5.file(fname).hexdigest
    puts "[.] fetching remote data..."
    remote_data  = open(url).read.force_encoding('cp1252').encode('utf-8')
    puts "[.] got #{remote_data.size} bytes"
    raise "too small remote data (#{remote_data.size})" if remote_data.size < 100_000
    remote_md5   = Digest::MD5.hexdigest(remote_data)
    if remote_md5 == existing_md5
      puts "[.] same as local"
    else
      existing_size = File.size(fname)
      File.open(fname,"wb"){ |f| f << remote_data }
      puts "[*] updated: #{existing_size} -> #{remote_data.size}"
    end
  end

  desc "convert txt2bin"
  task :convert do
    require './lib/pedump/packer'
    t0 = Time.now
    sigs = PEdump::Packer.parse
    printf "[.] parsed %d definitions in %6.3fs\n", sigs.size, Time.now-t0
    File.open(PEdump::Packer::BIN_SIGS_FILE,"wb"){ |f| Marshal.dump(sigs,f) }
  end
end

desc "build readme"
task :readme do
  require 'erb'
  tpl = File.read('README.md.tpl').gsub(/^%\s+(.+)/) do |x|
    x.sub! /^%/,''
    "<%= run(\"#{x}\") %>"
  end
  def run cmd
    cmd.strip!
    puts "[.] #{cmd} ..."
    r = "    # #{cmd}\n\n"
    cmd.sub! /^pedump/,"../bin/pedump"
    lines = `#{cmd}`.sub(/\A\n+/m,'').sub(/\s+\Z/,'').split("\n")
    lines = lines[0,25] + ['...'] if lines.size > 50
    r << lines.map{|x| "    #{x}"}.join("\n")
    r << "\n"
  end
  Dir.chdir 'samples'
  result = ERB.new(tpl,nil,'%>').result
  Dir.chdir '..'
  File.open('README.md','w'){ |f| f << result }
end
