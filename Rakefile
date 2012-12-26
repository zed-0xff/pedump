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
  gem.files.include "data/*.bin"
  gem.files.include "data/*.txt"

  gem.files.exclude "samples/*", "README.md.tpl"
  gem.extra_rdoc_files.exclude "README.md.tpl"
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

  desc "test on corkami binaries"
  task :corkami do
      require './lib/pedump'
      require './lib/pedump/cli'
      path = "samples/corkami"
      `find #{path} -type f`.split("\n").each do |fname|
        STDERR.puts "\n### #{fname}\n"
        PEdump::CLI.new(fname).run
      end
  end
end

def check_file url, prefix=nil
  require 'digest/md5'
  require 'open-uri'

  STDOUT.sync = true
  fname = File.join 'data', (prefix ? "#{prefix}-" : '') + File.basename(url)
  existing_md5 = File.exist?(fname) ? Digest::MD5.file(fname).hexdigest : ''
  print "[.] fetching #{url} .. "
  remote_data  = open(url).read.force_encoding('cp1252').encode('utf-8')
  puts "#{remote_data.size} bytes"
  raise "too small remote data (#{remote_data.size})" if remote_data.size < 80_000
  remote_md5   = Digest::MD5.hexdigest(remote_data)
  if remote_md5 == existing_md5
    puts "[.] same as local"
  else
    existing_size = File.exist?(fname) ? File.size(fname) : 0
    File.open(fname,"wb"){ |f| f << remote_data }
    puts "[*] updated: #{existing_size} -> #{remote_data.size}"
  end
end

namespace :sigs do
  desc "update packers db from net"
  task :update do
    require './lib/pedump/packer'
    check_file "http://research.pandasecurity.com/blogs/images/userdb.txt"
    check_file "http://fuu.googlecode.com/svn/trunk/src/x86/Tools/Signaturesdb/signatures.txt"
    check_file "http://handlers.sans.edu/jclausing/userdb.txt", "jc"
  end

  desc "convert txt2bin"
  task :convert do
    require './lib/pedump/packer'
    t0 = Time.now
    sigs = PEdump::SigParser.parse :optimize => true, :verbose => true
    printf "[.] parsed %d definitions in %6.3fs\n", sigs.size, Time.now-t0
    File.open(PEdump::Packer::BIN_SIGS_FILE,"wb"){ |f| Marshal.dump(sigs,f) }
  end

  desc "dump"
  task :dump do
    require './lib/pedump/packer'
    require 'awesome_print'
    PEdump::Packer.all.
      group_by{ |sig| sig.name }.
      sort_by{|name,sigs| name }.
      each do |name,sigs|
        next if sigs.size == 1
        puts name.green
        sigs.each do |sig|
          printf "    %-5s  %s\n", sig.ep_only, sig.re.source.inspect
        end
      end
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

namespace :console do
  desc "start console with PEdump::Loader with loaded file"
  task :load do
    raise "gimme a fname" unless fname = ENV['fname']
    require './lib/pedump'
    require './lib/pedump/loader'
    require 'pp'
    File.open(fname,"rb") do |f|
      @ldr = PEdump::Loader.new f
      puts "[.] loader is at @ldr"
      pp @ldr.sections
      Rake::Task["console"].execute
    end
  end
end

desc "compare two PE files"
task :cmp do
  raise "gimme a f1" unless f1 = ENV['f1']
  raise "gimme a f2" unless f2 = ENV['f2']
  require './lib/pedump'
  require './lib/pedump/comparer'
  PEdump::Comparer.cmp(f1,f2)
end
