# frozen_string_literal: true

require 'bundler/gem_tasks'
require 'rspec/core/rake_task'

desc 'run specs'
RSpec::Core::RakeTask.new

task default: %i[spec readme]

task :init do
  $LOAD_PATH.unshift(File.join(File.dirname(__FILE__), 'lib'))
  require 'pedump'
  require 'pedump/cli'
end

namespace :test do
  desc 'test on all files in given path'
  task all_files: :init do
    path = ENV['path'] || raise('run me with path=...')
    `find #{path} -type f`.split("\n").each do |fname|
      puts "\n### #{fname}\n"
      PEdump::CLI.new(fname).run
    end
  end

  namespace :all_files do
    desc 'output file name to stderr, use with stdout redirection'
    task stderr: :init do
      path = ENV['path'] || raise('run me with path=...')
      `find #{path} -type f`.split("\n").each do |fname|
        warn "\n### #{fname}\n"
        PEdump::CLI.new(fname).run
      end
    end
  end

  desc 'test on corkami binaries'
  task corkami: :init do
    path = 'samples/corkami'
    `find #{path} -type f`.split("\n").each do |fname|
      warn "\n### #{fname}\n"
      PEdump::CLI.new(fname).run
    end
  end
end

def check_file(url, params = {})
  require 'digest/md5'
  require 'open-uri'

  params[:min_size] ||= 80_000

  $stdout.sync = true
  prefix = params[:prefix]
  fname = File.join 'data', (prefix ? "#{prefix}-" : '') + File.basename(url)
  existing_md5 = File.exist?(fname) ? Digest::MD5.file(fname).hexdigest : ''
  print "[.] fetching #{url} .. "
  remote_data = URI.open(url).read.force_encoding('cp1252').encode('utf-8')
  puts "#{remote_data.size} bytes"
  raise "too small remote data (#{remote_data.size})" if remote_data.size < params[:min_size]

  remote_md5 = Digest::MD5.hexdigest(remote_data)
  if remote_md5 == existing_md5
    puts '[.] same as local'
  else
    existing_size = File.exist?(fname) ? File.size(fname) : 0
    File.write(fname, remote_data, mode: 'wb')
    puts "[*] updated: #{existing_size} -> #{remote_data.size}"
  end
end

RICH_IDS_URL = 'https://raw.githubusercontent.com/dishather/richprint/master/comp_id.txt'

namespace :rich do
  desc 'update rich comp_id db from net'
  task :update do
    check_file RICH_IDS_URL, min_size: 30_000
  end

  desc 'convert'
  task :convert do
    result = [
      'class PEdump',
      "  # data from #{RICH_IDS_URL}",
      '  RICH_IDS = {'
    ]
    n = 0
    t0 = Time.now
    File.readlines(File.join('data', File.basename(RICH_IDS_URL))).each do |line|
      line.strip!
      next if line.empty? || line[0] == '#'

      comp_id, desc = line.split(nil, 2)
      raise unless comp_id =~ /\A[0-9a-fA-F]+\Z/

      result << "    0x#{comp_id} => #{desc.inspect},"
      n += 1
    end
    result << '  }'
    result << 'end'
    printf "[.] parsed %d definitions in %6.3fs\n", n, Time.now - t0
    File.write('lib/pedump/rich.rb', result.join("\n") + "\n")
  end
end

namespace :sigs do
  desc 'convert txt2bin'
  task convert: :init do
    require './lib/pedump/packer'
    t0 = Time.now
    sigs = PEdump::SigParser.parse optimize: true
    printf "[.] parsed %d definitions in %6.3fs\n", sigs.size, Time.now - t0
    File.open(PEdump::Packer::BIN_SIGS_FILE, 'wb') { |f| Marshal.dump(sigs, f) }
  end

  desc 'dump'
  task dump: :init do
    require './lib/pedump/packer'
    PEdump::Packer.all
                  .group_by(&:name)
                  .sort_by { |name, _sigs| name }
                  .each do |name, sigs|
      next if sigs.size == 1

      puts name
      sigs.each do |sig|
        printf "    %-5s  %s\n", sig.ep_only, sig.re.source.inspect
      end
    end
  end
end

desc 'build readme'
task :readme do
  require 'erb'
  tpl = File.read('README.md.tpl').gsub(/^%\s+(.+)/) do |x|
    x.sub!(/^%/, '')
    "<%= run(\"#{x}\") %>"
  end
  def run(cmd)
    cmd.strip!
    puts "[.] #{cmd} ..."
    r = "    # #{cmd}\n\n"
    cmd.sub!(/^pedump/, '../bin/pedump')
    lines = `#{cmd}`.sub(/\A\n+/m, '').sub(/\s+\Z/, '').split("\n")
    lines = lines[0, 25] + ['...'] if lines.size > 50 && cmd.split.last != '-h'
    r << lines.map { |x| "    #{x}" }.join("\n")
    r << "\n"
  end
  Dir.chdir 'samples'
  result = ERB.new(tpl, trim_mode: '%>').result
  Dir.chdir '..'
  File.write('README.md', result)
end

namespace :console do
  desc 'start console with PEdump::Loader with loaded file'
  task :load do
    raise 'gimme a fname' unless (fname = ENV['fname'])

    require './lib/pedump'
    require './lib/pedump/loader'
    require 'pp'
    File.open(fname, 'rb') do |f|
      @ldr = PEdump::Loader.new f
      puts '[.] loader is at @ldr'
      pp @ldr.sections
      Rake::Task['console'].execute
    end
  end
end

desc 'compare two PE files'
task :cmp do
  raise 'gimme a f1' unless (f1 = ENV['f1'])
  raise 'gimme a f2' unless (f2 = ENV['f2'])

  require './lib/pedump'
  require './lib/pedump/comparer'
  PEdump::Comparer.cmp(f1, f2)
end
