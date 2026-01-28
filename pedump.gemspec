# frozen_string_literal: true

require 'English'
lib = File.expand_path('lib', __dir__)
$LOAD_PATH.unshift(lib) unless $LOAD_PATH.include?(lib)
require 'pedump/version'

Gem::Specification.new do |s|
  s.name        = 'pedump'
  s.version     = PEdump::VERSION
  s.authors     = ['Andrey "Zed" Zaikin']
  s.email       = 'zed.0xff@gmail.com'
  s.homepage    = 'http://github.com/zed-0xff/pedump'
  s.license     = 'MIT'
  s.summary     = 'dump win32 PE executable files with a pure ruby'
  s.description = 'dump headers, sections, extract resources of win32 PE exe,dll,etc'

  s.required_rubygems_version = Gem::Requirement.new('>= 0')
  s.require_paths = ['lib']

  s.files = `git ls-files -z`.split("\x0").reject do |f|
    f.match(%r{^(samples|spec|tmp)/}) ||
      f.match(/^\./) ||
      f == 'README.md.tpl'
  end
  s.executables = ['pedump']

  s.extra_rdoc_files = ['LICENSE.txt', 'README.md']

  s.add_runtime_dependency 'logger'
  s.add_runtime_dependency 'iostruct', '>= 0.7.0'
  s.add_runtime_dependency 'zhexdump', '>= 0.0.2'

  s.metadata['rubygems_mfa_required'] = 'true'
end
