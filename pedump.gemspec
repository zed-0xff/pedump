# coding: utf-8
lib = File.expand_path('../lib', __FILE__)
$LOAD_PATH.unshift(lib) unless $LOAD_PATH.include?(lib)
require 'pedump/version'

Gem::Specification.new do |spec|
  spec.name          = "pedump"
  spec.version       = PEdump::Version::STRING
  spec.authors       = ["Andrey \"Zed\" Zaikin"]
  spec.email         = ["zed.0xff@gmail.com"]

  spec.summary       = "dump win32 PE executable files with a pure ruby"
  spec.description   = "dump headers, sections, extract resources of win32 PE exe,dll,etc"
  spec.homepage      = "http://github.com/zed-0xff/pedump"
  spec.license       = "MIT"

  spec.files         = `git ls-files -z`.split("\x0").
    reject { |f| f.match(%r{^(test|spec|features|samples|tmp|\.)/}) || f.start_with?('.') || f == "README.md.tpl" }

  spec.bindir        = "bin"
  spec.executables   = spec.files.grep(%r{^bin/}) { |f| File.basename(f) }
  spec.require_paths = ["lib"]

  spec.add_dependency "awesome_print"
  spec.add_dependency "iostruct",       ">= 0.0.4"
  spec.add_dependency "multipart-post", "~> 2.0.0"
  spec.add_dependency "progressbar"
  spec.add_dependency "zhexdump",       ">= 0.0.2"

  spec.add_development_dependency "bundler", "~> 1.11"
  spec.add_development_dependency "rake",    "~> 10.0"
  spec.add_development_dependency "rspec",   "~> 3.0"
end
