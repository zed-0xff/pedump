# frozen_string_literal: true
require 'yaml'

class PEdump
  def self.ordlookup(dll, ord, make_name: false)
    dll = dll.downcase
    @ordlookup ||= {}
    @ordlookup[dll] ||= 
      begin
        yml_fname = File.expand_path(File.dirname(__FILE__) + "/../../data/ordlookup/" + dll + ".yml")
        if File.exist?(yml_fname)
          YAML.load_file(yml_fname)
        else
          {}
        end
      end
    @ordlookup[dll][ord] || (make_name ? "ord#{ord}" : nil)
  end
end
