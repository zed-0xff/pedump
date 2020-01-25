class PEdump
  module Version
    STRING = File.read(File.join(File.dirname(File.dirname(File.dirname(__FILE__))), 'VERSION')).strip
    MAJOR, MINOR, PATCH = STRING.split('.').map(&:to_i)
    BUILD = nil
  end
end
