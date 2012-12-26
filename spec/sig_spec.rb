require File.expand_path(File.dirname(__FILE__) + '/spec_helper')
require File.expand_path(File.dirname(__FILE__) + '/../lib/pedump/packer')

describe "PEdump::Packer" do
  it "should have enough signatures" do
    PEdump::Packer.count.should > 1000
  end

  it "should not match" do
    maxlen = PEdump::Packer.map(&:size).max
    s = 'x'*maxlen
    PEdump::Packer.of_data(s).should be_nil
  end

  it "should parse" do
    a = PEdump::SigParser.parse
    a.should be_instance_of(Array)
    a.map(&:class).uniq.should == [PEdump::Packer]
  end

  it "should not react to DOS signature" do
    data = "This program cannot be run in DOS mode"
    PEdump::Packer.of(data).should be_nil
  end

  it "should match sigs" do
    n = 0
    File.open('data/signatures.txt', 'r:cp1252') do |f|
      while row = f.gets
        row.strip!
        next unless row =~ /^\[(.*)=(.*)\]$/
        s = ''
        title,hexstring = $1,$2

        # bad sigs
        next if hexstring == '909090909090909090909090909090909090909090909090909090909090909090909090'
        next if hexstring == 'E9::::0000000000000000'

        (hexstring.size/2).times do |i|
          c = hexstring[i*2,2]
          if c == '::'
            s << '.'
          else
            s << c.to_i(16).chr
          end
        end
        packers = PEdump::Packer.of(s)
        if packers
          names = packers.map(&:name)
          next if names.any? do |name|
            a = name.upcase.tr('V','')
            b = title.upcase.tr('V','')
            a[b] || b[a]
          end
#          puts "[.] #{title}"
#          names.each do |x|
#            puts "\t= #{x}"
#          end
        else
          puts "[?] #{title}: #{hexstring}"
          n += 1
        end
      end
    end
    #puts "[.] diff = #{n}"
    n.should == 0
  end
end
