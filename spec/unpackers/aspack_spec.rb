root = File.expand_path(File.dirname(File.dirname(File.dirname(__FILE__))))
require "#{root}/spec/spec_helper"
require "#{root}/lib/pedump"
require "#{root}/lib/pedump/unpacker/aspack"
require "#{root}/lib/pedump/comparer"

describe PEdump::Unpacker::ASPack do
  Dir["#{root}/samples/*.asp[1-9]*.{exe}"].each do |pname|
    orig_fname = pname.sub(/\.asp[^.]+/,'')

    describe File.basename(orig_fname) + " vs " + File.basename(pname) do
      before :all do
        @ldr = PEdump::Loader.new(File.open(orig_fname,"rb"))
      end

      it "should have no differences" do
        File.open(pname,"rb") do |f|
          u = PEdump::Unpacker::ASPack.new(f)
          File.open("#{root}/tmp/unpacked.tmp","w+") do |fo|
            u.unpack.dump(fo)
            fo.rewind
            ldr = PEdump::Loader.new(fo)

            comparer = PEdump::Comparer.new(@ldr, ldr)
            comparer.ignored_data_dirs = [
              PEdump::IMAGE_DATA_DIRECTORY::LOAD_CONFIG,
              PEdump::IMAGE_DATA_DIRECTORY::Bound_IAT,
              PEdump::IMAGE_DATA_DIRECTORY::Delay_IAT
            ]
            comparer.ignored_sections = [ '.rsrc', '.aspack' ]
            comparer.diff.should == []
          end
        end
      end
    end
  end

  Dir["#{root}/samples/*.asp[1-9]*.{ocx}"].each do |pname|
    orig_fname = pname.sub(/\.asp[^.]+/,'')

    describe File.basename(orig_fname) + " vs " + File.basename(pname) do
      before :all do
        @ldr = PEdump::Loader.new(File.open(orig_fname,"rb"))
      end

      it "should have no differences" do
        File.open(pname,"rb") do |f|
          u = PEdump::Unpacker::ASPack.new(f)
          File.open("#{root}/tmp/unpacked.tmp","w+") do |fo|
            u.unpack.dump(fo)
            fo.rewind
            ldr = PEdump::Loader.new(fo)

            comparer = PEdump::Comparer.new(@ldr, ldr)
            comparer.ignored_data_dirs = [
              PEdump::IMAGE_DATA_DIRECTORY::LOAD_CONFIG,
              PEdump::IMAGE_DATA_DIRECTORY::Bound_IAT,
              PEdump::IMAGE_DATA_DIRECTORY::Delay_IAT,
              PEdump::IMAGE_DATA_DIRECTORY::BASERELOC, # 0x15496 vs 0x15494
              PEdump::IMAGE_DATA_DIRECTORY::IAT
            ]
            comparer.ignored_sections = [ '.rsrc', '.aspack', '.cas' ]
            comparer.diff.should == []
          end
        end
      end
    end
  end
end
