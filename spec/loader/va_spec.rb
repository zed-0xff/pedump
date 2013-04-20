require 'spec_helper'
require 'pedump/loader'

describe PEdump::Loader do
  describe "#valid_va?" do
    describe "samples/calc.exe" do
      before do
        io = open("samples/calc.exe","rb")
        @ldr = PEdump::Loader.new io
      end

      %w'1001000 1010000 104b999 104c000 1051000 109c000 10a01f5'.each do |x|
        it "returns true for 0x#{x}" do
          @ldr.valid_va?(x.to_i(16)).should be_true
        end
      end

      %w'0 1 1000 1000fff 104b99a 104bfff 1050fff 109bfff 10a01f6'.each do |x|
        it "returns false for 0x#{x}" do
          @ldr.valid_va?(x.to_i(16)).should be_false
        end
      end
    end

    describe "samples/upx.exe" do
      before do
        io = open("samples/upx.exe","rb")
        @ldr = PEdump::Loader.new io
      end

      %w'401000 541000 589000 589fff'.each do |x|
        it "returns true for 0x#{x}" do
          @ldr.valid_va?(x.to_i(16)).should be_true
        end
      end

      %w'0 1 1000 400000 58a000'.each do |x|
        it "returns false for 0x#{x}" do
          @ldr.valid_va?(x.to_i(16)).should be_false
        end
      end
    end
  end
end
