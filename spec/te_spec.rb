require File.expand_path(File.dirname(__FILE__) + '/spec_helper')
require File.expand_path(File.dirname(__FILE__) + '/../lib/pedump')

basename = "iso9660_x64"
te_fname = basename + ".te"
pe_fname = basename + ".efi"

describe te_fname do
  it "should have 'VZ' signature" do
    sample.te.Signature.should == ('Z'.ord << 8) + 'V'.ord
  end
  it "should be equal to source efi" do
    #efi = PEdump.new(open(File.join(File.dirname(sample.io.path), pe_fname)))
    #pe = efi.pe
    te = sample.te
    te.Machine.should              ==  0x8664
    te.NumberOfSections.should     ==  3
    te.Subsystem.should            ==  0xb
    te.StrippedSize.should         ==  0x188
    te.AddressOfEntryPoint.should  ==  0x45d5
    te.BaseOfCode.should           ==  0x240
    te.ImageBase.should            ==  0

    te.DataDirectory.size.should == 2

    te.sections.size.should == 3
  end
  it "should be TE and not PE or NE" do
    sample.should be_te
    sample.should_not be_pe
    sample.should_not be_ne
  end
end
