require File.expand_path(File.dirname(__FILE__) + '/spec_helper')
require File.expand_path(File.dirname(__FILE__) + '/../lib/pedump')

5.times do |idx|
  fname = "ne#{idx}." + (idx==4 ? "dll" : "exe")

  modulenames = %w"_DELIS VISTA21P ISSET_SE HORSNCF MAPI"
  exports = []

  # ne0.exe
  exports << [
    PEdump::ExportedFunction.new("WNDPROC", 1, 0x10258)
  ]

  # ne1.exe
  exports << []

  # ne2.exe
  exports << [
    PEdump::ExportedFunction.new("LOGODLGPROC", 1, 0x13ACA),
    PEdump::ExportedFunction.new("BARWNDPROC",  2, 0x15FF0),
    PEdump::ExportedFunction.new("SETUPWNDPROC",3, 0x100B2),
    PEdump::ExportedFunction.new("LOGOBWNDPROC",4, 0x147B4),
  ]

  # ne3.exe
  exports << [
    PEdump::ExportedFunction.new("___EXPORTEDSTUB", 1, 0x63cf4),
    PEdump::ExportedFunction.new("_AFX_VERSION",    2, 0x4272c),
  ]

  # ne4.dll
  exports << [
    PEdump::ExportedFunction.new("WEP", 1, 0x10000),
    PEdump::ExportedFunction.new("BMAPIGETREADMAIL",  33, 0x7020A),
    PEdump::ExportedFunction.new("BMAPIRESOLVENAME",  38, 0x7077C),
    PEdump::ExportedFunction.new("BMAPIGETADDRESS",   36, 0x70692),
    PEdump::ExportedFunction.new("BMAPIFINDNEXT",     34, 0x70074),
    PEdump::ExportedFunction.new("BMAPIDETAILS",      37, 0x706F1),
    PEdump::ExportedFunction.new("MAPIFREEBUFFER",    18, 0xb0A71),
    PEdump::ExportedFunction.new("MAPIFINDNEXT",      16, 0xa0000),
    PEdump::ExportedFunction.new("MAPIDELETEMAIL",    17, 0x90000),
    PEdump::ExportedFunction.new("MAPIREADMAIL",      15, 0x100000),
    PEdump::ExportedFunction.new("BMAPIADDRESS",      35, 0x7051D),
    PEdump::ExportedFunction.new("MAPIADDRESS",       19, 0x60139),
    PEdump::ExportedFunction.new("MAPILOGON",         11, 0xc0000),
    PEdump::ExportedFunction.new("MAPISENDMAIL",      13, 0x130000),
    PEdump::ExportedFunction.new("MAPIRESOLVENAME",   21, 0x60A3F),
    PEdump::ExportedFunction.new("MAPIDETAILS",       20, 0x60752),
    PEdump::ExportedFunction.new("BMAPISAVEMAIL",     31, 0x70455),
    PEdump::ExportedFunction.new("MAPISAVEMAIL",      14, 0x1302BE),
    PEdump::ExportedFunction.new("BMAPIREADMAIL",     32, 0x70141),
    PEdump::ExportedFunction.new("MAPISENDDOCUMENTS", 10, 0x120703),
    PEdump::ExportedFunction.new("MAPILOGOFF",        12, 0xc00D2),
    PEdump::ExportedFunction.new("BMAPISENDMAIL",     30, 0x70000),
  ]

  imports = [
    ['KERNEL',   0x80],
    ['VBRUN300', 0x64],
    ['GDI',      0x15f],
    ['FINSTDLL', nil,  'FILECOPY'],
    ['DEMILAYR', 0x6f]
  ]

  versions = %w'2.20.900.0 - 3.0.111.0 1.0.0.1 3.2.0.4057'

  describe fname do
    it "should have NE header" do
      sample do |f|
        f.ne.should_not be_nil
      end
    end

    it "should not have PE header" do
      sample do |f|
        f.pe.should be_nil
      end
    end

    it "should have NE segments" do
      sample do |f|
        f.ne.segments.size.should == f.ne.ne_cseg
      end
    end

    it "should have NE resources" do
      sample do |f|
        f.ne.resources.should_not be_nil
        ver = f.ne.resources.find{ |res| res.type == 'VERSION' }
        expected = versions[idx]
        if expected == '-'
          ver.should be_nil
        else
          vi = ver.data.first
          [
            vi.Value.dwFileVersionMS.to_i >> 16,
            vi.Value.dwFileVersionMS.to_i &  0xffff,
            vi.Value.dwFileVersionLS.to_i >> 16,
            vi.Value.dwFileVersionLS.to_i &  0xffff
          ].join('.').should == expected
        end
      end
    end

    it "should have imports" do
      sample do |f|
        f.ne.imports.should_not be_nil
        func = PEdump::ImportedFunction.new
        func.module_name = imports[idx][0]
        func.ordinal     = imports[idx][1]
        func.name        = imports[idx][2]

        f.ne.imports.should include(func)
      end
    end
    it "should have exports" do
      sample do |f|
        f.ne.exports.should_not be_nil
        f.ne.exports.name.should == modulenames[idx]
        f.ne.exports.functions.should == exports[idx]
      end
    end
  end
end
