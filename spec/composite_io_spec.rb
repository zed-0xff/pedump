require File.expand_path(File.dirname(__FILE__) + '/spec_helper')
require File.expand_path(File.dirname(__FILE__) + '/../lib/pedump/composite_io')

describe PEdump::CompositeIO do
  it "concatenates" do
    io = PEdump::CompositeIO.new(
      StringIO.new('foo'),
      StringIO.new('bar'),
      StringIO.new('baz')
    )
    io.read.should == 'foobarbaz'
  end

  it "reads sequentally" do
    io = PEdump::CompositeIO.new(
      StringIO.new('foo1'),
      StringIO.new('bar2'),
      StringIO.new('baz')
    )
    io.read(3).should == 'foo'
    io.read(3).should == '1ba'
    io.read(3).should == 'r2b'
    io.read(3).should == 'az'
  end

  it "behaves like StringIO" do
    io1 = StringIO.new('foo')
    io2 = PEdump::CompositeIO.new(StringIO.new('foo'))

    io1.read.should == io2.read       # 'foo'
    io1.read.should == io2.read       # ''
    io1.read(3).should == io2.read(3) # nil
  end

  it "tracks number of bytes read" do
    io = PEdump::CompositeIO.new(
      StringIO.new('foo1'),
      StringIO.new('bar2'),
      StringIO.new('baz')
    )
    io.tell.should == 0
    io.read(3)
    io.tell.should == 3
    io.read(4)
    io.tell.should == 7
    io.read
    io.tell.should == 11
    io.read
    io.tell.should == 11
    io.read 10
    io.tell.should == 11
  end

  it "chains eof? call" do
    io = PEdump::CompositeIO.new(
      StringIO.new('foo1'),
      StringIO.new('bar2'),
      StringIO.new('baz')
    )
    io.eof?.should be_false
    io.read(3)
    io.eof?.should be_false
    io.read(4)
    io.eof?.should be_false
    io.read
    io.eof?.should be_true
    io.read
    io.eof?.should be_true
    io.read 10
    io.eof?.should be_true
  end

  it "seeks" do
    io = PEdump::CompositeIO.new(
      StringIO.new('foo1'),
      StringIO.new('bar2'),
      StringIO.new('baz')
    )

    io.seek(5)
    io.tell.should == 5
    io.read(4).should == "ar2b"

    io.seek(0)
    io.tell.should == 0
    io.read.should == "foo1bar2baz"

    io.seek(1)
    io.tell.should == 1
    io.read.should == "oo1bar2baz"
  end

  it "respects start positions" do
    ios = [
      StringIO.new('foo1'),
      StringIO.new('bar2'),
      StringIO.new('baz3')
    ]
    ios.each_with_index{ |io,idx| io.seek(idx+1) }

    s = "oo1r23"

    io = PEdump::CompositeIO.new(*ios)
    io.tell.should == 0
    io.read.should == s

    s.size.times do |pos|
      io.seek(pos)
      io.tell.should == pos
      io.read.should == s[pos..-1]
    end
  end

  it "summarizes size" do
    io = PEdump::CompositeIO.new(
      StringIO.new('foo1'),
      StringIO.new('bar2'),
      StringIO.new('baz')
    )
    io.size.should == 11
  end
end
