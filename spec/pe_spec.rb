require File.expand_path(File.dirname(__FILE__) + '/spec_helper')
require File.expand_path(File.dirname(__FILE__) + '/../lib/pedump')

describe 'PE' do
  it "should assume TimeDateStamp is in UTC"

  describe PEdump::ImportedFunction do
    it "should be equal" do
      # XXX necessary?
      a = []
      described_class.new(*a).should == described_class.new(*a)
      a = ['a']
      described_class.new(*a).should == described_class.new(*a)
      a = ['a','b']
      described_class.new(*a).should == described_class.new(*a)
      a = ['a','b','c']
      described_class.new(*a).should == described_class.new(*a)
      a = ['a','b','c','d']
      described_class.new(*a).should == described_class.new(*a)
    end

    it "should not be equal" do
      a = ['a']
      b = []
      described_class.new(*a).should_not == described_class.new(*b)
      a = ['a']
      b = ['b']
      described_class.new(*a).should_not == described_class.new(*b)
      a = ['a','B']
      b = ['a','b']
      described_class.new(*a).should_not == described_class.new(*b)
      a = ['a','b','c']
      b = ['a','b']
      described_class.new(*a).should_not == described_class.new(*b)
      a = ['a','b','c']
      b = ['a','b','X']
      described_class.new(*a).should_not == described_class.new(*b)
    end

    it "should be equal with different VA's" do
      # XXX necessary?
      a = ['a','b','c',nil]
      b = ['a','b','c','d']
      described_class.new(*a).should == described_class.new(*b)
      a = ['a','b','c',0x1000]
      b = ['a','b','c',0x2000]
      described_class.new(*a).should == described_class.new(*b)
      a = ['a','b','c',0x1000]
      b = ['a','b','c',0x1000]
      described_class.new(*a).should == described_class.new(*b)
    end

    it "should be equal in uniq() with different VA's" do
      a = ['a','b','c',nil]
      b = ['a','b','c','d']
      [described_class.new(*a), described_class.new(*b)].uniq.size.should == 1
      a = ['a','b','c',0x1000]
      b = ['a','b','c',0x2000]
      [described_class.new(*a), described_class.new(*b)].uniq.size.should == 1
      a = ['a','b','c',0x1000]
      b = ['a','b','c',0x1000]
      [described_class.new(*a), described_class.new(*b)].uniq.size.should == 1
    end
  end
end
