require File.expand_path(File.dirname(__FILE__) + '/spec_helper')
require File.expand_path(File.dirname(__FILE__) + '/../lib/pedump')

describe 'PE' do
  it "should assume TimeDateStamp is in UTC"

  KLASS = PEdump::ImportedFunction

  describe KLASS do
    it "should be equal" do
      pending "necessary?"
      a = []
      KLASS.new(*a).should == KLASS.new(*a)
      a = ['a']
      KLASS.new(*a).should == KLASS.new(*a)
      a = ['a','b']
      KLASS.new(*a).should == KLASS.new(*a)
      a = ['a','b','c']
      KLASS.new(*a).should == KLASS.new(*a)
      a = ['a','b','c','d']
      KLASS.new(*a).should == KLASS.new(*a)
    end

    it "should not be equal" do
      a = ['a']
      b = []
      KLASS.new(*a).should_not == KLASS.new(*b)
      a = ['a']
      b = ['b']
      KLASS.new(*a).should_not == KLASS.new(*b)
      a = ['a','B']
      b = ['a','b']
      KLASS.new(*a).should_not == KLASS.new(*b)
      a = ['a','b','c']
      b = ['a','b']
      KLASS.new(*a).should_not == KLASS.new(*b)
      a = ['a','b','c']
      b = ['a','b','X']
      KLASS.new(*a).should_not == KLASS.new(*b)
    end

    it "should be equal with different VA's" do
      pending "necessary?"
      a = ['a','b','c',nil]
      b = ['a','b','c','d']
      KLASS.new(*a).should == KLASS.new(*b)
      a = ['a','b','c',0x1000]
      b = ['a','b','c',0x2000]
      KLASS.new(*a).should == KLASS.new(*b)
      a = ['a','b','c',0x1000]
      b = ['a','b','c',0x1000]
      KLASS.new(*a).should == KLASS.new(*b)
    end

    it "should be equal in uniq() with different VA's" do
      a = ['a','b','c',nil]
      b = ['a','b','c','d']
      [KLASS.new(*a), KLASS.new(*b)].uniq.size.should == 1
      a = ['a','b','c',0x1000]
      b = ['a','b','c',0x2000]
      [KLASS.new(*a), KLASS.new(*b)].uniq.size.should == 1
      a = ['a','b','c',0x1000]
      b = ['a','b','c',0x1000]
      [KLASS.new(*a), KLASS.new(*b)].uniq.size.should == 1
    end
  end
end
