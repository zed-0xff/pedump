class PEdump
  class CompositeIO
    def initialize(*ios)
      @ios    = ios.flatten
      @starts = ios.map(&:tell) # respect current position of each IO
      @pos = 0
    end

    def read(amount = nil, buf = nil)
      buf ||= ''; buf1 = ''

      # truncates buffer to zero length if nothing read
      @ios.first.read(amount,buf)

      @ios[1..-1].each do |io|
        break if amount && buf.size >= amount
        io.read(amount ? (amount-buf.size) : nil, buf1)
        buf << buf1
      end

      @pos += buf.size

      buf.size > 0 ? buf : (amount ? nil : buf )
    end

    def tell
      @pos
    end

    def seek pos
      @pos = pos
      @ios.each_with_index do |io,idx|
        if pos > 0
          sz = io.size-@starts[idx]
          io.seek( @starts[idx] + (pos < sz ? pos : sz) )
          pos -= sz
        else
          # seek all remaining IOs to 0
          io.seek @starts[idx]
        end
      end
    end

    def rewind
      seek(0)
    end

    def size
      @ios.map(&:size).inject(&:+)
    end

    def eof?
      @ios.all?(&:eof?)
    end
  end
end
