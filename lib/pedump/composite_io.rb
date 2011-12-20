class PEdump
  class CompositeIO
    def initialize(*ios)
      @ios = ios.flatten
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

    def eof?
      @ios.all?(&:eof?)
    end
  end
end
