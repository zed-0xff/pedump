# frozen_string_literal: true

class PEdump
  class CLI
    # Streaming multipart body for file uploads
    class MultipartBody
      BOUNDARY_CHARS = ('a'..'z').to_a + ('A'..'Z').to_a + ('0'..'9').to_a

      def self.generate_boundary
        "----PEdumpUpload#{Array.new(32) { BOUNDARY_CHARS.sample }.join}"
      end

      def initialize(header, file_io, footer, total_size)
        @parts = [
          StringIO.new(header),
          file_io,
          StringIO.new(footer)
        ]
        @part_index = 0
        @size = total_size
      end

      attr_reader :size

      def read(length = nil, outbuf = nil)
        outbuf ||= String.new
        outbuf.clear
        outbuf.force_encoding(Encoding::BINARY)

        return nil if @part_index >= @parts.length

        while @part_index < @parts.length
          chunk = if length
                    @parts[@part_index].read(length - outbuf.bytesize)
                  else
                    @parts[@part_index].read
                  end

          if chunk
            outbuf << chunk
            break if length && outbuf.bytesize >= length
          else
            @part_index += 1
          end
        end

        outbuf.empty? && length ? nil : outbuf
      end

      def rewind
        @parts.each(&:rewind)
        @part_index = 0
      end
    end
  end
end
