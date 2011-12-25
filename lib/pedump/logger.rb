require 'awesome_print' # for colored tty logging

class PEdump
  class Logger < ::Logger
    def initialize *args
      super
      @formatter = proc do |severity,_,_,msg|
        # quick and dirty way to remove duplicate messages
        if @prevmsg == msg && severity != 'DEBUG' && severity != 'INFO'
          ''
        else
          @prevmsg = msg
          "#{msg}\n"
        end
      end
      @level = WARN
    end
  end

  def Logger.create params
    logger =
      if params[:logger]
        params[:logger]
      else
        logdev = params[:logdev] || STDERR
        logger_class =
          if params.key?(:color)
            # forced color or not
            params[:color] ? ColoredLogger : Logger
          else
            # set color if logdev is TTY
            (logdev.respond_to?(:tty?) && logdev.tty?) ? ColoredLogger : Logger
          end
        logger_class.new(logdev)
      end

    logger.level = params[:log_level] if params[:log_level]
    logger
  end

  class ColoredLogger < ::Logger
    def initialize *args
      super
      @formatter = proc do |severity,_,_,msg|
        # quick and dirty way to remove duplicate messages
        if @prevmsg == msg && severity != 'DEBUG' && severity != 'INFO'
          ''
        else
          @prevmsg = msg
          color =
            case severity
            when 'FATAL'
              :redish
            when 'ERROR'
              :red
            when 'WARN'
              :yellowish
            when 'DEBUG'
              :gray
            end
          "#{color ? msg.send(color) : msg}\n"
        end
      end
      @level = WARN
    end
  end
end
