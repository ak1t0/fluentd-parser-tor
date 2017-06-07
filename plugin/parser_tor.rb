require 'fluent/parser'

module Fluent
  class TextParser
    class TorLogParser < Parser
      # Register this parser as "tor"
      Plugin.register_parser("tor", self)

      config_param :delimiter, :string, :default => " " # delimiter is configurable with " " as default
      config_param :time_format, :string, :default => "%b %d %H:%M:%S.%L" # time_format is configurable

      # This method is called after config_params have read configuration parameters
      def configure(conf)
        super

        if @delimiter.length != 1
          raise ConfigError, "delimiter must be a single character. #{@delimiter} is not."
        end

        # TimeParser class is already given. It takes a single argument as the time format
        # to parse the time string with.
        @time_parser = TimeParser.new(@time_format)
      end

      # This is the main method. The input "text" is the unit of data to be parsed.
      # If this is the in_tail plugin, it would be a line. If this is for in_syslog,
      # it is a single syslog message.
      def parse(text)
        splited = text.split(@delimiter, 4)
        time = splited[0..2].join(" ")
        data = splited[3]
        time = @time_parser.parse(time)
        record = {}
        k, v = data.split(@delimiter, 2)
        record[k] = v
        # take onion domain
        if v.match(/[a-z0-9]{32}\|[a-z0-9]{16}/)
          record["domain"] = v.split("|")[1] + ".onion"
        end
        yield time, record
      end
    end
  end
end
