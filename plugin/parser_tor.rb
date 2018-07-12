require 'fluent/plugin/parser'
require 'socket'

module Fluent::Plugin
  class TorLogParser < Fluent::Plugin::Parser
    # Register this parser as "tor"
    Fluent::Plugin.register_parser("tor", self)

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
      @time_parser = Fluent::TimeParser.new(@time_format)
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
      record["raw_query"] = v
      # take onion domain
      if v.match(/[a-z0-9]{32}\|[a-z0-9]{16}/)
        record["address"] = v.split("|")[1].strip + ".onion"
      end
      # take tor node IP address
      data = Socket.getifaddrs.select{|x| (x.name == "eth0" or x.name.include?("enp")) and x.addr.ipv4?}
      if (data != []) && (data.first.respond_to? :addr) 
        record["snooper"] = data.first.addr.ip_address
      end
      yield time, record
    end
  end
end
