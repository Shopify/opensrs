require "uri"
require "net/https"
require "digest/md5"
require "openssl"

module OpenSRS
  class OpenSRSError < StandardError; end

  class BadResponse < OpenSRSError; end
  class ConnectionError < OpenSRSError; end
  class TimeoutError < ConnectionError; end

  class Server
    class << self
      attr_accessor :ciphers
    end
    self.ciphers = 'TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:TLS_AES_128_GCM_SHA256:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-SHA384:ECDHE-RSA-AES128-SHA256'

    attr_accessor :server,
                  :username,
                  :password,
                  :key,
                  :timeout,
                  :open_timeout,
                  :logger,
                  :log_compaction,
                  :sanitize_logs,
                  :proxy

    SANITIZING_METHODS = [
      :sanitize_rw_register
    ].freeze

    def initialize(options = {})
      @server   = URI.parse(options[:server] || "https://rr-n1-tor.opensrs.net:55443/")
      @username = options[:username]
      @password = options[:password]
      @key      = options[:key]
      @timeout  = options[:timeout]
      @open_timeout = options[:open_timeout]
      @logger   = options[:logger]
      @log_compaction   = options[:log_compaction]
      @sanitize_logs = options[:sanitize_logs]
      @proxy    = URI.parse(options[:proxy]) if options[:proxy]
    end

    def call(data = {})
      xml = xml_processor.build({ :protocol => "XCP" }.merge!(data))
      log('Request', xml, data)

      begin
        response = http.post(server_path, xml, headers(xml))
        log('Response', response.body, data)
      rescue Net::HTTPBadResponse
        raise OpenSRS::BadResponse, "Received a bad response from OpenSRS. Please check that your IP address is added to the whitelist, and try again."
      end

      parsed_response = xml_processor.parse(response.body)
      return OpenSRS::Response.new(parsed_response, xml, response.body)
    rescue Timeout::Error => err
      raise OpenSRS::TimeoutError, err
    rescue Errno::ECONNRESET, Errno::ECONNREFUSED => err
      raise OpenSRS::ConnectionError, err
    end

    def xml_processor
      @@xml_processor
    end

    def self.xml_processor=(name)
      require "opensrs/xml_processor/#{name.to_s.downcase}"
      @@xml_processor = OpenSRS::XmlProcessor.const_get("#{name.to_s.capitalize}")
    end

    private

    def headers(request)
      {
        "Content-Length"  => request.length.to_s,
        "Content-Type"    => "text/xml",
        "X-Username"      => username,
        "X-Signature"     => signature(request)
      }
    end

    def signature(request)
      Digest::MD5.hexdigest(Digest::MD5.hexdigest(request + key) + key)
    end

    def http
      http = if @proxy
        Net::HTTP.new server.host, server.port,
          @proxy.host, @proxy.port, @proxy.user, @proxy.password
      else
        Net::HTTP.new(server.host, server.port)
      end
      http.use_ssl = (server.scheme == "https")
      if self.class.ciphers
        http.ciphers = self.class.ciphers
      end
      http.read_timeout = http.open_timeout = @timeout if @timeout
      http.open_timeout = @open_timeout                if @open_timeout
      http
    end

    def sanitize(type, data, options)
      return data unless @sanitize_logs

      SANITIZING_METHODS.inject(data) do |current_data, method|
        send(method, type, current_data, options)
      end
    end

    def sanitize_rw_register(type, data, options)
      return data unless type == "Request" &&
                         options[:object] == "DOMAIN" &&
                         options[:action] == "SW_REGISTER"

      data.gsub(%r{(<item key="reg_password">).*(</item>)}, '\1**sanitized**\2')
    end

    def log(type, data, options = {})
      return unless logger

      message = "[OpenSRS] #{type} XML"
      message = "#{message} for #{options[:object]} #{options[:action]}" if options[:object] && options[:action]

      logs = [message, sanitize(type, data, options)].join("\n")
      logs = logs.split("\n").each { |line| line.lstrip! }.join('') if log_compaction

      logger.info(logs)
    end

    def server_path
      server.path.empty? ? '/' : server.path
    end
  end
end
