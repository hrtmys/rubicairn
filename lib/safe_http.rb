# frozen_string_literal: true

require "ipaddr"
require "net/http"
require "openssl"
require "resolv"
require "uri"

module Rubicairn
  # SSRF-hardened HTTP client with IP filtering, redirect validation, and body size limits.
  module SafeHTTP
    class Error < StandardError; end
    class InvalidURLError < Error; end
    class BlockedIPError < Error; end
    class TooManyRedirectsError < Error; end
    class ResponseTooLargeError < Error; end
    class InvalidEncodingError < Error; end

    BLOCKED_IPV4_CIDRS = [
      IPAddr.new("0.0.0.0/8"),
      IPAddr.new("10.0.0.0/8"),
      IPAddr.new("100.64.0.0/10"),
      IPAddr.new("127.0.0.0/8"),
      IPAddr.new("169.254.0.0/16"),
      IPAddr.new("172.16.0.0/12"),
      IPAddr.new("192.168.0.0/16"),
      IPAddr.new("224.0.0.0/4"),
      IPAddr.new("240.0.0.0/4")
    ].freeze

    BLOCKED_IPV6_CIDRS = [
      IPAddr.new("::/128"),
      IPAddr.new("::1/128"),
      IPAddr.new("fc00::/7"),
      IPAddr.new("fe80::/10"),
      IPAddr.new("ff00::/8"),
      IPAddr.new("::ffff:0:0/96")
    ].freeze

    module_function

    def blocked_ip?(ip_str)
      ip = IPAddr.new(ip_str.to_s.strip)
      if ip.ipv4?
        BLOCKED_IPV4_CIDRS.any? { |cidr| cidr.include?(ip) }
      elsif ip.ipv6?
        return true if BLOCKED_IPV6_CIDRS.any? { |cidr| cidr.include?(ip) }

        if ip.ipv4_mapped?
          native = ip.native
          return BLOCKED_IPV4_CIDRS.any? { |cidr| cidr.include?(native) }
        end
        false
      else
        true
      end
    rescue IPAddr::InvalidAddressError, IPAddr::AddressFamilyError
      true
    end

    def parse_http_uri!(url)
      uri = URI.parse(url.to_s)
      unless uri.is_a?(URI::HTTP) && %w[http https].include?(uri.scheme) && uri.host && !uri.host.empty?
        raise InvalidURLError, "Invalid or unsupported URL: #{url}"
      end

      uri
    rescue URI::InvalidURIError => e
      raise InvalidURLError, e.message
    end

    def resolve_and_validate_host!(host)
      clean_host = host.to_s.delete_prefix("[").delete_suffix("]")
      ips = begin
        IPAddr.new(clean_host)
        [clean_host]
      rescue IPAddr::InvalidAddressError
        Resolv.getaddresses(clean_host)
      end

      raise BlockedIPError, "DNS resolution returned no addresses for #{host}" if ips.empty?

      ips.each do |ip|
        raise BlockedIPError, "Blocked IP address #{ip} for host #{host}" if blocked_ip?(ip)
      end

      ips
    end

    def request(method:, url:, headers: {}, body: nil, config:, max_bytes: 65_536, max_redirects: 3, header_builder: nil)
      current_url = url.to_s
      redirects_left = max_redirects

      loop do
        uri = parse_http_uri!(current_url)
        resolved_ips = resolve_and_validate_host!(uri.host)

        req_headers = header_builder ? header_builder.call(current_url) : headers.dup
        req_headers["User-Agent"] ||= config.user_agent

        response, response_body = perform_http(
          method: method,
          uri: uri,
          ipaddr: resolved_ips.first,
          headers: req_headers,
          body: body,
          config: config,
          max_bytes: max_bytes
        )

        if response.is_a?(Net::HTTPRedirection) && method.to_s.downcase == "get"
          raise TooManyRedirectsError, "Too many redirects" if redirects_left <= 0

          location = response["location"]
          raise InvalidURLError, "Redirect missing Location header" if location.nil? || location.empty?

          current_url = URI.join(current_url, location).to_s
          redirects_left -= 1
          next
        end

        resp_headers = {}
        response.each_header { |k, v| resp_headers[k.downcase] = v }

        return {
          status: response.code.to_i,
          headers: resp_headers,
          body: response_body
        }
      end
    end

    def perform_http(method:, uri:, ipaddr:, headers:, body:, config:, max_bytes:)
      http = Net::HTTP.new(uri.host, uri.port)
      http.ipaddr = ipaddr
      http.open_timeout = config.http_open_timeout
      http.read_timeout = config.http_read_timeout
      if uri.scheme == "https"
        http.use_ssl = true
        http.verify_mode = OpenSSL::SSL::VERIFY_PEER
      end

      req_class = case method.to_s.downcase
                  when "get" then Net::HTTP::Get
                  when "post" then Net::HTTP::Post
                  else raise ArgumentError, "Unsupported HTTP method: #{method}"
                  end

      req = req_class.new(uri.request_uri)
      headers.each { |k, v| req[k] = v }
      req.body = body if body

      chunks = +""
      response_obj = nil
      http.start do |conn|
        conn.request(req) do |res|
          response_obj = res
          res.read_body do |chunk|
            chunks << chunk
            if chunks.bytesize > max_bytes
              raise ResponseTooLargeError, "Response exceeded #{max_bytes} bytes"
            end
          end
        end
      end

      chunks.force_encoding("UTF-8")
      raise InvalidEncodingError, "Response body is not valid UTF-8" unless chunks.valid_encoding?

      [response_obj, chunks]
    end
  end
end
