# frozen_string_literal: true

require "base64"
require "digest"
require "json"
require "openssl"
require "rack/utils"
require "time"
require "uri"
require_relative "safe_http"

module Rubicairn
  # draft-cavage HTTP Signatures (rsa-sha256) signer and verifier.
  module HttpSig
    class VerificationError < StandardError
      attr_reader :status

      def initialize(message, status: 401)
        super(message)
        @status = status
      end
    end

    # Thread-safe LRU/TTL cache for remote public keys with fetch rate limiting.
    class KeyCache
      MAX_ENTRIES = 100
      TTL_SECONDS = 3600
      RATE_WINDOW_SECONDS = 60
      MAX_FETCHES_PER_WINDOW = 30

      def initialize(max_entries: MAX_ENTRIES, ttl_seconds: TTL_SECONDS)
        @max_entries = max_entries
        @ttl_seconds = ttl_seconds
        @entries = {}
        @fetch_timestamps = []
        @mutex = Mutex.new
      end

      def get(key_id)
        @mutex.synchronize do
          entry = @entries[key_id]
          return nil unless entry

          if (Time.now - entry[:fetched_at]) > @ttl_seconds
            @entries.delete(key_id)
            return nil
          end

          # Refresh LRU order
          @entries.delete(key_id)
          @entries[key_id] = entry
          entry
        end
      end

      def set(key_id, value)
        @mutex.synchronize do
          @entries.delete(key_id)
          @entries.shift while @entries.size >= @max_entries
          @entries[key_id] = value.merge(fetched_at: Time.now)
        end
      end

      def delete(key_id)
        @mutex.synchronize do
          @entries.delete(key_id)
        end
      end

      def allow_fetch?
        @mutex.synchronize do
          cutoff = Time.now - RATE_WINDOW_SECONDS
          @fetch_timestamps.reject! { |t| t < cutoff }
          return false if @fetch_timestamps.size >= MAX_FETCHES_PER_WINDOW

          @fetch_timestamps << Time.now
          true
        end
      end
    end

    module_function

    def sign_headers(method:, url:, body: nil, config:, date: Time.now.utc)
      uri = URI.parse(url.to_s)
      default_port = (uri.scheme == "https" && uri.port == 443) || (uri.scheme == "http" && uri.port == 80)
      host_val = default_port ? uri.host : "#{uri.host}:#{uri.port}"
      date_val = date.utc.httpdate
      request_target = "#{method.to_s.downcase} #{uri.request_uri}"

      if method.to_s.downcase == "post"
        payload = body.to_s
        digest_val = "SHA-256=#{Base64.strict_encode64(Digest::SHA256.digest(payload))}"
        headers_list = "(request-target) host date digest"
        signing_string = [
          "(request-target): #{request_target}",
          "host: #{host_val}",
          "date: #{date_val}",
          "digest: #{digest_val}"
        ].join("\n")
      else
        headers_list = "(request-target) host date"
        signing_string = [
          "(request-target): #{request_target}",
          "host: #{host_val}",
          "date: #{date_val}"
        ].join("\n")
      end

      sig_b64 = Base64.strict_encode64(
        config.private_key.sign(OpenSSL::Digest::SHA256.new, signing_string)
      )
      sig_header = %(keyId="#{config.key_id}",algorithm="rsa-sha256",headers="#{headers_list}",signature="#{sig_b64}")

      result = {
        "Host" => host_val,
        "Date" => date_val,
        "Signature" => sig_header,
        "User-Agent" => config.user_agent
      }

      if method.to_s.downcase == "post"
        result["Digest"] = digest_val
        result["Content-Type"] = "application/activity+json"
      else
        result["Accept"] = 'application/activity+json, application/ld+json; profile="https://www.w3.org/ns/activitystreams"'
      end

      result
    end

    def signed_get(url:, config:, max_bytes: 65_536)
      SafeHTTP.request(
        method: :get,
        url: url,
        config: config,
        max_bytes: max_bytes,
        header_builder: ->(next_url) { sign_headers(method: :get, url: next_url, config: config) }
      )
    rescue KeyVault::LockedError
      SafeHTTP.request(
        method: :get,
        url: url,
        headers: { "Accept" => 'application/activity+json, application/ld+json; profile="https://www.w3.org/ns/activitystreams"' },
        config: config,
        max_bytes: max_bytes
      )
    end

    def signed_post(url:, body:, config:)
      headers = sign_headers(method: :post, url: url, body: body, config: config)
      SafeHTTP.request(
        method: :post,
        url: url,
        headers: headers,
        body: body,
        config: config
      )
    end

    def verify_inbox_request(request:, raw_body:, config:, key_cache:, key_fetcher: nil)
      sig_header = request.env["HTTP_SIGNATURE"]
      date_header = request.env["HTTP_DATE"]
      digest_header = request.env["HTTP_DIGEST"]

      if empty_str?(sig_header) || empty_str?(date_header) || empty_str?(digest_header)
        raise VerificationError.new("Missing required signature headers", status: 401)
      end

      # Step 2: Date validation (±12 minutes)
      parsed_date = begin
        Time.httpdate(date_header)
      rescue ArgumentError
        raise VerificationError.new("Invalid Date header", status: 401)
      end
      if (Time.now.utc - parsed_date).abs > 720
        raise VerificationError.new("Date header outside allowed window", status: 401)
      end

      # Step 3: Digest validation
      expected_digest = "SHA-256=#{Base64.strict_encode64(Digest::SHA256.digest(raw_body))}"
      actual_digest = extract_sha256_digest(digest_header)
      if actual_digest.nil? || !Rack::Utils.secure_compare(expected_digest, actual_digest)
        raise VerificationError.new("Digest mismatch", status: 401)
      end

      # Step 4: Parse Signature header
      sig_params = parse_signature_header(sig_header)
      key_id = sig_params["keyId"]
      signed_headers_str = sig_params["headers"]
      sig_b64 = sig_params["signature"]

      if empty_str?(key_id) || empty_str?(signed_headers_str) || empty_str?(sig_b64)
        raise VerificationError.new("Incomplete Signature header", status: 401)
      end

      signed_headers = signed_headers_str.split(" ")
      unless signed_headers.include?("date") && signed_headers.include?("digest")
        raise VerificationError.new("Signature must cover date and digest", status: 401)
      end

      # Step 5: Parse JSON body
      activity = begin
        JSON.parse(raw_body)
      rescue JSON::ParserError
        raise VerificationError.new("Invalid JSON body", status: 400)
      end
      raise VerificationError.new("Activity must be a JSON object", status: 400) unless activity.is_a?(Hash)

      actor_uri = activity["actor"]
      raise VerificationError.new("Missing actor string", status: 400) unless actor_uri.is_a?(String) && !actor_uri.empty?

      # Step 6-8: Fetch key, verify ownership, and verify RSA signature (with 1 cache-miss retry)
      signing_string = build_signing_string(request, signed_headers)
      cached = key_cache.get(key_id)
      key_info = cached || fetch_and_cache_key(key_id, config, key_cache, key_fetcher)

      verify_ownership_and_sig!(key_info, actor_uri, sig_b64, signing_string)
      activity
    rescue VerificationError => e
      if e.status == 401 && cached && !key_info.nil?
        key_cache.delete(key_id)
        refreshed = fetch_and_cache_key(key_id, config, key_cache, key_fetcher)
        verify_ownership_and_sig!(refreshed, actor_uri, sig_b64, signing_string)
        return activity
      end
      raise
    end

    def verify_ownership_and_sig!(key_info, actor_uri, sig_b64, signing_string)
      unless key_info[:owner] == actor_uri
        raise VerificationError.new("Key owner mismatch", status: 401)
      end

      pub_key = OpenSSL::PKey::RSA.new(key_info[:public_key_pem])
      valid = pub_key.verify(OpenSSL::Digest::SHA256.new, Base64.decode64(sig_b64), signing_string)
      raise VerificationError.new("Invalid RSA signature", status: 401) unless valid
    rescue OpenSSL::PKey::PKeyError
      raise VerificationError.new("Invalid public key", status: 401)
    end

    def fetch_and_cache_key(key_id, config, key_cache, key_fetcher)
      raise VerificationError.new("Key fetch rate limit exceeded", status: 401) unless key_cache.allow_fetch?

      doc = if key_fetcher
              key_fetcher.call(key_id)
            else
              res = signed_get(url: key_id, config: config)
              raise VerificationError.new("Key fetch failed with #{res[:status]}", status: 401) unless res[:status].between?(200, 299)

              JSON.parse(res[:body])
            end

      raise VerificationError.new("Invalid key document", status: 401) unless doc.is_a?(Hash)

      pub_obj = doc["publicKey"].is_a?(Hash) ? doc["publicKey"] : doc
      owner = pub_obj["owner"] || doc["id"]
      pem = pub_obj["publicKeyPem"]

      if empty_str?(owner) || empty_str?(pem)
        raise VerificationError.new("Missing owner or publicKeyPem", status: 401)
      end

      info = { owner: owner, public_key_pem: pem, inbox: doc["inbox"] }
      key_cache.set(key_id, info)
      info
    rescue SafeHTTP::Error, JSON::ParserError
      raise VerificationError.new("Failed to fetch public key", status: 401)
    end

    def build_signing_string(request, signed_headers)
      signed_headers.map do |h|
        name = h.downcase
        if name == "(request-target)"
          "(request-target): #{request.request_method.downcase} #{request.fullpath}"
        else
          val = case name
                when "content-type" then request.content_type || request.env["CONTENT_TYPE"]
                when "content-length" then request.env["CONTENT_LENGTH"]
                when "host" then request.env["HTTP_HOST"]
                else request.env["HTTP_#{name.upcase.tr('-', '_')}"]
                end
          raise VerificationError.new("Missing signed header: #{name}", status: 401) if val.nil?

          "#{name}: #{val}"
        end
      end.join("\n")
    end

    def extract_sha256_digest(digest_header)
      digest_header.split(",").map(&:strip).find { |part| part.start_with?("SHA-256=") }
    end

    def parse_signature_header(header)
      params = {}
      header.split(",").each do |part|
        key, val = part.strip.split("=", 2)
        next unless key && val

        cleaned = val.strip
        cleaned = cleaned[1..-2] if cleaned.start_with?('"') && cleaned.end_with?('"')
        params[key.strip] = cleaned
      end
      params
    end

    def empty_str?(val)
      val.nil? || val.to_s.strip.empty?
    end
  end
end
