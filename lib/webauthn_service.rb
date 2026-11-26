# frozen_string_literal: true

require "base64"
require "digest"
require "json"
require "openssl"
require "rack/utils"
require "securerandom"

module Rubicairn
  # Pure-Ruby stdlib OpenSSL WebAuthn verifier (zero external webauthn/cbor gems).
  class WebAuthnService
    class Error < StandardError; end

    VerifiedCredential = Struct.new(:id, :public_key, :sign_count)
    Options = Struct.new(:challenge, :payload) do
      def as_json
        payload
      end
    end

    # Strictly bounded pure-Ruby CBOR decoder for WebAuthn attestationObject & legacy COSE keys.
    module MiniCBOR
      MAX_BYTES = 16_384
      MAX_DEPTH = 8

      module_function

      def decode(bytes)
        data = bytes.dup.force_encoding(Encoding::BINARY)
        raise Error, "CBOR payload too large" if data.bytesize > MAX_BYTES

        val, offset = read_item(data, 0, 0)
        raise Error, "Trailing bytes in CBOR" unless offset == data.bytesize

        val
      end

      def read_item(data, pos, depth)
        raise Error, "CBOR nesting too deep" if depth > MAX_DEPTH
        raise Error, "Unexpected end of CBOR" if pos >= data.bytesize

        initial = data.getbyte(pos)
        major = initial >> 5
        addl = initial & 0x1f
        pos += 1

        arg, pos = read_uint(data, pos, addl)

        case major
        when 0 then [arg, pos]
        when 1 then [-1 - arg, pos]
        when 2
          raise Error, "CBOR bytes out of bounds" if pos + arg > data.bytesize

          [data.byteslice(pos, arg), pos + arg]
        when 3
          raise Error, "CBOR text out of bounds" if pos + arg > data.bytesize

          [data.byteslice(pos, arg).force_encoding(Encoding::UTF_8), pos + arg]
        when 4
          arr = []
          arg.times do
            item, pos = read_item(data, pos, depth + 1)
            arr << item
          end
          [arr, pos]
        when 5
          map = {}
          arg.times do
            k, pos = read_item(data, pos, depth + 1)
            v, pos = read_item(data, pos, depth + 1)
            map[k] = v
          end
          [map, pos]
        when 7
          case addl
          when 20 then [false, pos]
          when 21 then [true, pos]
          when 22, 23 then [nil, pos]
          else raise Error, "Unsupported CBOR simple value"
          end
        else
          raise Error, "Unsupported CBOR major type #{major}"
        end
      end

      def read_uint(data, pos, addl)
        case addl
        when 0..23 then [addl, pos]
        when 24
          raise Error, "Unexpected EOF in CBOR uint8" if pos + 1 > data.bytesize

          [data.getbyte(pos), pos + 1]
        when 25
          raise Error, "Unexpected EOF in CBOR uint16" if pos + 2 > data.bytesize

          [data.byteslice(pos, 2).unpack1("n"), pos + 2]
        when 26
          raise Error, "Unexpected EOF in CBOR uint32" if pos + 4 > data.bytesize

          [data.byteslice(pos, 4).unpack1("N"), pos + 4]
        when 27
          raise Error, "Unexpected EOF in CBOR uint64" if pos + 8 > data.bytesize

          [data.byteslice(pos, 8).unpack1("Q>"), pos + 8]
        else
          raise Error, "Unsupported CBOR length encoding #{addl}"
        end
      end
    end

    def initialize(config)
      @config = config
    end

    def allowed_origins(request_base_url: nil)
      origins = ["https://#{@config.domain}"]
      if ENV["RUBICAIRN_DEV_BYPASS_ACCESS"] == "1" && ENV["RACK_ENV"] != "production" && request_base_url
        origins << request_base_url
      end
      origins.uniq
    end

    def registration_options(exclude_ids:, user_id:, user_name:, display_name:, request_base_url: nil)
      challenge = Base64.urlsafe_encode64(SecureRandom.random_bytes(32), padding: false)
      payload = {
        "rp" => { "id" => @config.domain, "name" => "Rubicairn (#{@config.domain})" },
        "user" => { "id" => user_id, "name" => user_name, "displayName" => display_name },
        "challenge" => challenge,
        "pubKeyCredParams" => [
          { "type" => "public-key", "alg" => -7 },
          { "type" => "public-key", "alg" => -257 }
        ],
        "timeout" => 120_000,
        "attestation" => "none",
        "excludeCredentials" => exclude_ids.map { |id| { "type" => "public-key", "id" => id } },
        "authenticatorSelection" => {
          "residentKey" => "preferred",
          "userVerification" => "required"
        }
      }
      {
        options: Options.new(challenge, payload),
        prf_salt_hex: SecureRandom.hex(32)
      }
    end

    def verify_registration(credential_params:, expected_challenge:, request_base_url: nil)
      response = credential_params.fetch("response")
      verify_client_data!(
        response.fetch("clientDataJSON"),
        expected_type: "webauthn.create",
        expected_challenge: expected_challenge,
        request_base_url: request_base_url
      )

      att_raw = b64url_decode(response.fetch("attestationObject"))
      att = MiniCBOR.decode(att_raw)
      raise Error, "Invalid attestationObject" unless att.is_a?(Hash) && att["authData"].is_a?(String)

      auth_data = att["authData"].dup.force_encoding(Encoding::BINARY)
      parsed = parse_auth_data(auth_data, expect_attested: true)

      cred_id_b64 = Base64.urlsafe_encode64(parsed[:credential_id], padding: false)
      unless cred_id_b64 == credential_params["id"].to_s
        raise Error, "Credential ID mismatch"
      end

      pkey = cose_to_pkey(parsed[:cose_key])
      VerifiedCredential.new(cred_id_b64, pkey.public_to_pem, parsed[:sign_count])
    rescue KeyError => e
      raise Error, "Missing WebAuthn parameter: #{e.message}"
    end

    def authentication_options(allow_ids:, request_base_url: nil)
      challenge = Base64.urlsafe_encode64(SecureRandom.random_bytes(32), padding: false)
      payload = {
        "challenge" => challenge,
        "timeout" => 120_000,
        "rpId" => @config.domain,
        "allowCredentials" => allow_ids.map { |id| { "type" => "public-key", "id" => id } },
        "userVerification" => "required"
      }
      Options.new(challenge, payload)
    end

    def verify_authentication(credential_params:, expected_challenge:, stored_public_key:, stored_sign_count:, request_base_url: nil)
      response = credential_params.fetch("response")
      client_data_raw = verify_client_data!(
        response.fetch("clientDataJSON"),
        expected_type: "webauthn.get",
        expected_challenge: expected_challenge,
        request_base_url: request_base_url
      )

      auth_data = b64url_decode(response.fetch("authenticatorData"))
      parsed = parse_auth_data(auth_data, expect_attested: false)

      if (parsed[:sign_count].positive? || stored_sign_count.to_i.positive?) && parsed[:sign_count] <= stored_sign_count.to_i
        raise Error, "Signature counter did not advance"
      end

      pkey = load_stored_public_key(stored_public_key)
      signature = b64url_decode(response.fetch("signature"))
      signed_payload = auth_data + Digest::SHA256.digest(client_data_raw)

      unless pkey.verify(OpenSSL::Digest::SHA256.new, signature, signed_payload)
        raise Error, "Invalid WebAuthn signature"
      end

      VerifiedCredential.new(credential_params["id"].to_s, stored_public_key, parsed[:sign_count])
    rescue KeyError => e
      raise Error, "Missing WebAuthn parameter: #{e.message}"
    rescue OpenSSL::PKey::PKeyError => e
      raise Error, "Invalid stored public key: #{e.message}"
    end

    def load_stored_public_key(stored)
      str = stored.to_s
      return OpenSSL::PKey.read(str) if str.start_with?("-----BEGIN")

      raw = begin
        Base64.urlsafe_decode64(pad_b64(str))
      rescue ArgumentError
        Base64.strict_decode64(str)
      end
      cose_to_pkey(MiniCBOR.decode(raw))
    end

    def cose_to_pkey(cose)
      raise Error, "Invalid COSE key" unless cose.is_a?(Hash)

      kty = cose[1]
      alg = cose[3]
      if kty == 2 && alg == -7 && cose[-1] == 1
        x = cose[-2].to_s.b
        y = cose[-3].to_s.b
        raise Error, "Invalid P-256 coordinates" unless x.bytesize == 32 && y.bytesize == 32

        spki = OpenSSL::ASN1::Sequence.new([
          OpenSSL::ASN1::Sequence.new([
            OpenSSL::ASN1::ObjectId.new("id-ecPublicKey"),
            OpenSSL::ASN1::ObjectId.new("prime256v1")
          ]),
          OpenSSL::ASN1::BitString.new("\x04#{x}#{y}".b)
        ])
        OpenSSL::PKey.read(spki.to_der)
      elsif kty == 3 && alg == -257
        n_bytes = cose[-1].to_s.b
        e_bytes = cose[-2].to_s.b
        raise Error, "Invalid RSA COSE key" if n_bytes.empty? || e_bytes.empty?

        rsa_pub = OpenSSL::ASN1::Sequence.new([
          OpenSSL::ASN1::Integer.new(OpenSSL::BN.new(n_bytes, 2)),
          OpenSSL::ASN1::Integer.new(OpenSSL::BN.new(e_bytes, 2))
        ])
        spki = OpenSSL::ASN1::Sequence.new([
          OpenSSL::ASN1::Sequence.new([
            OpenSSL::ASN1::ObjectId.new("rsaEncryption"),
            OpenSSL::ASN1::Null.new(nil)
          ]),
          OpenSSL::ASN1::BitString.new(rsa_pub.to_der)
        ])
        OpenSSL::PKey.read(spki.to_der)
      else
        raise Error, "Unsupported COSE key type/alg (kty=#{kty}, alg=#{alg})"
      end
    end

    private

    def verify_client_data!(client_data_b64, expected_type:, expected_challenge:, request_base_url:)
      raw = b64url_decode(client_data_b64)
      doc = JSON.parse(raw)
      raise Error, "Invalid clientDataJSON" unless doc.is_a?(Hash)
      raise Error, "Unexpected clientData type" unless doc["type"] == expected_type

      actual_challenge = doc["challenge"].to_s
      if actual_challenge.empty? || expected_challenge.to_s.empty?
        raise Error, "WebAuthn challenge mismatch"
      end

      actual_bytes = b64url_decode(actual_challenge)
      expected_bytes = b64url_decode(expected_challenge.to_s)
      unless actual_bytes.bytesize == expected_bytes.bytesize && Rack::Utils.secure_compare(actual_bytes, expected_bytes)
        raise Error, "WebAuthn challenge mismatch"
      end

      unless allowed_origins(request_base_url: request_base_url).include?(doc["origin"].to_s)
        raise Error, "WebAuthn origin mismatch: #{doc['origin']}"
      end

      raw
    rescue JSON::ParserError => e
      raise Error, "Malformed clientDataJSON: #{e.message}"
    end

    def parse_auth_data(auth_data, expect_attested:)
      raise Error, "authenticatorData too short" if auth_data.bytesize < 37

      rp_id_hash = auth_data.byteslice(0, 32)
      expected_rp_hash = Digest::SHA256.digest(@config.domain)
      raise Error, "RP ID hash mismatch" unless Rack::Utils.secure_compare(rp_id_hash, expected_rp_hash)

      flags = auth_data.getbyte(32)
      raise Error, "User Present flag missing" unless (flags & 0x01) == 0x01
      raise Error, "User Verified flag missing" unless (flags & 0x04) == 0x04

      sign_count = auth_data.byteslice(33, 4).unpack1("N")
      return { sign_count: sign_count } unless expect_attested

      raise Error, "Attested credential data missing" unless (flags & 0x40) == 0x40
      raise Error, "Attested credential header too short" if auth_data.bytesize < 55

      cred_len = auth_data.byteslice(53, 2).unpack1("n")
      raise Error, "Invalid credential ID length" if cred_len.zero? || 55 + cred_len > auth_data.bytesize

      cred_id = auth_data.byteslice(55, cred_len)
      cose_bytes = auth_data.byteslice(55 + cred_len, auth_data.bytesize - (55 + cred_len))
      cose_key = MiniCBOR.decode(cose_bytes)

      { sign_count: sign_count, credential_id: cred_id, cose_key: cose_key }
    end

    def b64url_decode(str)
      Base64.urlsafe_decode64(pad_b64(str))
    rescue ArgumentError => e
      raise Error, "Invalid base64url: #{e.message}"
    end

    def pad_b64(str)
      s = str.to_s.strip
      rem = s.length % 4
      rem.zero? ? s : s + ("=" * (4 - rem))
    end
  end
end
