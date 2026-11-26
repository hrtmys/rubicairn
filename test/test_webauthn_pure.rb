# frozen_string_literal: true

require_relative "test_helper"
require "webauthn_service"

class TestWebAuthnPure < Minitest::Test
  def setup
    @config = Rubicairn::Config.new({ "domain" => "example.com", "username" => "alice" })
    @service = Rubicairn::WebAuthnService.new(@config)
    @ec_key = OpenSSL::PKey::EC.generate("prime256v1")
    @cred_id_raw = OpenSSL::Random.random_bytes(16)
    @cred_id_b64 = Base64.urlsafe_encode64(@cred_id_raw, padding: false)
  end

  def cbor_uint(major, n)
    prefix = major << 5
    if n < 24
      [prefix | n].pack("C")
    elsif n < 256
      [prefix | 24, n].pack("CC")
    elsif n < 65_536
      [prefix | 25, n].pack("Cn")
    else
      [prefix | 26, n].pack("CN")
    end
  end

  def cbor_encode(obj)
    case obj
    when Integer
      obj >= 0 ? cbor_uint(0, obj) : cbor_uint(1, -1 - obj)
    when String
      if obj.encoding == Encoding::BINARY
        cbor_uint(2, obj.bytesize) + obj
      else
        utf = obj.encode(Encoding::UTF_8).b
        cbor_uint(3, utf.bytesize) + utf
      end
    when Hash
      cbor_uint(5, obj.size) + obj.map { |k, v| cbor_encode(k) + cbor_encode(v) }.join.b
    else
      raise "Unsupported in test encoder: #{obj.class}"
    end
  end

  def ec_cose_map
    uncompressed = @ec_key.public_key.to_bn.to_s(2)
    x = uncompressed.byteslice(1, 32).b
    y = uncompressed.byteslice(33, 32).b
    { 1 => 2, 3 => -7, -1 => 1, -2 => x, -3 => y }
  end

  def b64u(bin)
    Base64.urlsafe_encode64(bin, padding: false)
  end

  def test_real_ecdsa_registration_and_authentication_and_legacy_cose
    reg = @service.registration_options(
      exclude_ids: [],
      user_id: "uid-1",
      user_name: "alice@example.com",
      display_name: "Alice"
    )
    challenge = reg[:options].challenge
    assert_equal 43, challenge.length
    refute_includes challenge, "="

    client_data = JSON.generate({ "type" => "webauthn.create", "challenge" => challenge, "origin" => "https://example.com" })
    cose_bytes = cbor_encode(ec_cose_map)
    rp_hash = Digest::SHA256.digest("example.com")
    flags = [0x01 | 0x04 | 0x40].pack("C") # UP + UV + AT
    sign_count = [1].pack("N")
    aaguid = ("\x00" * 16).b
    cred_len = [@cred_id_raw.bytesize].pack("n")
    auth_data = rp_hash + flags + sign_count + aaguid + cred_len + @cred_id_raw + cose_bytes
    att_obj = cbor_encode({ "fmt" => "none", "attStmt" => {}, "authData" => auth_data })

    verified_reg = @service.verify_registration(
      credential_params: {
        "id" => @cred_id_b64,
        "response" => {
          "clientDataJSON" => b64u(client_data),
          "attestationObject" => b64u(att_obj)
        }
      },
      expected_challenge: challenge
    )

    assert_equal @cred_id_b64, verified_reg.id
    assert verified_reg.public_key.start_with?("-----BEGIN PUBLIC KEY-----")
    assert_equal 1, verified_reg.sign_count

    # Real ECDSA authentication (with both SPKI PEM and legacy Base64 COSE format)
    [verified_reg.public_key, Base64.strict_encode64(cose_bytes)].each_with_index do |stored_pk, idx|
      auth_opts = @service.authentication_options(allow_ids: [@cred_id_b64])
      assert_equal 43, auth_opts.challenge.length
      refute_includes auth_opts.challenge, "="
      auth_cd = JSON.generate({ "type" => "webauthn.get", "challenge" => auth_opts.challenge, "origin" => "https://example.com" })
      auth_ad = rp_hash + [0x01 | 0x04].pack("C") + [2 + idx].pack("N")
      sig = @ec_key.sign(OpenSSL::Digest::SHA256.new, auth_ad + Digest::SHA256.digest(auth_cd))

      verified_auth = @service.verify_authentication(
        credential_params: {
          "id" => @cred_id_b64,
          "response" => {
            "clientDataJSON" => b64u(auth_cd),
            "authenticatorData" => b64u(auth_ad),
            "signature" => b64u(sig)
          }
        },
        expected_challenge: auth_opts.challenge,
        stored_public_key: stored_pk,
        stored_sign_count: 1 + idx
      )
      assert_equal 2 + idx, verified_auth.sign_count
    end

    # Tampered signature fails
    auth_opts = @service.authentication_options(allow_ids: [@cred_id_b64])
    auth_cd = JSON.generate({ "type" => "webauthn.get", "challenge" => auth_opts.challenge, "origin" => "https://example.com" })
    auth_ad = rp_hash + [0x01 | 0x04].pack("C") + [10].pack("N")
    bad_sig = @ec_key.sign(OpenSSL::Digest::SHA256.new, "wrong-payload")

    assert_raises(Rubicairn::WebAuthnService::Error) do
      @service.verify_authentication(
        credential_params: {
          "id" => @cred_id_b64,
          "response" => {
            "clientDataJSON" => b64u(auth_cd),
            "authenticatorData" => b64u(auth_ad),
            "signature" => b64u(bad_sig)
          }
        },
        expected_challenge: auth_opts.challenge,
        stored_public_key: verified_reg.public_key,
        stored_sign_count: 5
      )
    end

    # Sign count regression (cloned authenticator) fails
    sig_ok = @ec_key.sign(OpenSSL::Digest::SHA256.new, auth_ad + Digest::SHA256.digest(auth_cd))
    assert_raises(Rubicairn::WebAuthnService::Error) do
      @service.verify_authentication(
        credential_params: {
          "id" => @cred_id_b64,
          "response" => {
            "clientDataJSON" => b64u(auth_cd),
            "authenticatorData" => b64u(auth_ad),
            "signature" => b64u(sig_ok)
          }
        },
        expected_challenge: auth_opts.challenge,
        stored_public_key: verified_reg.public_key,
        stored_sign_count: 20
      )
    end
  end
end
