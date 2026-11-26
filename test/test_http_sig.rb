# frozen_string_literal: true

require_relative "test_helper"

class TestHttpSig < Minitest::Test
  def setup
    @remote_key = OpenSSL::PKey::RSA.new(2048)
    @remote_config = Rubicairn::Config.new(
      { "domain" => "remote.example", "username" => "bob" },
      private_key: @remote_key
    )
    @local_config = Rubicairn::Config.new(
      { "domain" => "example.com", "username" => "alice" },
      private_key: OpenSSL::PKey::RSA.new(2048)
    )
    @key_cache = Rubicairn::HttpSig::KeyCache.new
  end

  def build_signed_request(body:, date: Time.now.utc, actor: @remote_config.actor_uri, owner: @remote_config.actor_uri)
    url = "https://example.com/users/alice/inbox"
    headers = Rubicairn::HttpSig.sign_headers(
      method: :post,
      url: url,
      body: body,
      config: @remote_config,
      date: date
    )

    env = Rack::MockRequest.env_for(
      url,
      method: "POST",
      input: body,
      "HTTP_HOST" => headers["Host"],
      "HTTP_DATE" => headers["Date"],
      "HTTP_DIGEST" => headers["Digest"],
      "HTTP_SIGNATURE" => headers["Signature"],
      "CONTENT_TYPE" => headers["Content-Type"]
    )
    request = Rack::Request.new(env)
    fetcher = ->(_key_id) { { "id" => owner, "publicKey" => { "owner" => owner, "publicKeyPem" => @remote_key.public_key.to_pem } } }
    [request, fetcher]
  end

  def test_valid_signed_post_passes
    body = JSON.generate({ "type" => "Like", "actor" => @remote_config.actor_uri, "object" => "https://example.com/users/alice/notes/1" })
    request, fetcher = build_signed_request(body: body)

    activity = Rubicairn::HttpSig.verify_inbox_request(
      request: request,
      raw_body: body,
      config: @local_config,
      key_cache: @key_cache,
      key_fetcher: fetcher
    )

    assert_equal "Like", activity["type"]
    assert_equal @remote_config.actor_uri, activity["actor"]
  end

  def test_tampered_body_returns_401
    body = JSON.generate({ "type" => "Like", "actor" => @remote_config.actor_uri, "object" => "https://example.com/users/alice/notes/1" })
    request, fetcher = build_signed_request(body: body)
    tampered = body.sub("notes/1", "notes/2")

    err = assert_raises(Rubicairn::HttpSig::VerificationError) do
      Rubicairn::HttpSig.verify_inbox_request(
        request: request,
        raw_body: tampered,
        config: @local_config,
        key_cache: @key_cache,
        key_fetcher: fetcher
      )
    end
    assert_equal 401, err.status
  end

  def test_expired_date_returns_401
    body = JSON.generate({ "type" => "Like", "actor" => @remote_config.actor_uri })
    request, fetcher = build_signed_request(body: body, date: Time.now.utc - 900)

    err = assert_raises(Rubicairn::HttpSig::VerificationError) do
      Rubicairn::HttpSig.verify_inbox_request(
        request: request,
        raw_body: body,
        config: @local_config,
        key_cache: @key_cache,
        key_fetcher: fetcher
      )
    end
    assert_equal 401, err.status
  end

  def test_owner_mismatch_returns_401
    body = JSON.generate({ "type" => "Like", "actor" => @remote_config.actor_uri })
    request, fetcher = build_signed_request(body: body, owner: "https://evil.example/users/mallory")

    err = assert_raises(Rubicairn::HttpSig::VerificationError) do
      Rubicairn::HttpSig.verify_inbox_request(
        request: request,
        raw_body: body,
        config: @local_config,
        key_cache: @key_cache,
        key_fetcher: fetcher
      )
    end
    assert_equal 401, err.status
  end
end
