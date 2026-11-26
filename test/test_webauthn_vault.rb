# frozen_string_literal: true

require_relative "test_helper"
require_relative "../app"

class TestWebAuthnVault < Minitest::Test
  FakeVerifiedCred = Struct.new(:id, :public_key, :sign_count)

  class FakeWebAuthnService
    def initialize(cred_id:, public_key_b64:)
      @cred_id = cred_id
      @public_key_b64 = public_key_b64
      @sign_count = 1
    end

    def registration_options(exclude_ids:, user_id:, user_name:, display_name:, request_base_url: nil)
      opts = Struct.new(:challenge, :to_h) do
        def as_json
          { "challenge" => challenge, "user" => { "id" => "uid", "name" => "alice" } }
        end
      end.new("reg-challenge-123")
      { options: opts, prf_salt_hex: "aa" * 32 }
    end

    def verify_registration(credential_params:, expected_challenge:, request_base_url: nil)
      raise Rubicairn::WebAuthnService::Error, "bad challenge" unless expected_challenge == "reg-challenge-123"

      FakeVerifiedCred.new(@cred_id, @public_key_b64, 1)
    end

    def authentication_options(allow_ids:, request_base_url: nil)
      Struct.new(:challenge) do
        def as_json
          { "challenge" => challenge, "allowCredentials" => [] }
        end
      end.new("auth-challenge-456")
    end

    def verify_authentication(credential_params:, expected_challenge:, stored_public_key:, stored_sign_count:, request_base_url: nil)
      raise Rubicairn::WebAuthnService::Error, "bad auth challenge" unless expected_challenge == "auth-challenge-456"

      @sign_count += 1
      FakeVerifiedCred.new(@cred_id, stored_public_key, @sign_count)
    end
  end

  def setup
    @tmpdir = Dir.mktmpdir("webauthn_test")
    @db = Rubicairn::DB.new(File.join(@tmpdir, "test.db"))
    @plain_pem = File.join(@tmpdir, "private.pem")
    @rsa = OpenSSL::PKey::RSA.new(2048)
    File.open(@plain_pem, "wb", 0o600) { |f| f.write(@rsa.to_pem) }

    @config = Rubicairn::Config.new(
      {
        "domain" => "example.com",
        "username" => "alice",
        "display_name" => "Alice",
        "summary" => "Bio",
        "contact" => "contact@example.com",
        "admin_email" => "alice@example.com"
      },
      private_key_path: @plain_pem
    )
    @key_cache = Rubicairn::HttpSig::KeyCache.new
    @fake_wa = FakeWebAuthnService.new(cred_id: "cred-1", public_key_b64: "pub-cose-1")

    RubicairnApp.set :app_config, @config
    RubicairnApp.set :app_db, @db
    RubicairnApp.set :app_key_cache, @key_cache
    RubicairnApp.set :app_rss_reader, Rubicairn::RssReader.new(@config)
    RubicairnApp.set :app_webauthn_service, @fake_wa
    RubicairnApp.set :require_passkey, true

    @req = Rack::MockRequest.new(RubicairnApp)
    @orig_deliver = Rubicairn::ActivityPub.method(:deliver)
    @orig_resolve_handle = Rubicairn::ActivityPub.method(:resolve_handle)
    Rubicairn::ActivityPub.singleton_class.define_method(:deliver) { |**_kwargs| { status: 202 } }
    Rubicairn::ActivityPub.singleton_class.define_method(:resolve_handle) do |_h, **_kwargs|
      { actor_uri: "https://remote.example/users/bob", inbox_uri: "https://remote.example/users/bob/inbox", user: "bob", host: "remote.example", handle: "bob@remote.example" }
    end
  end

  def teardown
    RubicairnApp.set :app_webauthn_service, nil
    Rubicairn::ActivityPub.singleton_class.define_method(:deliver, @orig_deliver)
    Rubicairn::ActivityPub.singleton_class.define_method(:resolve_handle, @orig_resolve_handle)
    @db.close
    FileUtils.rm_rf(@tmpdir)
  end

  def headers(cookie = nil, extra = {})
    h = { "HTTP_CF_ACCESS_AUTHENTICATED_USER_EMAIL" => "alice@example.com" }.merge(extra)
    h["HTTP_COOKIE"] = cookie if cookie
    h
  end

  def get_auth_cookie_and_csrf
    res = @req.get("/admin/auth", headers)
    assert_equal 200, res.status
    @cookie = res.headers["set-cookie"].split(";").first if res.headers["set-cookie"]
    @csrf = res.body.match(/<meta name="csrf-token" content="([^"]+)">/)[1]
    [@cookie, @csrf]
  end

  def post_json(path, _cookie, csrf, payload = {})
    res = @req.post(
      path,
      headers(@cookie, "CONTENT_TYPE" => "application/json", "HTTP_X_CSRF_TOKEN" => csrf).merge(input: JSON.generate(payload))
    )
    @cookie = res.headers["set-cookie"].split(";").first if res.headers["set-cookie"]
    res
  end

  def test_passkey_seals_vault_gates_admin_and_enforces_step_up
    # Before registration: GET /admin redirects to /admin/auth, POST /admin/notes -> 403
    res_gate = @req.get("/admin", headers)
    assert_includes [302, 303], res_gate.status
    assert_includes res_gate.headers["location"], "/admin/auth"

    cookie, csrf = get_auth_cookie_and_csrf
    res_post_blocked = @req.post("/admin/notes", headers(cookie).merge(params: { "content" => "nope", "authenticity_token" => csrf }))
    assert_equal 403, res_post_blocked.status

    # Register initial Passkey with PRF output -> seals private.pem
    prf_b64 = Base64.urlsafe_encode64("12345678901234567890123456789012", padding: false)
    res_opt = post_json("/admin/webauthn/register/options", cookie, csrf)
    assert_equal 200, res_opt.status

    res_ver = post_json("/admin/webauthn/register/verify", cookie, csrf, {
      "nickname" => "MacBook",
      "wrap_mode" => "prf",
      "prf_output" => prf_b64,
      "credential" => { "id" => "cred-1" }
    })
    assert_equal 200, res_ver.status
    ver_json = JSON.parse(res_ver.body)
    assert ver_json["ok"]
    assert_match(/\A[0-9a-f]{64}\z/, ver_json["recovery_key"])
    refute File.exist?(@plain_pem)
    assert @config.key_vault.sealed?

    # Normal note posting works without step-up
    res_note = @req.post("/admin/notes", headers(@cookie).merge(params: { "content" => "Unlocked post", "authenticity_token" => csrf }))
    assert_includes [302, 303], res_note.status
    @cookie = res_note.headers["set-cookie"].split(";").first if res_note.headers["set-cookie"]
    assert_equal 1, @db.list_public_notes.size

    # Follow & Accept Follower are BLOCKED without step-up token
    res_follow_no_step = @req.post("/admin/follows", headers(@cookie).merge(params: { "handle" => "@bob@remote.example", "authenticity_token" => csrf }))
    assert_equal 403, res_follow_no_step.status

    @db.upsert_follower(actor_uri: "https://remote.example/users/carol", inbox_uri: "https://remote.example/users/carol/inbox", status: "pending")
    res_acc_no_step = @req.post("/admin/followers/accept", headers(@cookie).merge(params: { "actor_uri" => "https://remote.example/users/carol", "authenticity_token" => csrf }))
    assert_equal 403, res_acc_no_step.status

    # Perform step-up for follow
    assert_equal 200, post_json("/admin/webauthn/step_up/options", @cookie, csrf, { "action" => "follow" }).status
    step_res = post_json("/admin/webauthn/step_up/verify", @cookie, csrf, { "credential" => { "id" => "cred-1" } })
    assert_equal 200, step_res.status
    step_token = JSON.parse(step_res.body)["step_up_token"]

    res_follow_ok = @req.post("/admin/follows", headers(@cookie).merge(params: { "handle" => "@bob@remote.example", "authenticity_token" => csrf, "step_up_token" => step_token }))
    assert_includes [302, 303], res_follow_ok.status
    @cookie = res_follow_ok.headers["set-cookie"].split(";").first if res_follow_ok.headers["set-cookie"]
    assert_equal 1, @db.list_followings.size

    # Replay of used step-up token is rejected
    res_follow_replay = @req.post("/admin/follows", headers(@cookie).merge(params: { "handle" => "@bob@remote.example", "authenticity_token" => csrf, "step_up_token" => step_token }))
    assert_equal 403, res_follow_replay.status

    # Lock / logout wipes in-memory key; public Actor JSON still returns 200, private_key! raises LockedError
    res_logout = @req.post("/admin/logout", headers(@cookie).merge(params: { "authenticity_token" => csrf }))
    assert_includes [302, 303], res_logout.status
    @cookie = res_logout.headers["set-cookie"].split(";").first if res_logout.headers["set-cookie"]
    refute @config.key_vault.unlocked?
    assert_raises(Rubicairn::KeyVault::LockedError) { @config.private_key }

    actor_res = @req.get("/users/alice", "HTTP_ACCEPT" => "application/activity+json")
    assert_equal 200, actor_res.status

    # Passkey login unlocks vault again
    assert_equal 200, post_json("/admin/webauthn/login/options", cookie, csrf).status
    login_res = post_json("/admin/webauthn/login/verify", cookie, csrf, {
      "prf_output" => prf_b64,
      "credential" => { "id" => "cred-1" }
    })
    assert_equal 200, login_res.status
    assert @config.key_vault.unlocked?
  end
end
