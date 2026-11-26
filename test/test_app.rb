# frozen_string_literal: true

require_relative "test_helper"
require_relative "../app"

class TestApp < Minitest::Test
  def setup
    @tmpdir = Dir.mktmpdir("rubicairn_test")
    @db_path = File.join(@tmpdir, "test.db")
    @db = Rubicairn::DB.new(@db_path)

    @local_key = OpenSSL::PKey::RSA.new(2048)
    @config = Rubicairn::Config.new(
      {
        "domain" => "example.com",
        "username" => "alice",
        "display_name" => "Alice",
        "summary" => "Single-user Rubicairn instance.",
        "contact" => "admin@example.com",
        "repository_url" => "https://github.com/example/rubicairn",
        "admin_email" => "alice@example.com",
        "max_followers" => 50,
        "rss_cache_seconds" => 600,
        "http_open_timeout" => 2,
        "http_read_timeout" => 2
      },
      private_key: @local_key
    )

    @key_cache = Rubicairn::HttpSig::KeyCache.new
    @rss_reader = Rubicairn::RssReader.new(@config)

    @remote_key = OpenSSL::PKey::RSA.new(2048)
    @remote_config = Rubicairn::Config.new(
      { "domain" => "remote.example", "username" => "bob" },
      private_key: @remote_key
    )
    @remote_inbox = "https://remote.example/users/bob/inbox"
    @key_cache.set(
      @remote_config.key_id,
      {
        owner: @remote_config.actor_uri,
        public_key_pem: @remote_key.public_key.to_pem,
        inbox: @remote_inbox
      }
    )

    RubicairnApp.set :app_config, @config
    RubicairnApp.set :app_db, @db
    RubicairnApp.set :app_key_cache, @key_cache
    RubicairnApp.set :app_rss_reader, @rss_reader
    RubicairnApp.set :trends_path, File.join(@tmpdir, "trends.json")
    RubicairnApp.set :advisories_path, File.join(@tmpdir, "security_advisories.json")
    RubicairnApp.set :lockfile_path, File.join(@tmpdir, "Gemfile.lock")
    RubicairnApp.set :require_passkey, false

    @req = Rack::MockRequest.new(RubicairnApp)
    @deliveries = []
    @orig_deliver = Rubicairn::ActivityPub.method(:deliver)
    deliveries_ref = @deliveries
    Rubicairn::ActivityPub.singleton_class.define_method(:deliver) do |inbox_uri:, payload:, config:|
      deliveries_ref << { inbox_uri: inbox_uri, payload: payload }
      { status: 202, headers: {}, body: "" }
    end
  end

  def teardown
    RubicairnApp.set :require_passkey, true
    Rubicairn::ActivityPub.singleton_class.define_method(:deliver, @orig_deliver)
    @db.close
    FileUtils.rm_rf(@tmpdir)
  end

  def admin_headers(cookie = nil)
    h = { "HTTP_CF_ACCESS_AUTHENTICATED_USER_EMAIL" => "alice@example.com" }
    h["HTTP_COOKIE"] = cookie if cookie
    h
  end

  def fetch_admin_session_and_csrf
    res = @req.get("/admin", admin_headers)
    assert_equal 200, res.status
    cookie = res.headers["set-cookie"].split(";").first
    match = res.body.match(/name="authenticity_token" value="([^"]+)"/)
    refute_nil match, "CSRF token should be present in admin HTML"
    [cookie, match[1]]
  end

  def post_signed_inbox(activity)
    body = JSON.generate(activity)
    url = "https://example.com/users/alice/inbox"
    headers = Rubicairn::HttpSig.sign_headers(
      method: :post,
      url: url,
      body: body,
      config: @remote_config
    )
    @req.post(
      "/users/alice/inbox",
      input: body,
      "HTTP_HOST" => headers["Host"],
      "HTTP_DATE" => headers["Date"],
      "HTTP_DIGEST" => headers["Digest"],
      "HTTP_SIGNATURE" => headers["Signature"],
      "CONTENT_TYPE" => headers["Content-Type"]
    )
  end

  def test_webfinger
    res = @req.get("/.well-known/webfinger?resource=acct:alice@example.com")
    assert_equal 200, res.status
    assert_includes res.content_type, "application/jrd+json"
    json = JSON.parse(res.body)
    assert_equal "acct:alice@example.com", json["subject"]
    assert_equal "https://example.com/users/alice", json["links"].first["href"]

    res404 = @req.get("/.well-known/webfinger?resource=acct:nobody@example.com")
    assert_equal 404, res404.status
  end

  def test_actor_json_and_public_html
    res_json = @req.get("/users/alice", "HTTP_ACCEPT" => "application/activity+json")
    assert_equal 200, res_json.status
    assert_includes res_json.content_type, "application/activity+json"
    actor = JSON.parse(res_json.body)
    assert_equal "Person", actor["type"]
    assert_equal "alice", actor["preferredUsername"]

    res_html = @req.get("/users/alice", "HTTP_ACCEPT" => "text/html")
    assert_equal 200, res_html.status
    assert_equal "public, max-age=30", res_html.headers["cache-control"]
    assert_includes res_html.headers["content-security-policy"], "default-src 'none'"
    assert_includes res_html.body, "@alice@example.com"
  end

  def test_root_redirect_and_up
    res_root = @req.get("/")
    assert_equal 302, res_root.status
    assert_includes res_root.headers["location"], "/users/alice"

    res_up = @req.get("/up")
    assert_equal 200, res_up.status
    assert_equal "ok", res_up.body
  end

  def test_admin_access_control
    res_no_header = @req.get("/admin")
    assert_equal 403, res_no_header.status

    res_wrong = @req.get("/admin", "HTTP_CF_ACCESS_AUTHENTICATED_USER_EMAIL" => "evil@example.com")
    assert_equal 403, res_wrong.status

    res_ok = @req.get("/admin", admin_headers)
    assert_equal 200, res_ok.status
  end

  def test_admin_post_notes_requires_csrf_and_persists
    cookie, token = fetch_admin_session_and_csrf

    res_no_csrf = @req.post("/admin/notes", admin_headers(cookie).merge(params: { "content" => "Blocked" }))
    assert_equal 403, res_no_csrf.status

    res_ok = @req.post(
      "/admin/notes",
      admin_headers(cookie).merge(params: { "content" => "Hello Rubicairn!", "authenticity_token" => token })
    )
    assert_includes [302, 303], res_ok.status
    assert_includes res_ok.headers["location"], "/admin?msg=posted"
    assert_equal 1, @db.list_public_notes.size
  end

  def test_inbox_like_updates_count_and_hides_actor_on_public_page
    note = @db.create_note("Public note")

    res = post_signed_inbox(
      "id" => "https://remote.example/activities/like-1",
      "type" => "Like",
      "actor" => @remote_config.actor_uri,
      "object" => @config.note_uri(note["id"])
    )
    assert_equal 202, res.status
    assert_equal 1, @db.count_received_likes(note["id"])

    pub_res = @req.get("/users/alice", "HTTP_ACCEPT" => "text/html")
    assert_includes pub_res.body, "&#9829; 1"
    refute_includes pub_res.body, @remote_config.actor_uri

    admin_res = @req.get("/admin", admin_headers)
    assert_includes admin_res.body, @remote_config.actor_uri
  end

  def test_inbox_follow_auto_accepts_followed_and_pends_unknown
    res_pending = post_signed_inbox(
      "id" => "https://remote.example/activities/follow-1",
      "type" => "Follow",
      "actor" => @remote_config.actor_uri,
      "object" => @config.actor_uri
    )
    assert_equal 202, res_pending.status
    assert_equal "pending", @db.find_follower(@remote_config.actor_uri)["status"]

    @db.delete_follower(@remote_config.actor_uri)
    @db.create_following(
      actor_uri: @remote_config.actor_uri,
      inbox_uri: @remote_inbox,
      handle: "bob@remote.example",
      rss_url: "https://remote.example/@bob.rss",
      follow_activity_id: "https://example.com/users/alice#follow-1"
    )

    res_accepted = post_signed_inbox(
      "id" => "https://remote.example/activities/follow-2",
      "type" => "Follow",
      "actor" => @remote_config.actor_uri,
      "object" => @config.actor_uri
    )
    assert_equal 202, res_accepted.status
    assert_equal "accepted", @db.find_follower(@remote_config.actor_uri)["status"]
    assert_equal 1, @deliveries.size
  end

  def test_inbox_create_is_ignored_with_202
    res = post_signed_inbox(
      "id" => "https://remote.example/activities/create-1",
      "type" => "Create",
      "actor" => @remote_config.actor_uri,
      "object" => { "type" => "Note", "content" => "Should not be stored" }
    )
    assert_equal 202, res.status
    assert_equal 0, @db.list_all_notes.size
  end

  def test_note_tombstone_and_outbox_and_body_limits
    note = @db.create_note("Will be deleted")
    res_outbox = @req.get("/users/alice/outbox")
    assert_equal 200, res_outbox.status
    assert_equal 1, JSON.parse(res_outbox.body)["totalItems"]

    @db.soft_delete_note(note["id"])
    res_gone = @req.get("/users/alice/notes/#{note['id']}")
    assert_equal 410, res_gone.status
    assert_equal "Tombstone", JSON.parse(res_gone.body)["type"]

    oversized = "a" * 65_537
    res_413 = @req.post("/users/alice/inbox", input: oversized)
    assert_equal 413, res_413.status
  end

  def test_privacy_page_and_public_follow_panel_and_stats
    @db.create_note("First post")
    res_privacy = @req.get("/privacy")
    assert_equal 200, res_privacy.status
    assert_includes res_privacy.headers["content-security-policy"], "default-src 'none'"
    assert_includes res_privacy.body, "プライバシーポリシー"
    assert_includes res_privacy.body, "<!--email_off-->"
    refute_includes res_privacy.body, "admin@example.com"
    assert_includes res_privacy.body, 'class="m-addr"'
    assert_includes res_privacy.body, '\0040'

    res_pub = @req.get("/users/alice", "HTTP_ACCEPT" => "text/html")
    assert_equal 200, res_pub.status
    assert_includes res_pub.body, "フォロー"
    assert_includes res_pub.body, "サーバー情報"
    assert_includes res_pub.body, "/privacy"
    assert_includes res_pub.body, "<!--email_off-->"
    refute_includes res_pub.body, "admin@example.com"
    assert_includes res_pub.body, 'class="m-addr"'
  end

  def test_admin_tabs_profile_edit_links_and_note_delete
    cookie, token = fetch_admin_session_and_csrf

    %w[posts rss follows profile].each do |tab|
      res_tab = @req.get("/admin?tab=#{tab}", admin_headers(cookie))
      assert_equal 200, res_tab.status
    end

    res_no_csrf = @req.post("/admin/profile", admin_headers(cookie).merge(params: { "display_name" => "NoCSRF" }))
    assert_equal 403, res_no_csrf.status

    res_prof = @req.post(
      "/admin/profile",
      admin_headers(cookie).merge(
        params: {
          "display_name" => "Alice Updated",
          "summary" => "New bio here",
          "contact" => "contact@example.com",
          "privacy_policy" => "Custom note",
          "authenticity_token" => token
        }
      )
    )
    assert_includes [302, 303], res_prof.status
    assert_includes res_prof.headers["location"], "tab=profile&msg=profile_updated"

    res_bad_link = @req.post(
      "/admin/profile/links",
      admin_headers(cookie).merge(
        params: { "label" => "Bad", "url" => "javascript:alert(1)", "authenticity_token" => token }
      )
    )
    assert_includes [302, 303], res_bad_link.status
    assert_equal 0, @db.list_profile_links.size

    res_link = @req.post(
      "/admin/profile/links",
      admin_headers(cookie).merge(
        params: { "label" => "GitHub", "url" => "https://github.com/hrtmys", "authenticity_token" => token }
      )
    )
    assert_includes [302, 303], res_link.status
    links = @db.list_profile_links
    assert_equal 1, links.size

    actor_res = @req.get("/users/alice", "HTTP_ACCEPT" => "application/activity+json")
    actor_json = JSON.parse(actor_res.body)
    assert_equal "Alice Updated", actor_json["name"]
    assert_equal "PropertyValue", actor_json["attachment"].first["type"]
    assert_includes actor_json["attachment"].first["value"], 'rel="me'

    pub_res = @req.get("/users/alice", "HTTP_ACCEPT" => "text/html")
    assert_includes pub_res.body, "Alice Updated"
    assert_includes pub_res.body, "https://github.com/hrtmys"

    res_del_link = @req.post(
      "/admin/profile/links/#{links.first['id']}/delete",
      admin_headers(cookie).merge(params: { "authenticity_token" => token })
    )
    assert_includes [302, 303], res_del_link.status
    assert_equal 0, @db.list_profile_links.size

    note = @db.create_note("Delete me")
    res_del_note = @req.post(
      "/admin/notes/#{note['id']}/delete",
      admin_headers(cookie).merge(params: { "authenticity_token" => token })
    )
    assert_includes [302, 303], res_del_note.status
    refute_nil @db.find_note(note["id"])["deleted_at"]
  end

  def test_follow_by_profile_url_duplicate_unfollow_and_follower_removal
    orig_signed_get = Rubicairn::HttpSig.method(:signed_get)
    Rubicairn::HttpSig.singleton_class.define_method(:signed_get) do |url:, **_kwargs|
      if url == "https://remote.example/@carol"
        {
          status: 200,
          headers: {},
          body: JSON.generate(
            "id" => "https://remote.example/users/carol",
            "inbox" => "https://remote.example/users/carol/inbox",
            "preferredUsername" => "carol"
          )
        }
      else
        { status: 404, headers: {}, body: "" }
      end
    end

    cookie, token = fetch_admin_session_and_csrf
    res_follow = @req.post(
      "/admin/follows",
      admin_headers(cookie).merge(
        params: { "handle" => "https://remote.example/@carol", "authenticity_token" => token }
      )
    )
    assert_includes [302, 303], res_follow.status
    assert_includes res_follow.headers["location"], "msg=followed"
    followings = @db.list_followings
    assert_equal 1, followings.size
    assert_equal "carol@remote.example", followings.first["handle"]

    # Duplicate follow is rejected cleanly
    res_dup = @req.post(
      "/admin/follows",
      admin_headers(cookie).merge(
        params: { "handle" => "https://remote.example/@carol", "authenticity_token" => token }
      )
    )
    assert_includes [302, 303], res_dup.status
    assert_equal 1, @db.list_followings.size

    # Unfollow
    res_unfollow = @req.post(
      "/admin/follows/#{followings.first['id']}/undo",
      admin_headers(cookie).merge(params: { "authenticity_token" => token })
    )
    assert_includes [302, 303], res_unfollow.status
    assert_includes res_unfollow.headers["location"], "msg=unfollowed"
    assert_equal 0, @db.list_followings.size

    # Accepted follower removal
    @db.upsert_follower(
      actor_uri: "https://remote.example/users/carol",
      inbox_uri: "https://remote.example/users/carol/inbox",
      status: "accepted"
    )
    res_remove_follower = @req.post(
      "/admin/followers/reject",
      admin_headers(cookie).merge(
        params: { "actor_uri" => "https://remote.example/users/carol", "authenticity_token" => token }
      )
    )
    assert_includes [302, 303], res_remove_follower.status
    assert_nil @db.find_follower("https://remote.example/users/carol")
  ensure
    Rubicairn::HttpSig.singleton_class.define_method(:signed_get, orig_signed_get)
  end

  def test_admin_displays_security_advisory_banner_and_public_hides_it
    lockfile = File.join(@tmpdir, "Gemfile.lock")
    File.write(lockfile, "GEM\n  specs:\n    puma (6.6.1)\n")
    lock_sha = Digest::SHA256.file(lockfile).hexdigest

    File.write(
      File.join(@tmpdir, "security_advisories.json"),
      JSON.generate(
        {
          "checked_at" => "2026-11-26T00:00:00Z",
          "lockfile_sha256" => lock_sha,
          "gems_checked" => 10,
          "advisories" => [
            {
              "id" => "GHSA-test-0001",
              "gem" => "puma",
              "installed_version" => "6.6.1",
              "severity" => "CRITICAL",
              "fixed_version" => "6.6.2",
              "url" => "https://osv.dev/vulnerability/GHSA-test-0001"
            }
          ]
        }
      )
    )

    # First visit shows the banner
    res_admin = @req.get("/admin", admin_headers)
    assert_equal 200, res_admin.status
    assert_includes res_admin.body, "GHSA-test-0001"
    assert_includes res_admin.body, "CRITICAL"

    # Second visit within 7 days suppresses the top banner
    res_admin_2 = @req.get("/admin", admin_headers)
    assert_equal 200, res_admin_2.status
    refute_includes res_admin_2.body, "GHSA-test-0001"

    # Updating Gemfile.lock clears the advisory immediately
    File.write(lockfile, "GEM\n  specs:\n    puma (8.0.2)\n")
    res_admin_3 = @req.get("/admin?tab=profile", admin_headers)
    assert_equal 200, res_admin_3.status
    refute_includes res_admin_3.body, "GHSA-test-0001"
    assert_includes res_admin_3.body, "更新済み（次回チェック待ち）"

    res_pub = @req.get("/users/alice", "HTTP_ACCEPT" => "text/html")
    assert_equal 200, res_pub.status
    refute_includes res_pub.body, "GHSA-test-0001"
  end

  def test_public_like_guidance_panel_and_jst_local_time
    note = @db.create_note("Timezone test", created_at: "2026-11-26T02:15:00Z")

    res_html = @req.get("/users/alice", "HTTP_ACCEPT" => "text/html")
    assert_equal 200, res_html.status
    assert_includes res_html.body, "2026-11-26 11:15 JST"
    assert_includes res_html.body, 'class="like-box"'
    assert_includes res_html.body, @config.note_uri(note["id"])
    assert_includes res_html.body, "Mastodon"
    assert_includes res_html.body, "Misskey"
    assert_includes res_html.body, "Bluesky"

    # ActivityPub JSON stays in UTC ISO 8601
    res_json = @req.get("/users/alice/notes/#{note['id']}", "HTTP_ACCEPT" => "application/activity+json")
    assert_equal 200, res_json.status
    assert_equal "2026-11-26T02:15:00Z", JSON.parse(res_json.body)["published"]
  end

  def test_resolve_object_html_autodiscovery_and_actor_url_error
    orig_signed_get = Rubicairn::HttpSig.method(:signed_get)
    Rubicairn::HttpSig.singleton_class.define_method(:signed_get) do |url:, **_kwargs|
      case url
      when "https://social.example/@info/post-1"
        {
          status: 200,
          headers: { "content-type" => "text/html; charset=utf-8" },
          body: '<html><head><link rel="alternate" type="application/activity+json" href="/notes/post-1"></head></html>'
        }
      when "https://social.example/notes/post-1"
        {
          status: 200,
          headers: { "content-type" => "application/activity+json" },
          body: JSON.generate(
            "id" => "https://social.example/notes/post-1",
            "type" => "Note",
            "attributedTo" => "https://social.example/users/info",
            "content" => "<p>Hello</p>"
          )
        }
      when "https://social.example/@info"
        {
          status: 200,
          headers: { "content-type" => "text/html; charset=utf-8" },
          body: '<html><head><link rel="alternate" type="application/activity+json" href="https://social.example/users/info"></head></html>'
        }
      when "https://social.example/users/info"
        {
          status: 200,
          headers: { "content-type" => "application/activity+json" },
          body: JSON.generate(
            "id" => "https://social.example/users/info",
            "type" => "Organization",
            "inbox" => "https://social.example/users/info/inbox"
          )
        }
      else
        { status: 404, headers: {}, body: "" }
      end
    end

    resolved = Rubicairn::ActivityPub.resolve_object("https://social.example/@info/post-1", config: @config)
    assert_equal "https://social.example/notes/post-1", resolved[:object_uri]
    assert_equal "https://social.example/users/info", resolved[:actor_uri]
    assert_equal "https://social.example/users/info/inbox", resolved[:inbox_uri]

    err = assert_raises(Rubicairn::ActivityPub::ResolutionError) do
      Rubicairn::ActivityPub.resolve_object("https://social.example/@info", config: @config)
    end
    assert_includes err.message, "このURLはアカウントのようです"
  ensure
    Rubicairn::HttpSig.singleton_class.define_method(:signed_get, orig_signed_get)
  end

  def test_rss_reader_falls_back_to_activitypub_outbox_on_html_response
    orig_request = Rubicairn::SafeHTTP.method(:request)
    Rubicairn::SafeHTTP.singleton_class.define_method(:request) do |url:, **_kwargs|
      case url
      when "https://social.example/@info.rss"
        {
          status: 200,
          headers: { "content-type" => "text/html; charset=utf-8" },
          body: "<!DOCTYPE html><html><head><link rel='stylesheet' href='/a.css'></head><body>Profile</body></html>"
        }
      when "https://social.example/users/info"
        {
          status: 200,
          headers: { "content-type" => "application/activity+json" },
          body: JSON.generate("id" => "https://social.example/users/info", "outbox" => "https://social.example/users/info/outbox")
        }
      when "https://social.example/users/info/outbox"
        {
          status: 200,
          headers: { "content-type" => "application/activity+json" },
          body: JSON.generate(
            "type" => "OrderedCollection",
            "first" => "https://social.example/users/info/outbox?page=true"
          )
        }
      when "https://social.example/users/info/outbox?page=true"
        {
          status: 200,
          headers: { "content-type" => "application/activity+json" },
          body: JSON.generate(
            "type" => "OrderedCollectionPage",
            "orderedItems" => [
              {
                "type" => "Create",
                "published" => "2026-11-26T00:00:00Z",
                "object" => {
                  "id" => "https://social.example/notes/1",
                  "type" => "Note",
                  "url" => "https://social.example/@info/1",
                  "published" => "2026-11-26T00:00:00Z",
                  "content" => "<p>Hello &amp; <b>World</b></p>"
                }
              },
              {
                "type" => "Create",
                "published" => "2026-11-25T00:00:00Z",
                "object" => {
                  "id" => "javascript:alert(1)",
                  "type" => "Note",
                  "url" => "javascript:alert(1)",
                  "content" => "<p>Safe text only</p>"
                }
              }
            ]
          )
        }
      else
        { status: 404, headers: {}, body: "" }
      end
    end

    res = Rubicairn::RssReader.new(@config).fetch_all(
      [
        {
          "handle" => "info@social.example",
          "actor_uri" => "https://social.example/users/info",
          "rss_url" => "https://social.example/@info.rss"
        }
      ],
      force: true
    )

    assert_empty res[:errors]
    assert_equal 2, res[:items].size
    assert_equal "info@social.example", res[:items].first[:author]
    assert_equal "https://social.example/@info/1", res[:items].first[:url]
    assert_equal "Hello & World", res[:items].first[:text]
    assert_nil res[:items].last[:url]
    assert_equal "Safe text only", res[:items].last[:text]
  ensure
    Rubicairn::SafeHTTP.singleton_class.define_method(:request, orig_request)
  end

  def test_admin_rss_tab_protects_handles_from_email_obfuscation
    @db.create_following(
      actor_uri: "https://social.example/users/info",
      inbox_uri: "https://social.example/users/info/inbox",
      handle: "info@social.example",
      rss_url: "https://social.example/@info.rss",
      follow_activity_id: "https://example.com/users/alice#follow-2"
    )

    orig_request = Rubicairn::SafeHTTP.method(:request)
    Rubicairn::SafeHTTP.singleton_class.define_method(:request) do |url:, **_kwargs|
      case url
      when "https://social.example/@info.rss"
        {
          status: 200,
          headers: { "content-type" => "text/html; charset=utf-8" },
          body: "<html><body>no rss</body></html>"
        }
      when "https://social.example/users/info"
        {
          status: 200,
          headers: { "content-type" => "application/activity+json" },
          body: JSON.generate("id" => "https://social.example/users/info", "outbox" => "https://social.example/users/info/outbox")
        }
      when "https://social.example/users/info/outbox"
        {
          status: 200,
          headers: { "content-type" => "application/activity+json" },
          body: JSON.generate(
            "type" => "OrderedCollection",
            "orderedItems" => [
              {
                "type" => "Create",
                "published" => "2026-11-26T00:00:00Z",
                "object" => {
                  "id" => "https://social.example/notes/1",
                  "type" => "Note",
                  "url" => "https://social.example/@info/1",
                  "published" => "2026-11-26T00:00:00Z",
                  "content" => "<p>Inline action test</p>"
                }
              }
            ]
          )
        }
      else
        { status: 404, headers: {}, body: "" }
      end
    end

    res = @req.get("/admin?tab=rss&refresh_rss=1", admin_headers)
    assert_equal 200, res.status
    assert_includes res.body, "<!--email_off-->info<span>@</span>social.example"
    assert_includes res.body, 'action="/admin/likes"'
    assert_includes res.body, 'action="/admin/boosts"'
    assert_includes res.body, 'name="return_tab" value="rss"'
    assert_includes res.body, 'value="https://social.example/@info/1"'
  ensure
    Rubicairn::SafeHTTP.singleton_class.define_method(:request, orig_request)
  end

  def test_boost_displays_sanitized_on_public_page_and_outbox_and_disappears_on_undo
    orig_signed_get = Rubicairn::HttpSig.method(:signed_get)
    Rubicairn::HttpSig.singleton_class.define_method(:signed_get) do |url:, **_kwargs|
      case url
      when "https://social.example/@info/post-xss"
        {
          status: 200,
          headers: { "content-type" => "application/activity+json" },
          body: JSON.generate(
            "id" => "https://social.example/notes/post-xss",
            "type" => "Note",
            "url" => "https://social.example/@info/post-xss",
            "attributedTo" => "https://social.example/users/info",
            "content" => '<script>alert(1)</script><p>Hello <b>Boost</b> https://social.example/ok</p>'
          )
        }
      when "https://social.example/users/info"
        {
          status: 200,
          headers: { "content-type" => "application/activity+json" },
          body: JSON.generate(
            "id" => "https://social.example/users/info",
            "type" => "Organization",
            "name" => "NaCl Info",
            "preferredUsername" => "info",
            "inbox" => "https://social.example/users/info/inbox"
          )
        }
      else
        { status: 404, headers: {}, body: "" }
      end
    end

    cookie, token = fetch_admin_session_and_csrf
    res_boost = @req.post(
      "/admin/boosts",
      admin_headers(cookie).merge(
        params: { "url" => "https://social.example/@info/post-xss", "authenticity_token" => token }
      )
    )
    assert_includes [302, 303], res_boost.status
    assert_includes res_boost.headers["location"], "msg=boosted"

    # Duplicate boost is rejected cleanly
    res_dup = @req.post(
      "/admin/boosts",
      admin_headers(cookie).merge(
        params: { "url" => "https://social.example/@info/post-xss", "authenticity_token" => token }
      )
    )
    assert_includes [302, 303], res_dup.status
    assert_equal 1, @db.list_boosts.size

    # Public page shows sanitized boost under strict CSP
    res_pub = @req.get("/users/alice", "HTTP_ACCEPT" => "text/html")
    assert_equal 200, res_pub.status
    assert_includes res_pub.headers["content-security-policy"], "default-src 'none'"
    assert_includes res_pub.body, "↻ ブースト"
    assert_includes res_pub.body, "NaCl Info"
    assert_includes res_pub.body, "<!--email_off--><span>@</span>info<span>@</span>social.example<!--/email_off-->"
    assert_includes res_pub.body, "Hello Boost"
    assert_includes res_pub.body, 'rel="nofollow noopener noreferrer"'
    refute_includes res_pub.body, "<script>"

    # Outbox includes Announce activity
    res_outbox = @req.get("/users/alice/outbox")
    assert_equal 200, res_outbox.status
    outbox = JSON.parse(res_outbox.body)
    announce = outbox["orderedItems"].find { |i| i["type"] == "Announce" }
    refute_nil announce
    assert_equal "https://social.example/notes/post-xss", announce["object"]

    # Undo removes boost from public page and outbox
    boost_id = @db.list_boosts.first["id"]
    res_undo = @req.post(
      "/admin/boosts/#{boost_id}/undo",
      admin_headers(cookie).merge(params: { "authenticity_token" => token })
    )
    assert_includes [302, 303], res_undo.status

    res_pub_after = @req.get("/users/alice", "HTTP_ACCEPT" => "text/html")
    refute_includes res_pub_after.body, "Hello Boost"
    res_outbox_after = @req.get("/users/alice/outbox")
    assert_equal 0, JSON.parse(res_outbox_after.body)["totalItems"]
  ensure
    Rubicairn::HttpSig.singleton_class.define_method(:signed_get, orig_signed_get)
  end

  def test_db_migrates_legacy_boosts_table
    legacy_path = File.join(@tmpdir, "legacy.db")
    raw = SQLite3::Database.new(legacy_path)
    raw.execute(<<~SQL)
      CREATE TABLE boosts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        target_object_uri TEXT UNIQUE NOT NULL,
        target_actor_uri TEXT NOT NULL,
        target_inbox_uri TEXT NOT NULL,
        activity_id TEXT NOT NULL,
        created_at TEXT NOT NULL
      );
    SQL
    raw.close

    migrated = Rubicairn::DB.new(legacy_path)
    id = migrated.create_boost(
      target_object_uri: "https://social.example/notes/1",
      target_actor_uri: "https://social.example/users/info",
      target_inbox_uri: "https://social.example/users/info/inbox",
      activity_id: "https://example.com/users/alice#announce-1",
      target_url: "https://social.example/@info/1",
      target_author_name: "Info",
      target_author_handle: "@info@social.example",
      target_content_text: "Migrated text"
    )
    row = migrated.find_boost(id)
    assert_equal "Migrated text", row["target_content_text"]
    migrated.close
  end

  def test_favicons_and_minimal_admin_pwa_manifest
    res_manifest = @req.get("/manifest.webmanifest")
    assert_equal 200, res_manifest.status
    assert_includes res_manifest.content_type, "application/manifest+json"
    manifest = JSON.parse(res_manifest.body)
    assert_equal "/admin", manifest["start_url"]
    assert_equal "standalone", manifest["display"]
    icon_srcs = manifest["icons"].map { |i| i["src"] }
    assert_includes icon_srcs, "/icon-192.png"
    assert_includes icon_srcs, "/icon-512.png"

    %w[/favicon.svg /favicon.ico /apple-touch-icon.png /icon-192.png /icon-512.png].each do |path|
      res_asset = @req.get(path)
      assert_equal 200, res_asset.status, "Expected #{path} to return 200"
      refute_empty res_asset.body
    end

    res_pub = @req.get("/users/alice", "HTTP_ACCEPT" => "text/html")
    assert_equal 200, res_pub.status
    assert_includes res_pub.body, 'href="/favicon.svg"'
    assert_includes res_pub.body, 'href="/apple-touch-icon.png"'
    refute_includes res_pub.body, "/manifest.webmanifest"
    assert_includes res_pub.headers["content-security-policy"], "default-src 'none'"
    refute_includes res_pub.headers["content-security-policy"], "script-src"

    res_admin = @req.get("/admin", admin_headers)
    assert_equal 200, res_admin.status
    assert_includes res_admin.body, 'href="/manifest.webmanifest"'
    assert_includes res_admin.body, 'name="apple-mobile-web-app-capable"'
    assert_includes res_admin.headers["content-security-policy"], "manifest-src 'self'"
    assert_includes res_admin.headers["content-security-policy"], "img-src 'self'"
  end
end
