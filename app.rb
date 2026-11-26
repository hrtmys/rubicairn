# frozen_string_literal: true

require "base64"
require "cgi/escape"
require "digest"
require "json"
require "securerandom"
require "sinatra/base"
require "time"

require_relative "lib/config"
require_relative "lib/db"
require_relative "lib/safe_http"
require_relative "lib/http_sig"
require_relative "lib/activity_pub"
require_relative "lib/rss_reader"
require_relative "lib/webauthn_service"

# Single-user ActivityPub (Mastodon-compatible) server.
class RubicairnApp < Sinatra::Base
  CSP_HEADER = "default-src 'none'; style-src 'unsafe-inline'; img-src 'self';"
  MAX_INBOX_BYTES = 65_536

  set :sessions, true
  set :session_secret, SecureRandom.hex(32)
  set :protection, except: [:authenticity_token]
  set :method_override, false
  set :host_authorization, { permitted_hosts: [] }
  set :views, File.expand_path("views", __dir__)
  set :public_folder, File.expand_path("public", __dir__)
  set :static_cache_control, [:public, { max_age: 86_400 }]

  set :app_config, nil
  set :app_db, nil
  set :app_key_cache, nil
  set :app_rss_reader, nil
  set :app_webauthn_service, nil
  set :trends_path, "data/trends.json"
  set :advisories_path, "data/security_advisories.json"
  set :lockfile_path, "Gemfile.lock"
  set :advisory_remind_interval, 7 * 86_400
  set :require_passkey, true
  set :passkey_session_ttl, 43_200

  helpers do
    def h(str)
      CGI.escapeHTML(str.to_s)
    end

    def safe_url?(url)
      url.to_s.start_with?("https://", "http://")
    end

    def format_local_time(ts)
      str = ts.to_s.strip
      return "" if str.empty?

      t = ts.is_a?(Time) ? ts : Time.parse(str)
      offset = config.timezone_offset.to_s.strip
      offset = "+09:00" unless offset.match?(/\A[+-]\d{2}:\d{2}\z/)
      local = t.getlocal(offset)
      zone_label = offset == "+09:00" ? "JST" : offset
      local.strftime("%Y-%m-%d %H:%M #{zone_label}")
    rescue ArgumentError
      ts.to_s
    end

    def safe_at_html(text)
      "<!--email_off-->#{h(text).gsub('@', '<span>@</span>')}<!--/email_off-->"
    end

    def obfuscated_contact_html(contact)
      str = contact.to_s.strip
      return "" if str.empty?

      if str.include?("@")
        local, domain = str.split("@", 2)
        if !local.empty? && !domain.empty?
          a = local[0, local.length / 2]
          b = local[local.length / 2..]
          c = domain[0, domain.length / 2]
          d = domain[domain.length / 2..]
          return %(<!--email_off--><details class="contact-reveal"><summary>連絡先を表示</summary><span class="m-addr" data-a="#{h(a)}" data-b="#{h(b)}" data-c="#{h(c)}" data-d="#{h(d)}"></span></details><!--/email_off-->)
        end
      end

      if safe_url?(str)
        %(<a href="#{h(str)}" rel="nofollow noopener noreferrer" target="_blank">#{h(str)}</a>)
      else
        h(str)
      end
    end

    def effective_profile
      stored = db.get_profile_settings
      {
        display_name: stored["display_name"] && !stored["display_name"].empty? ? stored["display_name"] : config.display_name,
        summary: stored.key?("summary") ? stored["summary"] : config.summary,
        contact: stored["contact"] && !stored["contact"].empty? ? stored["contact"] : config.contact,
        privacy_policy: stored["privacy_policy"].to_s,
        links: db.list_profile_links
      }
    end

    def profile_stats
      {
        notes: db.count_public_notes,
        followings: db.count_followings,
        followers: db.count_accepted_followers
      }
    end

    def config
      settings.app_config || (settings.app_config = Rubicairn::Config.load)
    end

    def db
      settings.app_db || (settings.app_db = Rubicairn::DB.new("data/core.db"))
    end

    def key_cache
      settings.app_key_cache || (settings.app_key_cache = Rubicairn::HttpSig::KeyCache.new)
    end

    def rss_reader
      settings.app_rss_reader || (settings.app_rss_reader = Rubicairn::RssReader.new(config))
    end

    def activity_pub_accept?
      accept = request.env["HTTP_ACCEPT"].to_s
      accept.include?("application/activity+json") || accept.include?("application/ld+json")
    end

    def json_response(status_code, payload, content_type: "application/activity+json")
      status status_code
      headers "Content-Type" => content_type
      JSON.generate(payload)
    end

    def valid_utf8_param?(val)
      case val
      when String
        val.encoding == Encoding::UTF_8 && val.valid_encoding?
      when Array
        val.all? { |v| valid_utf8_param?(v) }
      when Hash
        val.all? { |k, v| valid_utf8_param?(k) && valid_utf8_param?(v) }
      else
        true
      end
    end

    def read_body_limited(io, max_bytes = MAX_INBOX_BYTES)
      io.rewind if io.respond_to?(:rewind)
      chunks = +""
      while (chunk = io.read(4096))
        chunks << chunk
        halt 413, "Payload Too Large" if chunks.bytesize > max_bytes
      end
      chunks.force_encoding("UTF-8")
      halt 400, "Invalid UTF-8" unless chunks.valid_encoding?
      chunks
    end

    def extract_note_id_from_uri(uri)
      prefix = "#{config.actor_uri}/notes/"
      return nil unless uri.is_a?(String) && uri.start_with?(prefix)

      rest = uri.delete_prefix(prefix)
      return nil unless rest.match?(/\A\d+\z/)

      rest.to_i
    end

    def deliver_with_retry_record(inboxes, payload)
      payload_json = JSON.generate(payload)
      inboxes.uniq.each do |inbox|
        next if inbox.to_s.empty?

        begin
          Rubicairn::ActivityPub.deliver(inbox_uri: inbox, payload: payload_json, config: config)
        rescue Rubicairn::ActivityPub::DeliveryError => e
          db.record_failed_delivery(target_inbox: inbox, payload_json: payload_json, last_error: e.message)
        end
      end
    end

    def load_trends
      path = settings.trends_path
      return nil unless path && File.exist?(path)

      raw = File.read(path, encoding: "UTF-8")
      return nil unless raw.valid_encoding?

      JSON.parse(raw)
    rescue JSON::ParserError, Errno::ENOENT
      nil
    end

    def load_security_advisories
      path = settings.advisories_path
      return nil unless path && File.exist?(path)

      raw = File.read(path, encoding: "UTF-8")
      return nil unless raw.valid_encoding?

      doc = JSON.parse(raw)
      return nil unless doc.is_a?(Hash)

      if doc["lockfile_sha256"] && settings.lockfile_path && File.exist?(settings.lockfile_path)
        current_sha = Digest::SHA256.file(settings.lockfile_path).hexdigest
        if current_sha != doc["lockfile_sha256"]
          return doc.merge("advisories" => [], "stale_after_update" => true)
        end
      end

      doc
    rescue JSON::ParserError, Errno::ENOENT
      nil
    end

    def should_show_advisory_banner?(doc)
      return false unless doc && doc["advisories"].is_a?(Array) && !doc["advisories"].empty?

      fingerprint = doc["advisories"].map { |a| "#{a['id']}:#{a['gem']}:#{a['installed_version']}" }.sort.join(",")
      stored = db.get_profile_settings
      last_fp = stored["advisory_last_fingerprint"].to_s
      last_shown = stored["advisory_last_shown_at"].to_i

      if fingerprint != last_fp || (Time.now.to_i - last_shown) >= settings.advisory_remind_interval
        db.set_profile_setting("advisory_last_fingerprint", fingerprint)
        db.set_profile_setting("advisory_last_shown_at", Time.now.to_i.to_s)
        true
      else
        false
      end
    end

    def webauthn_service
      settings.app_webauthn_service || (settings.app_webauthn_service = Rubicairn::WebAuthnService.new(config))
    end

    def admin_csp_header(nonce)
      "default-src 'none'; script-src 'nonce-#{nonce}'; style-src 'unsafe-inline'; img-src 'self'; manifest-src 'self'; connect-src 'self';"
    end

    def passkey_session_valid?
      verified_at = session[:passkey_verified_at].to_i
      return false if verified_at <= 0

      (Time.now.to_i - verified_at) < settings.passkey_session_ttl
    end

    def passkey_unlocked_and_valid?
      db.count_webauthn_credentials.positive? && passkey_session_valid? && config.key_vault.unlocked?
    end

    def require_step_up!(action)
      return unless settings.require_passkey

      token = params["step_up_token"].to_s
      tokens = session[:step_up_tokens]
      entry = tokens.is_a?(Hash) ? tokens.delete(action.to_s) : nil
      valid = entry && Time.now.to_i <= entry["expires_at"].to_i && !token.empty? &&
              Rack::Utils.secure_compare(token, entry["token"].to_s)
      halt 403, "Passkey re-authentication required" unless valid
    end

    def parse_json_body(max_bytes = 16_384)
      raw = read_body_limited(request.body, max_bytes)
      JSON.parse(raw)
    rescue JSON::ParserError
      halt 400, "Invalid JSON"
    end

    def derive_kek(wrap_mode:, prf_output:, passphrase:, prf_salt_hex:)
      if wrap_mode == "prf"
        raise Rubicairn::KeyVault::UnlockError, "Missing PRF output" if prf_output.to_s.empty?

        Rubicairn::KeyVault.derive_prf_kek(prf_output.to_s)
      elsif wrap_mode == "passphrase"
        raise Rubicairn::KeyVault::UnlockError, "Vault passphrase must be at least 12 characters" if passphrase.to_s.length < 12

        Rubicairn::KeyVault.derive_passphrase_kek(passphrase.to_s, prf_salt_hex.to_s)
      else
        raise Rubicairn::KeyVault::UnlockError, "Unsupported wrap mode"
      end
    end

    def b64url_encode(bin)
      Base64.urlsafe_encode64(bin, padding: false)
    end
  end

  before do
    halt 400, "Invalid UTF-8" unless valid_utf8_param?(request.GET)
    if request.form_data? && !request.path_info.end_with?("/inbox")
      halt 400, "Invalid UTF-8" unless valid_utf8_param?(request.POST)
    end
  end

  PASSKEY_EXEMPT_PATHS = %w[
    /admin/auth
    /admin/logout
    /admin/webauthn/register/options
    /admin/webauthn/register/verify
    /admin/webauthn/login/options
    /admin/webauthn/login/verify
    /admin/webauthn/recover
  ].freeze

  before "/admin*" do
    dev_bypass = ENV["RUBICAIRN_DEV_BYPASS_ACCESS"] == "1" && ENV["RACK_ENV"] != "production"
    unless dev_bypass
      email = request.env["HTTP_CF_ACCESS_AUTHENTICATED_USER_EMAIL"].to_s
      expected = config.admin_email.to_s
      if email.empty? || expected.empty? || !Rack::Utils.secure_compare(email, expected)
        halt 403, "Forbidden"
      end
    end

    session[:csrf_token] ||= SecureRandom.hex(32)

    if request.post?
      token = params["authenticity_token"].to_s
      token = request.env["HTTP_X_CSRF_TOKEN"].to_s if token.empty?
      if token.empty? || !Rack::Utils.secure_compare(token, session[:csrf_token])
        halt 403, "Invalid CSRF token"
      end
    end

    if settings.require_passkey && !PASSKEY_EXEMPT_PATHS.include?(request.path_info)
      unless passkey_unlocked_and_valid?
        if request.get?
          redirect "/admin/auth"
        else
          halt 403, "Passkey authentication required"
        end
      end
    end
  end

  get "/" do
    redirect "/users/#{config.username}"
  end

  get "/up" do
    if db.ping
      status 200
      "ok"
    else
      status 500
      "error"
    end
  rescue StandardError
    status 500
    "error"
  end

  get "/manifest.webmanifest" do
    profile = effective_profile
    headers "Cache-Control" => "public, max-age=3600"
    manifest = {
      "name" => "#{profile[:display_name]} - Rubicairn",
      "short_name" => "Rubicairn",
      "start_url" => "/admin",
      "scope" => "/",
      "display" => "standalone",
      "background_color" => "#141416",
      "theme_color" => "#141416",
      "icons" => [
        { "src" => "/icon-192.png", "sizes" => "192x192", "type" => "image/png", "purpose" => "any maskable" },
        { "src" => "/icon-512.png", "sizes" => "512x512", "type" => "image/png", "purpose" => "any maskable" }
      ]
    }
    json_response(200, manifest, content_type: "application/manifest+json")
  end

  get "/.well-known/webfinger" do
    expected = "acct:#{config.username}@#{config.domain}"
    halt 404, "Not Found" unless params["resource"] == expected

    json_response(200, Rubicairn::ActivityPub.webfinger_json(config), content_type: "application/jrd+json")
  end

  get "/privacy" do
    headers "Cache-Control" => "public, max-age=30",
            "Content-Security-Policy" => CSP_HEADER
    @profile = effective_profile
    erb :privacy
  end

  get "/users/:name" do
    halt 404, "Not Found" unless params["name"] == config.username

    profile = effective_profile
    if activity_pub_accept?
      json_response(200, Rubicairn::ActivityPub.actor_json(config, profile: profile))
    else
      headers "Cache-Control" => "public, max-age=30",
              "Content-Security-Policy" => CSP_HEADER
      @profile = profile
      @stats = profile_stats
      notes = db.list_public_notes(limit: 50)
      boosts = db.list_boosts(limit: 50)
      @timeline = (notes.map { |n| n.merge("kind" => "note") } + boosts.map { |b| b.merge("kind" => "boost") })
                  .sort_by { |item| item["created_at"].to_s }
                  .reverse
                  .first(50)
      erb :public
    end
  end

  get "/users/:name/outbox" do
    halt 404, "Not Found" unless params["name"] == config.username

    notes = db.list_public_notes(limit: 50)
    boosts = db.list_boosts(limit: 50)
    json_response(200, Rubicairn::ActivityPub.outbox_json(config, notes, boosts: boosts))
  end

  get "/users/:name/notes/:id" do
    halt 404, "Not Found" unless params["name"] == config.username
    halt 404, "Not Found" unless params["id"].to_s.match?(/\A\d+\z/)

    note = db.find_note(params["id"].to_i)
    halt 404, "Not Found" unless note

    if note["deleted_at"]
      return json_response(410, Rubicairn::ActivityPub.tombstone_json(config, note))
    end

    if activity_pub_accept?
      json_response(200, Rubicairn::ActivityPub.note_json(config, note))
    else
      headers "Cache-Control" => "public, max-age=30",
              "Content-Security-Policy" => CSP_HEADER
      @profile = effective_profile
      @stats = profile_stats
      @timeline = [note.merge("kind" => "note", "like_count" => db.count_received_likes(note["id"]))]
      erb :public
    end
  end

  post "/users/:name/inbox" do
    halt 404, "Not Found" unless params["name"] == config.username

    raw_body = read_body_limited(request.body, MAX_INBOX_BYTES)

    begin
      activity = Rubicairn::HttpSig.verify_inbox_request(
        request: request,
        raw_body: raw_body,
        config: config,
        key_cache: key_cache
      )
    rescue Rubicairn::HttpSig::VerificationError => e
      halt e.status, e.message
    end

    actor_uri = activity["actor"]

    case activity["type"]
    when "Follow"
      target_obj = activity["object"].is_a?(Hash) ? activity["object"]["id"] : activity["object"]
      halt 400, "Invalid Follow target" unless target_obj == config.actor_uri

      inbox_uri = activity["inbox"]
      if inbox_uri.to_s.empty?
        sig_params = Rubicairn::HttpSig.parse_signature_header(request.env["HTTP_SIGNATURE"].to_s)
        cached = key_cache.get(sig_params["keyId"])
        inbox_uri = cached[:inbox] if cached && !cached[:inbox].to_s.empty?
      end
      if inbox_uri.to_s.empty?
        begin
          inbox_uri = Rubicairn::ActivityPub.fetch_actor_inbox(actor_uri, config: config)
        rescue Rubicairn::ActivityPub::ResolutionError
          halt 400, "Could not resolve follower inbox"
        end
      end

      if db.following_actor?(actor_uri)
        db.upsert_follower(actor_uri: actor_uri, inbox_uri: inbox_uri, status: "accepted")
        accept_payload = Rubicairn::ActivityPub.accept_activity(config, activity)
        deliver_with_retry_record([inbox_uri], accept_payload)
      else
        existing = db.find_follower(actor_uri)
        if existing.nil? && db.count_followers >= config.max_followers
          halt 403, "Follower limit reached"
        end
        status_val = existing ? existing["status"] : "pending"
        db.upsert_follower(actor_uri: actor_uri, inbox_uri: inbox_uri, status: status_val)
      end

    when "Undo"
      obj = activity["object"]
      if obj.is_a?(Hash)
        case obj["type"]
        when "Follow"
          db.delete_follower(actor_uri)
        when "Like"
          target_uri = obj["object"]
          note_id = extract_note_id_from_uri(target_uri)
          db.remove_received_like(actor_uri: actor_uri, note_id: note_id, activity_id: obj["id"])
        end
      elsif obj.is_a?(String)
        db.remove_received_like(actor_uri: actor_uri, activity_id: obj)
      end

    when "Like"
      note_id = extract_note_id_from_uri(activity["object"])
      if note_id
        note = db.find_note(note_id)
        if note && note["deleted_at"].nil?
          db.add_received_like(
            note_id: note_id,
            actor_uri: actor_uri,
            activity_id: activity["id"]
          )
        end
      end

    when "Delete"
      obj = activity["object"]
      deleted_id = obj.is_a?(Hash) ? obj["id"] : obj.to_s
      db.delete_follower(actor_uri) if deleted_id == actor_uri
    end

    status 202
    ""
  end

  get "/admin/auth" do
    @csp_nonce = SecureRandom.base64(16)
    headers "Content-Security-Policy" => admin_csp_header(@csp_nonce),
            "Cache-Control" => "no-store"

    @profile = effective_profile
    @credentials_count = db.count_webauthn_credentials
    @vault_sealed = config.key_vault.sealed?
    @has_recovery = !db.get_vault_recovery.nil?
    @flash_error = session.delete(:flash_error)
    @msg = params["msg"]
    erb :admin_auth
  end

  post "/admin/logout" do
    config.key_vault.lock!
    session.delete(:passkey_verified_at)
    session.delete(:step_up_tokens)
    redirect "/admin/auth?msg=locked"
  end

  post "/admin/webauthn/register/options" do
    if db.count_webauthn_credentials.positive?
      halt 403, "Passkey authentication required" unless passkey_unlocked_and_valid?
    end

    session[:webauthn_user_id] ||= SecureRandom.urlsafe_base64(32)
    exclude_ids = db.list_webauthn_credentials.map { |c| c["external_id"] }
    res = webauthn_service.registration_options(
      exclude_ids: exclude_ids,
      user_id: session[:webauthn_user_id],
      user_name: "#{config.username}@#{config.domain}",
      display_name: effective_profile[:display_name],
      request_base_url: request.base_url
    )

    session[:webauthn_reg_challenge] = res[:options].challenge
    session[:webauthn_reg_prf_salt] = res[:prf_salt_hex]

    json_response(
      200,
      {
        "options" => res[:options].as_json,
        "prf_salt" => b64url_encode([res[:prf_salt_hex]].pack("H*"))
      },
      content_type: "application/json"
    )
  end

  post "/admin/webauthn/register/verify" do
    is_additional = db.count_webauthn_credentials.positive?
    if is_additional
      halt 403, "Passkey authentication required" unless passkey_unlocked_and_valid?
    end

    data = parse_json_body
    if is_additional && settings.require_passkey
      params["step_up_token"] = data["step_up_token"].to_s
      require_step_up!("manage_passkey")
    end

    expected_challenge = session.delete(:webauthn_reg_challenge)
    prf_salt_hex = session.delete(:webauthn_reg_prf_salt)
    halt 400, "Registration challenge expired" if expected_challenge.to_s.empty? || prf_salt_hex.to_s.empty?

    cred = webauthn_service.verify_registration(
      credential_params: data.fetch("credential"),
      expected_challenge: expected_challenge,
      request_base_url: request.base_url
    )

    wrap_mode = data["wrap_mode"].to_s == "passphrase" ? "passphrase" : "prf"
    kek = derive_kek(
      wrap_mode: wrap_mode,
      prf_output: data["prf_output"],
      passphrase: data["vault_passphrase"],
      prf_salt_hex: prf_salt_hex
    )

    nickname = data["nickname"].to_s.strip
    nickname = "Passkey ##{db.count_webauthn_credentials + 1}" if nickname.empty?

    recovery_key_hex = nil
    if config.key_vault.sealed? || is_additional
      wrapped_vmk = config.key_vault.wrap_current_vmk(kek: kek)
    else
      sealed = config.key_vault.seal_initial!(kek: kek)
      wrapped_vmk = sealed[:wrapped_vmk]
      recovery_key_hex = sealed[:recovery_key_hex]
      db.save_vault_recovery(wrapped_vmk: sealed[:recovery_wrapped_vmk])
    end

    db.create_webauthn_credential(
      external_id: cred.id,
      public_key: cred.public_key,
      sign_count: cred.sign_count,
      nickname: nickname[0, 60],
      wrap_mode: wrap_mode,
      prf_salt: prf_salt_hex,
      wrapped_vmk: wrapped_vmk
    )

    session[:passkey_verified_at] = Time.now.to_i
    resp = { "ok" => true, "redirect" => is_additional ? "/admin?tab=profile&msg=passkey_added" : "/admin?msg=passkey_registered" }
    resp["recovery_key"] = recovery_key_hex if recovery_key_hex
    json_response(200, resp, content_type: "application/json")
  rescue Rubicairn::WebAuthnService::Error, Rubicairn::KeyVault::Error, KeyError => e
    json_response(400, { "error" => e.message }, content_type: "application/json")
  end

  post "/admin/webauthn/login/options" do
    creds = db.list_webauthn_credentials
    halt 400, "No Passkeys registered" if creds.empty?

    options = webauthn_service.authentication_options(
      allow_ids: creds.map { |c| c["external_id"] },
      request_base_url: request.base_url
    )
    session[:webauthn_auth_challenge] = options.challenge

    prf_salts = {}
    wrap_modes = {}
    creds.each do |c|
      prf_salts[c["external_id"]] = b64url_encode([c["prf_salt"]].pack("H*"))
      wrap_modes[c["external_id"]] = c["wrap_mode"]
    end

    json_response(
      200,
      { "options" => options.as_json, "prf_salts" => prf_salts, "wrap_modes" => wrap_modes },
      content_type: "application/json"
    )
  end

  post "/admin/webauthn/login/verify" do
    data = parse_json_body
    expected_challenge = session.delete(:webauthn_auth_challenge)
    halt 400, "Authentication challenge expired" if expected_challenge.to_s.empty?

    cred_params = data.fetch("credential")
    stored = db.find_webauthn_credential_by_external_id(cred_params["id"])
    halt 401, "Unknown Passkey" unless stored

    verified = webauthn_service.verify_authentication(
      credential_params: cred_params,
      expected_challenge: expected_challenge,
      stored_public_key: stored["public_key"],
      stored_sign_count: stored["sign_count"],
      request_base_url: request.base_url
    )

    kek = derive_kek(
      wrap_mode: stored["wrap_mode"],
      prf_output: data["prf_output"],
      passphrase: data["vault_passphrase"],
      prf_salt_hex: stored["prf_salt"]
    )
    config.key_vault.unlock_with_kek!(
      wrapped_vmk_json: stored["wrapped_vmk"],
      kek: kek,
      ttl: settings.passkey_session_ttl
    )
    db.update_webauthn_credential_usage(stored["id"], sign_count: verified.sign_count)
    session[:passkey_verified_at] = Time.now.to_i

    json_response(200, { "ok" => true, "redirect" => "/admin" }, content_type: "application/json")
  rescue Rubicairn::WebAuthnService::Error, Rubicairn::KeyVault::Error, KeyError => e
    json_response(401, { "error" => e.message }, content_type: "application/json")
  end

  post "/admin/webauthn/step_up/options" do
    halt 403, "Passkey authentication required" unless passkey_unlocked_and_valid?

    data = parse_json_body
    action = data["action"].to_s
    halt 400, "Invalid step-up action" unless %w[follow accept_follower manage_passkey].include?(action)

    creds = db.list_webauthn_credentials
    options = webauthn_service.authentication_options(
      allow_ids: creds.map { |c| c["external_id"] },
      request_base_url: request.base_url
    )
    session[:webauthn_step_up_challenge] = options.challenge
    session[:webauthn_step_up_action] = action

    json_response(200, { "options" => options.as_json }, content_type: "application/json")
  end

  post "/admin/webauthn/step_up/verify" do
    halt 403, "Passkey authentication required" unless passkey_unlocked_and_valid?

    data = parse_json_body
    expected_challenge = session.delete(:webauthn_step_up_challenge)
    action = session.delete(:webauthn_step_up_action)
    halt 400, "Step-up challenge expired" if expected_challenge.to_s.empty? || action.to_s.empty?

    cred_params = data.fetch("credential")
    stored = db.find_webauthn_credential_by_external_id(cred_params["id"])
    halt 401, "Unknown Passkey" unless stored

    verified = webauthn_service.verify_authentication(
      credential_params: cred_params,
      expected_challenge: expected_challenge,
      stored_public_key: stored["public_key"],
      stored_sign_count: stored["sign_count"],
      request_base_url: request.base_url
    )
    db.update_webauthn_credential_usage(stored["id"], sign_count: verified.sign_count)

    token = SecureRandom.hex(24)
    session[:step_up_tokens] ||= {}
    session[:step_up_tokens][action] = {
      "token" => token,
      "expires_at" => Time.now.to_i + 60
    }

    json_response(200, { "ok" => true, "step_up_token" => token }, content_type: "application/json")
  rescue Rubicairn::WebAuthnService::Error, KeyError => e
    json_response(401, { "error" => e.message }, content_type: "application/json")
  end

  post "/admin/webauthn/recover" do
    rec_hex = params["recovery_key"].to_s.strip.downcase
    recovery_row = db.get_vault_recovery
    unless recovery_row && rec_hex.match?(/\A[0-9a-f]{64}\z/)
      session[:flash_error] = "リカバリーキーが無効です。"
      redirect "/admin/auth"
    end

    rec_key = [rec_hex].pack("H*")
    config.key_vault.unlock_with_kek!(
      wrapped_vmk_json: recovery_row["wrapped_vmk"],
      kek: rec_key,
      ttl: settings.passkey_session_ttl
    )
    session[:passkey_verified_at] = Time.now.to_i
    redirect "/admin?tab=profile&msg=recovered"
  rescue Rubicairn::KeyVault::Error => e
    session[:flash_error] = e.message
    redirect "/admin/auth"
  end

  post "/admin/passkeys/:id/delete" do
    require_step_up!("manage_passkey")
    if db.count_webauthn_credentials <= 1
      session[:flash_error] = "最後の Passkey は削除できません。"
      redirect "/admin?tab=profile"
    end

    db.delete_webauthn_credential(params["id"].to_i)
    redirect "/admin?tab=profile&msg=passkey_deleted"
  end

  get "/admin" do
    @csp_nonce = SecureRandom.base64(16)
    headers "Content-Security-Policy" => admin_csp_header(@csp_nonce),
            "Cache-Control" => "no-store"

    @tab = %w[posts rss follows profile].include?(params["tab"]) ? params["tab"] : (params["refresh_rss"] == "1" ? "rss" : "posts")
    @msg = params["msg"]
    @flash_error = session.delete(:flash_error)
    @profile = effective_profile
    @stats = profile_stats

    @pending_followers = db.list_followers(status: "pending")
    @pending_count = @pending_followers.size

    @notes = db.list_all_notes(limit: 50)
    @received_likes_map = db.received_likes_by_note_ids(@notes.map { |n| n["id"] })
    @likes = db.list_likes
    @boosts = db.list_boosts
    @followings = db.list_followings
    @accepted_followers = db.list_followers(status: "accepted")
    @failed_deliveries = db.list_failed_deliveries
    @passkeys = db.list_webauthn_credentials
    @vault_sealed = config.key_vault.sealed?
    @vault_ttl = config.key_vault.remaining_ttl
    @security_advisories = load_security_advisories
    @show_advisory_banner = should_show_advisory_banner?(@security_advisories)

    if @tab == "rss"
      @trends = load_trends
      force_rss = params["refresh_rss"] == "1"
      @rss_data = rss_reader.fetch_all(@followings, force: force_rss)
    end

    erb :admin
  end

  post "/admin/notes" do
    content = params["content"].to_s.strip
    if content.empty?
      session[:flash_error] = "投稿内容を入力してください。"
      redirect "/admin"
    end

    note = db.create_note(content)
    payload = Rubicairn::ActivityPub.create_activity(config, note)
    deliver_with_retry_record(db.accepted_follower_inboxes, payload)
    redirect "/admin?msg=posted"
  rescue StandardError => e
    session[:flash_error] = e.message
    redirect "/admin"
  end

  post "/admin/notes/:id/delete" do
    note = db.find_note(params["id"].to_i)
    unless note
      session[:flash_error] = "投稿が見つかりません。"
      redirect "/admin"
    end

    if db.soft_delete_note(note["id"])
      payload = Rubicairn::ActivityPub.delete_activity(config, config.note_uri(note["id"]))
      deliver_with_retry_record(db.accepted_follower_inboxes, payload)
    end
    redirect "/admin?msg=deleted"
  rescue StandardError => e
    session[:flash_error] = e.message
    redirect "/admin"
  end

  post "/admin/likes" do
    return_tab = params["return_tab"] == "rss" ? "rss" : nil
    base_redirect = return_tab ? "/admin?tab=rss" : "/admin"
    url = params["url"].to_s.strip
    if url.empty?
      session[:flash_error] = "対象URLを入力してください。"
      redirect base_redirect
    end

    resolved = Rubicairn::ActivityPub.resolve_object(url, config: config)
    activity_id = Rubicairn::ActivityPub.generate_activity_id(config, "like")
    payload = Rubicairn::ActivityPub.like_activity(config, resolved[:object_uri], activity_id: activity_id)
    Rubicairn::ActivityPub.deliver(inbox_uri: resolved[:inbox_uri], payload: payload, config: config)
    db.create_like(
      target_object_uri: resolved[:object_uri],
      target_inbox_uri: resolved[:inbox_uri],
      activity_id: activity_id
    )
    redirect return_tab ? "/admin?tab=rss&msg=liked" : "/admin?msg=liked"
  rescue StandardError => e
    session[:flash_error] = e.message
    redirect base_redirect
  end

  post "/admin/likes/:id/undo" do
    like = db.find_like(params["id"].to_i)
    unless like
      session[:flash_error] = "対象のいいねが見つかりません。"
      redirect "/admin"
    end

    payload = Rubicairn::ActivityPub.undo_activity(
      config,
      original_activity_id: like["activity_id"],
      type: "Like",
      target_uri: like["target_object_uri"]
    )
    deliver_with_retry_record([like["target_inbox_uri"]], payload)
    db.delete_like(like["id"])
    redirect "/admin?msg=unliked"
  rescue StandardError => e
    session[:flash_error] = e.message
    redirect "/admin"
  end

  post "/admin/boosts" do
    return_tab = params["return_tab"] == "rss" ? "rss" : nil
    base_redirect = return_tab ? "/admin?tab=rss" : "/admin"
    url = params["url"].to_s.strip
    if url.empty?
      session[:flash_error] = "対象URLを入力してください。"
      redirect base_redirect
    end

    resolved = Rubicairn::ActivityPub.resolve_object(url, config: config)
    if db.boosted_object?(resolved[:object_uri])
      session[:flash_error] = "すでにブースト済みです。"
      redirect base_redirect
    end

    activity_id = Rubicairn::ActivityPub.generate_activity_id(config, "announce")
    payload = Rubicairn::ActivityPub.announce_activity(
      config,
      resolved[:object_uri],
      resolved[:actor_uri],
      activity_id: activity_id
    )
    inboxes = ([resolved[:inbox_uri]] + db.accepted_follower_inboxes).uniq
    deliver_with_retry_record(inboxes, payload)
    db.create_boost(
      target_object_uri: resolved[:object_uri],
      target_actor_uri: resolved[:actor_uri],
      target_inbox_uri: resolved[:inbox_uri],
      activity_id: activity_id,
      target_url: resolved[:target_url],
      target_author_name: resolved[:author_name],
      target_author_handle: resolved[:author_handle],
      target_content_text: resolved[:content_text]
    )
    redirect return_tab ? "/admin?tab=rss&msg=boosted" : "/admin?msg=boosted"
  rescue StandardError => e
    session[:flash_error] = e.message
    redirect base_redirect
  end

  post "/admin/boosts/:id/undo" do
    boost = db.find_boost(params["id"].to_i)
    unless boost
      session[:flash_error] = "対象のブーストが見つかりません。"
      redirect "/admin"
    end

    payload = Rubicairn::ActivityPub.undo_activity(
      config,
      original_activity_id: boost["activity_id"],
      type: "Announce",
      target_uri: boost["target_object_uri"]
    )
    inboxes = ([boost["target_inbox_uri"]] + db.accepted_follower_inboxes).uniq
    deliver_with_retry_record(inboxes, payload)
    db.delete_boost(boost["id"])
    redirect "/admin?msg=unboosted"
  rescue StandardError => e
    session[:flash_error] = e.message
    redirect "/admin"
  end

  post "/admin/follows" do
    require_step_up!("follow")
    handle = params["handle"].to_s.strip
    if handle.empty?
      session[:flash_error] = "ハンドルを入力してください。"
      redirect "/admin?tab=follows"
    end

    resolved = Rubicairn::ActivityPub.resolve_handle(handle, config: config)
    if db.following_actor?(resolved[:actor_uri])
      session[:flash_error] = "すでにフォロー済みです。"
      redirect "/admin?tab=follows"
    end

    rss_url = params["rss_url"].to_s.strip
    rss_url = "https://#{resolved[:host]}/@#{resolved[:user]}.rss" if rss_url.empty?

    activity_id = Rubicairn::ActivityPub.generate_activity_id(config, "follow")
    payload = Rubicairn::ActivityPub.follow_activity(config, resolved[:actor_uri], activity_id: activity_id)
    Rubicairn::ActivityPub.deliver(inbox_uri: resolved[:inbox_uri], payload: payload, config: config)
    db.create_following(
      actor_uri: resolved[:actor_uri],
      inbox_uri: resolved[:inbox_uri],
      handle: resolved[:handle],
      rss_url: rss_url,
      follow_activity_id: activity_id
    )
    redirect "/admin?tab=follows&msg=followed"
  rescue StandardError => e
    session[:flash_error] = e.message
    redirect "/admin?tab=follows"
  end

  post "/admin/follows/:id/undo" do
    following = db.find_following(params["id"].to_i)
    unless following
      session[:flash_error] = "対象のフォローが見つかりません。"
      redirect "/admin?tab=follows"
    end

    payload = Rubicairn::ActivityPub.undo_activity(
      config,
      original_activity_id: following["follow_activity_id"],
      type: "Follow",
      target_uri: following["actor_uri"]
    )
    deliver_with_retry_record([following["inbox_uri"]], payload)
    db.delete_following(following["id"])
    redirect "/admin?tab=follows&msg=unfollowed"
  rescue StandardError => e
    session[:flash_error] = e.message
    redirect "/admin?tab=follows"
  end

  post "/admin/followers/accept" do
    require_step_up!("accept_follower")
    actor_uri = params["actor_uri"].to_s.strip
    follower = db.accept_follower(actor_uri)
    unless follower
      session[:flash_error] = "フォロワーが見つかりません。"
      redirect "/admin?tab=follows"
    end

    payload = Rubicairn::ActivityPub.accept_activity(config, actor_uri)
    deliver_with_retry_record([follower["inbox_uri"]], payload)
    redirect "/admin?tab=follows&msg=accepted"
  rescue StandardError => e
    session[:flash_error] = e.message
    redirect "/admin?tab=follows"
  end

  post "/admin/followers/reject" do
    actor_uri = params["actor_uri"].to_s.strip
    db.delete_follower(actor_uri)
    redirect "/admin?tab=follows&msg=rejected"
  rescue StandardError => e
    session[:flash_error] = e.message
    redirect "/admin?tab=follows"
  end

  post "/admin/profile" do
    display_name = params["display_name"].to_s.strip
    summary = params["summary"].to_s.strip
    contact = params["contact"].to_s.strip
    privacy_policy = params["privacy_policy"].to_s.strip

    if display_name.empty? || display_name.length > 80
      session[:flash_error] = "表示名は1〜80文字で入力してください。"
      redirect "/admin?tab=profile"
    end
    if summary.length > 500 || contact.length > 120 || privacy_policy.length > 4000
      session[:flash_error] = "入力文字数が上限を超えています。"
      redirect "/admin?tab=profile"
    end

    db.set_profile_setting("display_name", display_name)
    db.set_profile_setting("summary", summary)
    db.set_profile_setting("contact", contact)
    db.set_profile_setting("privacy_policy", privacy_policy)
    redirect "/admin?tab=profile&msg=profile_updated"
  rescue StandardError => e
    session[:flash_error] = e.message
    redirect "/admin?tab=profile"
  end

  post "/admin/profile/links" do
    label = params["label"].to_s.strip
    url = params["url"].to_s.strip

    if label.empty? || label.length > 60
      session[:flash_error] = "リンク名は1〜60文字で入力してください。"
      redirect "/admin?tab=profile"
    end
    unless safe_url?(url) && url.length <= 300
      session[:flash_error] = "URLは https:// または http:// から始まる300文字以内で入力してください。"
      redirect "/admin?tab=profile"
    end
    if db.list_profile_links.size >= 10
      session[:flash_error] = "外部リンクは最大10件までです。"
      redirect "/admin?tab=profile"
    end

    db.add_profile_link(label: label, url: url)
    redirect "/admin?tab=profile&msg=link_added"
  rescue StandardError => e
    session[:flash_error] = e.message
    redirect "/admin?tab=profile"
  end

  post "/admin/profile/links/:id/delete" do
    db.delete_profile_link(params["id"].to_i)
    redirect "/admin?tab=profile&msg=link_deleted"
  rescue StandardError => e
    session[:flash_error] = e.message
    redirect "/admin?tab=profile"
  end

  post "/admin/deliveries/:id/retry" do
    delivery = db.find_failed_delivery(params["id"].to_i)
    unless delivery
      session[:flash_error] = "対象の配送失敗レコードが見つかりません。"
      redirect "/admin"
    end

    begin
      Rubicairn::ActivityPub.deliver(
        inbox_uri: delivery["target_inbox"],
        payload: delivery["payload_json"],
        config: config
      )
      db.delete_failed_delivery(delivery["id"])
    rescue Rubicairn::ActivityPub::DeliveryError => e
      db.increment_failed_delivery(delivery["id"], e.message)
      session[:flash_error] = e.message
    end
    redirect "/admin?msg=retried"
  end

  post "/admin/deliveries/:id/delete" do
    db.delete_failed_delivery(params["id"].to_i)
    redirect "/admin?msg=delivery_deleted"
  end
end
