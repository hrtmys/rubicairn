# frozen_string_literal: true

require "cgi/escape"
require "json"
require "securerandom"
require "time"
require_relative "http_sig"
require_relative "safe_http"

module Rubicairn
  # ActivityPub JSON builders, remote object/handle resolvers, and outbound delivery.
  module ActivityPub
    class Error < StandardError; end
    class ResolutionError < Error; end
    class DeliveryError < Error; end

    CONTEXT = [
      "https://www.w3.org/ns/activitystreams",
      "https://w3id.org/security/v1"
    ].freeze

    AS_CONTEXT = "https://www.w3.org/ns/activitystreams"
    PUBLIC_COLLECTION = "https://www.w3.org/ns/activitystreams#Public"
    ACTOR_TYPES = %w[Person Organization Service Group Application].freeze

    module_function

    def generate_activity_id(config, prefix = "activity")
      "#{config.actor_uri}##{prefix}-#{SecureRandom.uuid}"
    end

    def strip_html_to_plain_text(html, max_length: 2000)
      str = html.to_s.encode("UTF-8", invalid: :replace, undef: :replace, replace: "")
      str = str.gsub(%r{</p>|<br\s*/?>}i, "\n")
      str = str.gsub(/<[^>]*>/, "")
      str = CGI.unescapeHTML(str)
      str.gsub(/\n{3,}/, "\n\n").strip[0, max_length]
    end

    def format_content_html(raw)
      escaped = CGI.escapeHTML(raw.to_s)
      linked = escaped.gsub(%r{https://[^\s<>"']+}i) do |url|
        %(<a href="#{url}" rel="nofollow noopener noreferrer" target="_blank">#{url}</a>)
      end
      with_br = linked.gsub(/\r\n|\r|\n/, "<br>")
      "<p>#{with_br}</p>"
    end

    def webfinger_json(config)
      {
        "subject" => "acct:#{config.username}@#{config.domain}",
        "links" => [
          {
            "rel" => "self",
            "type" => "application/activity+json",
            "href" => config.actor_uri
          }
        ]
      }
    end

    def actor_json(config, profile: nil)
      display_name = profile && !profile[:display_name].to_s.empty? ? profile[:display_name] : config.display_name
      summary = profile && !profile[:summary].nil? ? profile[:summary] : config.summary
      raw_links = profile && profile[:links].is_a?(Array) ? profile[:links] : []
      valid_links = raw_links.select { |l| l["url"].to_s.start_with?("https://", "http://") }

      ctx = CONTEXT.dup
      if valid_links.any?
        ctx << {
          "schema" => "http://schema.org#",
          "PropertyValue" => "schema:PropertyValue",
          "value" => "schema:value"
        }
      end

      doc = {
        "@context" => ctx,
        "id" => config.actor_uri,
        "type" => "Person",
        "preferredUsername" => config.username,
        "name" => display_name,
        "summary" => format_content_html(summary),
        "url" => config.actor_uri,
        "inbox" => config.inbox_uri,
        "outbox" => config.outbox_uri,
        "manuallyApprovesFollowers" => true,
        "publicKey" => {
          "id" => config.key_id,
          "owner" => config.actor_uri,
          "publicKeyPem" => config.public_key_pem
        }
      }

      if valid_links.any?
        doc["attachment"] = valid_links.map do |link|
          escaped_url = CGI.escapeHTML(link["url"].to_s)
          {
            "type" => "PropertyValue",
            "name" => link["label"].to_s,
            "value" => %(<a href="#{escaped_url}" rel="me nofollow noopener noreferrer" target="_blank">#{escaped_url}</a>)
          }
        end
      end

      doc
    end

    def note_json(config, note, include_context: true)
      uri = config.note_uri(note["id"])
      obj = {
        "id" => uri,
        "type" => "Note",
        "attributedTo" => config.actor_uri,
        "content" => format_content_html(note["content_raw"]),
        "url" => uri,
        "published" => note["created_at"],
        "to" => [PUBLIC_COLLECTION]
      }
      include_context ? { "@context" => AS_CONTEXT }.merge(obj) : obj
    end

    def tombstone_json(config, note)
      {
        "@context" => AS_CONTEXT,
        "id" => config.note_uri(note["id"]),
        "type" => "Tombstone",
        "formerType" => "Note",
        "deleted" => note["deleted_at"]
      }
    end

    def outbox_json(config, notes, boosts: [])
      note_items = notes.map do |note|
        uri = config.note_uri(note["id"])
        {
          "id" => "#{uri}#create",
          "type" => "Create",
          "actor" => config.actor_uri,
          "published" => note["created_at"],
          "to" => [PUBLIC_COLLECTION],
          "object" => note_json(config, note, include_context: false)
        }
      end

      boost_items = boosts.map do |boost|
        {
          "id" => boost["activity_id"],
          "type" => "Announce",
          "actor" => config.actor_uri,
          "published" => boost["created_at"],
          "to" => [PUBLIC_COLLECTION],
          "cc" => [boost["target_actor_uri"]],
          "object" => boost["target_object_uri"]
        }
      end

      items = (note_items + boost_items).sort_by { |i| i["published"].to_s }.reverse.first(50)

      {
        "@context" => AS_CONTEXT,
        "id" => config.outbox_uri,
        "type" => "OrderedCollection",
        "totalItems" => items.size,
        "orderedItems" => items
      }
    end

    def create_activity(config, note)
      {
        "@context" => AS_CONTEXT,
        "id" => "#{config.note_uri(note['id'])}#create",
        "type" => "Create",
        "actor" => config.actor_uri,
        "published" => note["created_at"],
        "to" => [PUBLIC_COLLECTION],
        "object" => note_json(config, note, include_context: false)
      }
    end

    def delete_activity(config, note_uri)
      {
        "@context" => AS_CONTEXT,
        "id" => generate_activity_id(config, "delete"),
        "type" => "Delete",
        "actor" => config.actor_uri,
        "to" => [PUBLIC_COLLECTION],
        "object" => {
          "id" => note_uri,
          "type" => "Tombstone"
        }
      }
    end

    def follow_activity(config, target_actor_uri, activity_id: generate_activity_id(config, "follow"))
      {
        "@context" => AS_CONTEXT,
        "id" => activity_id,
        "type" => "Follow",
        "actor" => config.actor_uri,
        "object" => target_actor_uri
      }
    end

    def accept_activity(config, follow_object)
      obj = if follow_object.is_a?(Hash)
              follow_object
            else
              {
                "type" => "Follow",
                "actor" => follow_object.to_s,
                "object" => config.actor_uri
              }
            end

      {
        "@context" => AS_CONTEXT,
        "id" => generate_activity_id(config, "accept"),
        "type" => "Accept",
        "actor" => config.actor_uri,
        "object" => obj
      }
    end

    def like_activity(config, target_object_uri, activity_id: generate_activity_id(config, "like"))
      {
        "@context" => AS_CONTEXT,
        "id" => activity_id,
        "type" => "Like",
        "actor" => config.actor_uri,
        "object" => target_object_uri
      }
    end

    def announce_activity(config, target_object_uri, target_actor_uri, activity_id: generate_activity_id(config, "announce"))
      {
        "@context" => AS_CONTEXT,
        "id" => activity_id,
        "type" => "Announce",
        "actor" => config.actor_uri,
        "published" => Time.now.utc.iso8601,
        "to" => [PUBLIC_COLLECTION],
        "cc" => [target_actor_uri],
        "object" => target_object_uri
      }
    end

    def undo_activity(config, original_activity_id:, type:, target_uri:)
      {
        "@context" => AS_CONTEXT,
        "id" => generate_activity_id(config, "undo"),
        "type" => "Undo",
        "actor" => config.actor_uri,
        "object" => {
          "id" => original_activity_id,
          "type" => type,
          "actor" => config.actor_uri,
          "object" => target_uri
        }
      }
    end

    def resolve_handle(handle, config:)
      raw = handle.to_s.strip
      return resolve_actor_url(raw, config: config) if raw.start_with?("https://", "http://")

      cleaned = raw.delete_prefix("@")
      user, host = cleaned.split("@", 2)
      if user.nil? || host.nil? || user.empty? || host.empty? || cleaned.match?(%r{[\s/?#]})
        raise ResolutionError, "Invalid handle format"
      end

      resolve_webfinger_handle(user, host, config: config)
    rescue SafeHTTP::Error, JSON::ParserError => e
      raise ResolutionError, e.message
    end

    def discover_activitypub_url(html, base_url)
      snippet = html.to_s[0, 65_536]
      snippet.scan(/<link\b[^>]*>/i) do |tag|
        attrs = {}
        tag.scan(/\b([a-z][a-z0-9_-]*)\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s>]+))/i) do |k, v1, v2, v3|
          attrs[k.downcase] = CGI.unescapeHTML(v1 || v2 || v3 || "")
        end
        next unless attrs["rel"].to_s.downcase.split.include?("alternate")
        next unless attrs["type"].to_s.match?(%r{application/(activity|ld)\+json}i)

        href = attrs["href"].to_s.strip
        next if href.empty?

        begin
          resolved = URI.join(base_url, href).to_s
          SafeHTTP.parse_http_uri!(resolved)
          return resolved
        rescue URI::InvalidURIError, SafeHTTP::Error
          next
        end
      end
      nil
    end

    def extract_actor_hash(actor_doc, fallback_uri)
      return nil unless actor_doc.is_a?(Hash) && !actor_doc["id"].to_s.empty? && !actor_doc["inbox"].to_s.empty?

      actor_uri = actor_doc["id"].to_s
      inbox_uri = actor_doc["inbox"].to_s
      user = actor_doc["preferredUsername"].to_s
      user = fallback_uri.path.split("/").reject(&:empty?).last.to_s.delete_prefix("@") if user.empty?
      host = URI.parse(actor_uri).host || fallback_uri.host
      {
        actor_uri: actor_uri,
        inbox_uri: inbox_uri,
        user: user,
        host: host,
        handle: "#{user}@#{host}"
      }
    end

    def resolve_actor_url(url, config:)
      uri = SafeHTTP.parse_http_uri!(url)
      actor_res = HttpSig.signed_get(url: url, config: config)
      if actor_res[:status].between?(200, 299)
        begin
          actor_doc = JSON.parse(actor_res[:body])
          parsed = extract_actor_hash(actor_doc, uri)
          return parsed if parsed
        rescue JSON::ParserError
          alt_url = discover_activitypub_url(actor_res[:body], url)
          if alt_url
            alt_res = HttpSig.signed_get(url: alt_url, config: config)
            if alt_res[:status].between?(200, 299)
              begin
                parsed = extract_actor_hash(JSON.parse(alt_res[:body]), uri)
                return parsed if parsed
              rescue JSON::ParserError
                # Fall through to WebFinger
              end
            end
          end
        end
      end

      if uri.path =~ %r{\A/@([^/]+)/?\z} || uri.path =~ %r{\A/users/([^/]+)/?\z}
        return resolve_webfinger_handle(Regexp.last_match(1), uri.host, config: config)
      end

      raise ResolutionError, "Could not resolve ActivityPub actor from URL"
    end

    def resolve_webfinger_handle(user, host, config:)
      wf_url = "https://#{host}/.well-known/webfinger?resource=acct:#{CGI.escape(user)}@#{CGI.escape(host)}"
      wf_res = SafeHTTP.request(
        method: :get,
        url: wf_url,
        headers: { "Accept" => "application/jrd+json, application/json" },
        config: config
      )
      raise ResolutionError, "WebFinger returned #{wf_res[:status]}" unless wf_res[:status].between?(200, 299)

      wf_doc = JSON.parse(wf_res[:body])
      links = wf_doc["links"].is_a?(Array) ? wf_doc["links"] : []
      self_link = links.find do |l|
        l.is_a?(Hash) && l["rel"] == "self" &&
          l["type"].to_s.match?(/activity\+json|ld\+json/i) &&
          l["href"].is_a?(String)
      end
      raise ResolutionError, "Actor link not found in WebFinger" unless self_link

      actor_res = HttpSig.signed_get(url: self_link["href"], config: config)
      raise ResolutionError, "Actor fetch returned #{actor_res[:status]}" unless actor_res[:status].between?(200, 299)

      actor_doc = JSON.parse(actor_res[:body])
      actor_uri = actor_doc["id"]
      inbox_uri = actor_doc["inbox"]
      raise ResolutionError, "Missing actor id or inbox" if actor_uri.to_s.empty? || inbox_uri.to_s.empty?

      {
        actor_uri: actor_uri,
        inbox_uri: inbox_uri,
        user: user,
        host: host,
        handle: "#{user}@#{host}"
      }
    end

    def resolve_object(post_url, config:)
      obj_res = HttpSig.signed_get(url: post_url, config: config)
      raise ResolutionError, "Object fetch returned #{obj_res[:status]}" unless obj_res[:status].between?(200, 299)

      doc = begin
              JSON.parse(obj_res[:body])
            rescue JSON::ParserError
              alt_url = discover_activitypub_url(obj_res[:body], post_url)
              raise ResolutionError, "投稿の ActivityPub JSON を取得できませんでした" unless alt_url

              alt_res = HttpSig.signed_get(url: alt_url, config: config)
              raise ResolutionError, "Object fetch returned #{alt_res[:status]}" unless alt_res[:status].between?(200, 299)

              JSON.parse(alt_res[:body])
            end

      raise ResolutionError, "投稿の ActivityPub JSON が不正です" unless doc.is_a?(Hash)

      if ACTOR_TYPES.include?(doc["type"].to_s) || (doc["attributedTo"].nil? && !doc["inbox"].to_s.empty?)
        raise ResolutionError, "このURLはアカウントのようです。ブースト／いいねには個別の投稿URLを指定してください。"
      end

      object_id = doc["id"]
      attr_raw = doc["attributedTo"]
      attributed_to = case attr_raw
                      when String then attr_raw
                      when Array
                        first = attr_raw.first
                        first.is_a?(Hash) ? first["id"] : first.to_s
                      when Hash then attr_raw["id"]
                      end

      if object_id.to_s.empty? || attributed_to.to_s.empty?
        raise ResolutionError, "Object missing id or attributedTo"
      end

      actor_info = fetch_actor_info(attributed_to, config: config)
      raw_url = (doc["url"].is_a?(String) ? doc["url"] : nil) || object_id.to_s
      target_url = raw_url.strip.start_with?("https://", "http://") ? raw_url.strip[0, 500] : nil
      content_text = strip_html_to_plain_text(doc["content"] || doc["summary"] || "")

      {
        object_uri: object_id,
        actor_uri: attributed_to,
        inbox_uri: actor_info[:inbox_uri],
        target_url: target_url,
        author_name: actor_info[:name],
        author_handle: actor_info[:handle],
        content_text: content_text
      }
    rescue SafeHTTP::Error, JSON::ParserError => e
      raise ResolutionError, e.message
    end

    def fetch_actor_info(actor_uri, config:)
      res = HttpSig.signed_get(url: actor_uri, config: config)
      raise ResolutionError, "Actor fetch returned #{res[:status]}" unless res[:status].between?(200, 299)

      doc = JSON.parse(res[:body])
      inbox = doc["inbox"]
      raise ResolutionError, "Actor missing inbox" if inbox.to_s.empty?

      name = doc["name"].to_s.gsub(/[\r\n\t]+/, " ").strip[0, 120]
      username = doc["preferredUsername"].to_s.strip
      host = begin
               URI.parse(actor_uri).host
             rescue URI::InvalidURIError
               nil
             end
      handle = (!username.empty? && host) ? "@#{username}@#{host}"[0, 200] : actor_uri.to_s[0, 200]

      {
        inbox_uri: inbox,
        name: name.empty? ? username[0, 120] : name,
        handle: handle
      }
    rescue SafeHTTP::Error, JSON::ParserError => e
      raise ResolutionError, e.message
    end

    def fetch_actor_inbox(actor_uri, config:)
      fetch_actor_info(actor_uri, config: config)[:inbox_uri]
    end

    def deliver(inbox_uri:, payload:, config:)
      body = payload.is_a?(String) ? payload : JSON.generate(payload)
      res = HttpSig.signed_post(url: inbox_uri, body: body, config: config)
      unless res[:status].between?(200, 299)
        raise DeliveryError, "Delivery to #{inbox_uri} returned HTTP #{res[:status]}"
      end

      res
    rescue SafeHTTP::Error, KeyVault::LockedError => e
      raise DeliveryError, e.message
    end
  end
end
