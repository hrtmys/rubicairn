# frozen_string_literal: true

require "cgi/escape"
require "json"
require "rss"
require "time"
require_relative "safe_http"

module Rubicairn
  # Fetches, sanitizes, and caches RSS/Atom feeds (with ActivityPub Outbox fallback) for followed accounts.
  class RssReader
    MAX_RSS_BYTES = 524_288
    MAX_ACTOR_BYTES = 65_536
    MAX_ITEMS = 100
    AP_ACCEPT = 'application/activity+json, application/ld+json; profile="https://www.w3.org/ns/activitystreams"'

    def initialize(config)
      @config = config
      @mutex = Mutex.new
      @cache = nil
    end

    def fetch_all(followings, force: false)
      @mutex.synchronize do
        if !force && @cache && (Time.now - @cache[:fetched_at]) < @config.rss_cache_seconds
          return @cache
        end
      end

      items = []
      errors = []

      followings.each do |following|
        rss_url = following["rss_url"].to_s
        actor_uri = following["actor_uri"].to_s
        handle = following["handle"].to_s
        next if rss_url.empty? && actor_uri.empty?

        rss_items = nil
        rss_err = nil
        unless rss_url.empty?
          rss_items, rss_err = fetch_rss_items(rss_url, handle)
          if rss_err.nil?
            items.concat(rss_items)
            next
          end
        end

        unless actor_uri.empty?
          outbox_items, outbox_err = fetch_outbox_items(actor_uri, handle)
          if outbox_err.nil?
            items.concat(outbox_items)
            next
          end
          errors << "#{handle}: #{outbox_err}"
          next
        end

        errors << "#{handle}: #{rss_err}" if rss_err
      end

      sorted = items.sort_by { |i| i[:published_at] ? i[:published_at].to_i : 0 }.reverse.first(MAX_ITEMS)
      result = { fetched_at: Time.now, items: sorted, errors: errors }

      @mutex.synchronize do
        @cache = result
      end
      result
    end

    def self.extract_plain_text(html)
      str = html.to_s.encode("UTF-8", invalid: :replace, undef: :replace, replace: "")
      str = str.gsub(%r{</p>|<br\s*/?>}i, "\n")
      str = str.gsub(/<[^>]*>/, "")
      str = CGI.unescapeHTML(str)
      str.gsub(/\n{3,}/, "\n\n").strip
    end

    private

    def fetch_rss_items(rss_url, handle)
      res = SafeHTTP.request(
        method: :get,
        url: rss_url,
        config: @config,
        max_bytes: MAX_RSS_BYTES
      )
      return [nil, "HTTP #{res[:status]}"] unless res[:status].between?(200, 299)
      return [nil, "RSS非対応 (HTML)"] if html_response?(res)

      feed = begin
               RSS::Parser.parse(res[:body], false)
             rescue StandardError
               nil
             end
      return [nil, "RSS/Atom解析失敗"] unless feed

      parsed = feed.items.map do |item|
        {
          author: handle,
          url: extract_item_url(item),
          published_at: extract_published_at(item),
          text: self.class.extract_plain_text(extract_raw_body(item))
        }
      end
      [parsed, nil]
    rescue StandardError => e
      [nil, e.message]
    end

    def html_response?(res)
      ct = res[:headers].is_a?(Hash) ? res[:headers]["content-type"].to_s.downcase : ""
      return true if ct.include?("text/html") || ct.include?("application/xhtml")

      res[:body].to_s.lstrip.match?(/\A(?:<!doctype\s+html\b|<html\b)/i)
    end

    def fetch_outbox_items(actor_uri, handle)
      actor_res = SafeHTTP.request(
        method: :get,
        url: actor_uri,
        headers: { "Accept" => AP_ACCEPT },
        config: @config,
        max_bytes: MAX_ACTOR_BYTES
      )
      return [nil, "Actor HTTP #{actor_res[:status]}"] unless actor_res[:status].between?(200, 299)

      actor_doc = JSON.parse(actor_res[:body])
      outbox_url = actor_doc.is_a?(Hash) ? actor_doc["outbox"].to_s : ""
      return [nil, "Outboxなし"] if outbox_url.empty?

      outbox_res = SafeHTTP.request(
        method: :get,
        url: outbox_url,
        headers: { "Accept" => AP_ACCEPT },
        config: @config,
        max_bytes: MAX_RSS_BYTES
      )
      return [nil, "Outbox HTTP #{outbox_res[:status]}"] unless outbox_res[:status].between?(200, 299)

      outbox_doc = JSON.parse(outbox_res[:body])
      return [nil, "Outbox形式が不正です"] unless outbox_doc.is_a?(Hash)

      raw_items = extract_outbox_raw_items(outbox_doc)
      parsed = raw_items.first(MAX_ITEMS).filter_map { |entry| build_outbox_item(entry, handle) }
      [parsed, nil]
    rescue SafeHTTP::Error, JSON::ParserError, StandardError => e
      [nil, e.message]
    end

    def extract_outbox_raw_items(outbox_doc)
      return outbox_doc["orderedItems"] if outbox_doc["orderedItems"].is_a?(Array)
      return outbox_doc["items"] if outbox_doc["items"].is_a?(Array)

      first = outbox_doc["first"]
      if first.is_a?(Hash)
        return first["orderedItems"] if first["orderedItems"].is_a?(Array)
        return first["items"] if first["items"].is_a?(Array)

        first_url = first["id"].to_s
      else
        first_url = first.to_s
      end
      return [] if first_url.empty?

      page_res = SafeHTTP.request(
        method: :get,
        url: first_url,
        headers: { "Accept" => AP_ACCEPT },
        config: @config,
        max_bytes: MAX_RSS_BYTES
      )
      return [] unless page_res[:status].between?(200, 299)

      page_doc = JSON.parse(page_res[:body])
      return [] unless page_doc.is_a?(Hash)

      items = page_doc["orderedItems"] || page_doc["items"]
      items.is_a?(Array) ? items : []
    end

    def build_outbox_item(entry, handle)
      return nil unless entry.is_a?(Hash)

      if entry["type"] == "Create" && entry["object"].is_a?(Hash)
        note = entry["object"]
        fallback_pub = entry["published"]
      elsif %w[Note Article].include?(entry["type"].to_s)
        note = entry
        fallback_pub = entry["published"]
      else
        return nil
      end

      return nil unless %w[Note Article].include?(note["type"].to_s)

      raw_url = (note["url"].is_a?(String) ? note["url"] : nil) || (note["id"].is_a?(String) ? note["id"] : nil)
      url_str = raw_url.to_s.strip
      url = url_str.start_with?("https://", "http://") ? url_str : nil
      text = self.class.extract_plain_text(note["content"] || note["summary"] || "")
      return nil if text.empty? && url.nil?

      pub_str = (note["published"] || fallback_pub).to_s.strip
      pub_time = begin
                   pub_str.empty? ? nil : Time.parse(pub_str)
                 rescue ArgumentError
                   nil
                 end

      {
        author: handle,
        url: url,
        published_at: pub_time,
        text: text
      }
    end

    def extract_item_url(item)
      raw_link = if item.respond_to?(:link)
                   link_obj = item.link
                   link_obj.respond_to?(:href) ? link_obj.href : link_obj.to_s
                 end
      url = raw_link.to_s.strip
      url.start_with?("https://", "http://") ? url : nil
    end

    def extract_published_at(item)
      val = if item.respond_to?(:pubDate) && item.pubDate
              item.pubDate
            elsif item.respond_to?(:updated) && item.updated
              item.updated.respond_to?(:content) ? item.updated.content : item.updated
            elsif item.respond_to?(:published) && item.published
              item.published.respond_to?(:content) ? item.published.content : item.published
            end
      return val if val.is_a?(Time)
      return Time.parse(val.to_s) if val

      nil
    rescue ArgumentError
      nil
    end

    def extract_raw_body(item)
      if item.respond_to?(:description) && item.description
        item.description
      elsif item.respond_to?(:content_encoded) && item.content_encoded
        item.content_encoded
      elsif item.respond_to?(:content) && item.content
        item.content.respond_to?(:content) ? item.content.content : item.content.to_s
      elsif item.respond_to?(:summary) && item.summary
        item.summary.respond_to?(:content) ? item.summary.content : item.summary.to_s
      elsif item.respond_to?(:title) && item.title
        item.title.respond_to?(:content) ? item.title.content : item.title.to_s
      else
        ""
      end
    end
  end
end
