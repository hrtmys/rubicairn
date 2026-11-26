# frozen_string_literal: true

require "cgi/escape"
require "rss"
require "time"
require_relative "safe_http"

module Rubicairn
  # Fetches, sanitizes, and caches RSS/Atom feeds for followed accounts.
  class RssReader
    MAX_RSS_BYTES = 524_288
    MAX_ITEMS = 100

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
        handle = following["handle"].to_s
        next if rss_url.empty?

        begin
          res = SafeHTTP.request(
            method: :get,
            url: rss_url,
            config: @config,
            max_bytes: MAX_RSS_BYTES
          )
          unless res[:status].between?(200, 299)
            errors << "#{handle}: HTTP #{res[:status]}"
            next
          end

          feed = RSS::Parser.parse(res[:body], false)
          unless feed
            errors << "#{handle}: Failed to parse RSS/Atom"
            next
          end

          feed.items.each do |item|
            url = extract_item_url(item)
            pub_time = extract_published_at(item)
            raw_html = extract_raw_body(item)
            items << {
              author: handle,
              url: url,
              published_at: pub_time,
              text: self.class.extract_plain_text(raw_html)
            }
          end
        rescue StandardError => e
          errors << "#{handle}: #{e.message}"
        end
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
