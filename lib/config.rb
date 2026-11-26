# frozen_string_literal: true

require "openssl"
require "yaml"
require_relative "key_vault"

module Rubicairn
  # Application configuration loader and URI/key helpers.
  class Config
    KEYS = %w[
      domain
      username
      display_name
      summary
      contact
      repository_url
      admin_email
      max_followers
      rss_cache_seconds
      http_open_timeout
      http_read_timeout
      timezone_offset
    ].freeze

    attr_reader :private_key_path, :key_vault

    def self.load(path = "config/app.yml", private_key_path: "config/private.pem")
      raw = YAML.safe_load_file(path, permitted_classes: [], aliases: false) || {}
      new(raw, private_key_path: private_key_path)
    end

    def initialize(attrs = {}, private_key_path: "config/private.pem", private_key: nil, key_vault: nil)
      @data = {}
      attrs.each { |k, v| @data[k.to_s] = v }
      @private_key_path = private_key_path
      @key_vault = key_vault || KeyVault.new(plain_key_path: private_key_path, private_key: private_key)
    end

    def [](key)
      @data[key.to_s]
    end

    KEYS.each do |key|
      define_method(key) { @data[key] }
    end

    def max_followers
      Integer(@data.fetch("max_followers", 50))
    end

    def rss_cache_seconds
      Integer(@data.fetch("rss_cache_seconds", 600))
    end

    def http_open_timeout
      Integer(@data.fetch("http_open_timeout", 3))
    end

    def http_read_timeout
      Integer(@data.fetch("http_read_timeout", 5))
    end

    def timezone_offset
      val = @data["timezone_offset"].to_s.strip
      val.empty? ? "+09:00" : val
    end

    def base_url
      "https://#{domain}"
    end

    def actor_uri
      "https://#{domain}/users/#{username}"
    end

    def inbox_uri
      "https://#{domain}/users/#{username}/inbox"
    end

    def outbox_uri
      "https://#{domain}/users/#{username}/outbox"
    end

    def key_id
      "https://#{domain}/users/#{username}#main-key"
    end

    def note_uri(id)
      "https://#{domain}/users/#{username}/notes/#{id}"
    end

    def user_agent
      "Rubicairn/1.0 (+https://#{domain}/users/#{username})"
    end

    def private_key
      @key_vault.private_key!
    end

    def public_key_pem
      @key_vault.public_key_pem
    end
  end
end
