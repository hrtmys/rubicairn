# frozen_string_literal: true

ENV["RACK_ENV"] = "test"

require "minitest/autorun"
require "openssl"
require "rack/mock"
require "tmpdir"

$LOAD_PATH.unshift(File.expand_path("../lib", __dir__))

require "config"
require "db"
require "safe_http"
require "http_sig"
require "activity_pub"
require "rss_reader"
