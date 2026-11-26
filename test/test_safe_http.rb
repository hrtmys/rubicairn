# frozen_string_literal: true

require_relative "test_helper"

class TestSafeHTTP < Minitest::Test
  def setup
    @config = Rubicairn::Config.new(
      {
        "domain" => "example.com",
        "username" => "alice",
        "http_open_timeout" => 2,
        "http_read_timeout" => 2
      }
    )
  end

  def test_blocked_private_and_special_ips
    blocked = %w[
      127.0.0.1
      10.0.0.1
      192.168.1.1
      169.254.169.254
      172.16.0.1
      100.64.0.1
      0.0.0.0
      224.0.0.1
      240.0.0.1
      ::1
      ::
      fc00::1
      fe80::1
      ff02::1
      ::ffff:127.0.0.1
      ::ffff:10.0.0.1
      not-an-ip
    ]

    blocked.each do |ip|
      assert Rubicairn::SafeHTTP.blocked_ip?(ip), "Expected #{ip} to be blocked"
    end
  end

  def test_allows_global_ips
    allowed = %w[
      93.184.216.34
      1.1.1.1
      8.8.8.8
      2606:2800:220:1:248:1893:25c8:1946
    ]

    allowed.each do |ip|
      refute Rubicairn::SafeHTTP.blocked_ip?(ip), "Expected #{ip} to be allowed"
    end
  end

  def test_rejects_non_http_scheme_and_loopback_url
    assert_raises(Rubicairn::SafeHTTP::InvalidURLError) do
      Rubicairn::SafeHTTP.request(method: :get, url: "file:///etc/passwd", config: @config)
    end

    assert_raises(Rubicairn::SafeHTTP::BlockedIPError) do
      Rubicairn::SafeHTTP.request(method: :get, url: "http://127.0.0.1:4567/up", config: @config)
    end
  end
end
