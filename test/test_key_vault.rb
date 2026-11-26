# frozen_string_literal: true

require_relative "test_helper"
require "key_vault"

class TestKeyVault < Minitest::Test
  def setup
    @tmpdir = Dir.mktmpdir("vault_test")
    @plain_path = File.join(@tmpdir, "private.pem")
    @rsa = OpenSSL::PKey::RSA.new(2048)
    File.open(@plain_path, "wb", 0o600) { |f| f.write(@rsa.to_pem) }
    @vault = Rubicairn::KeyVault.new(plain_key_path: @plain_path)
  end

  def teardown
    FileUtils.rm_rf(@tmpdir)
  end

  def test_seal_lock_unlock_recovery_and_multi_wrap
    prf_b64 = Base64.urlsafe_encode64(OpenSSL::Random.random_bytes(32), padding: false)
    kek1 = Rubicairn::KeyVault.derive_prf_kek(prf_b64)

    sealed = @vault.seal_initial!(kek: kek1)
    assert @vault.sealed?
    assert @vault.unlocked?
    refute File.exist?(@plain_path), "Plaintext private.pem must be wiped and deleted"
    assert File.exist?(@vault.enc_key_path)
    assert_equal 0o600, File.stat(@vault.enc_key_path).mode & 0o777
    assert File.exist?(@vault.public_key_path)

    # Lock wipes in-memory key; public_key_pem still works, private_key! raises LockedError
    @vault.lock!
    refute @vault.unlocked?
    assert_equal @rsa.public_key.to_pem, @vault.public_key_pem
    assert_raises(Rubicairn::KeyVault::LockedError) { @vault.private_key! }

    # Wrong KEK fails
    wrong_kek = Rubicairn::KeyVault.derive_prf_kek(Base64.urlsafe_encode64(OpenSSL::Random.random_bytes(32), padding: false))
    assert_raises(Rubicairn::KeyVault::UnlockError) do
      @vault.unlock_with_kek!(wrapped_vmk_json: sealed[:wrapped_vmk], kek: wrong_kek)
    end
    refute @vault.unlocked?

    # Correct KEK unlocks
    @vault.unlock_with_kek!(wrapped_vmk_json: sealed[:wrapped_vmk], kek: kek1)
    assert @vault.unlocked?
    assert_equal @rsa.to_pem, @vault.private_key!.to_pem

    # Wrap VMK for second Passkey (passphrase mode)
    salt_hex = SecureRandom.hex(16)
    kek2 = Rubicairn::KeyVault.derive_passphrase_kek("correct-horse-battery-staple", salt_hex)
    wrapped2 = @vault.wrap_current_vmk(kek: kek2)
    @vault.lock!

    @vault.unlock_with_kek!(wrapped_vmk_json: wrapped2, kek: kek2)
    assert @vault.unlocked?
    @vault.lock!

    # Recovery key unlocks
    rec_key = [sealed[:recovery_key_hex]].pack("H*")
    @vault.unlock_with_kek!(wrapped_vmk_json: sealed[:recovery_wrapped_vmk], kek: rec_key)
    assert @vault.unlocked?
  end
end
