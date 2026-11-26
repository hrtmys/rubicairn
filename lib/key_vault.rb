# frozen_string_literal: true

require "base64"
require "digest"
require "json"
require "openssl"

module Rubicairn
  # Envelope-encrypted RSA private key vault unlocked in memory only via Passkey/Recovery.
  class KeyVault
    class Error < StandardError; end
    class LockedError < Error; end
    class UnlockError < Error; end

    DEFAULT_TTL = 43_200 # 12 hours
    SCRYPT_N = 16_384
    SCRYPT_R = 8
    SCRYPT_P = 1

    attr_reader :plain_key_path, :enc_key_path, :public_key_path

    def self.aes_gcm_encrypt(key32, plaintext)
      raise ArgumentError, "Key must be 32 bytes" unless key32.bytesize == 32

      cipher = OpenSSL::Cipher.new("aes-256-gcm")
      cipher.encrypt
      iv = cipher.random_iv
      cipher.key = key32
      cipher.auth_data = "minimumdon-vault-v1" # Kept as v1 vault AAD for live key compatibility
      ct = cipher.update(plaintext) + cipher.final
      tag = cipher.auth_tag

      JSON.generate(
        {
          "v" => 1,
          "alg" => "aes-256-gcm",
          "iv" => Base64.strict_encode64(iv),
          "tag" => Base64.strict_encode64(tag),
          "ct" => Base64.strict_encode64(ct)
        }
      )
    end

    def self.aes_gcm_decrypt(key32, json_blob)
      raise UnlockError, "Key must be 32 bytes" unless key32.bytesize == 32

      doc = JSON.parse(json_blob.to_s)
      raise UnlockError, "Unsupported vault format" unless doc.is_a?(Hash) && doc["alg"] == "aes-256-gcm"

      cipher = OpenSSL::Cipher.new("aes-256-gcm")
      cipher.decrypt
      cipher.key = key32
      cipher.iv = Base64.strict_decode64(doc.fetch("iv"))
      cipher.auth_tag = Base64.strict_decode64(doc.fetch("tag"))
      cipher.auth_data = "minimumdon-vault-v1" # Kept as v1 vault AAD for live key compatibility
      cipher.update(Base64.strict_decode64(doc.fetch("ct"))) + cipher.final
    rescue JSON::ParserError, KeyError, ArgumentError, OpenSSL::Cipher::CipherError => e
      raise UnlockError, "Decryption failed: #{e.message}"
    end

    def self.derive_prf_kek(prf_b64url)
      raw = Base64.urlsafe_decode64(pad_b64url(prf_b64url))
      raise UnlockError, "Empty PRF output" if raw.empty?

      # Kept as v1 KDF prefix for live key compatibility
      Digest::SHA256.digest("minimumdon-vmk-v1:#{raw}")
    rescue ArgumentError => e
      raise UnlockError, "Invalid PRF encoding: #{e.message}"
    end

    def self.derive_passphrase_kek(passphrase, salt_hex)
      salt = [salt_hex.to_s].pack("H*")
      raise UnlockError, "Invalid salt" if salt.empty?

      OpenSSL::KDF.scrypt(
        passphrase.to_s,
        salt: salt,
        N: SCRYPT_N,
        r: SCRYPT_R,
        p: SCRYPT_P,
        length: 32
      )
    end

    def self.pad_b64url(str)
      s = str.to_s.strip
      rem = s.length % 4
      rem.zero? ? s : s + ("=" * (4 - rem))
    end

    def initialize(plain_key_path: "config/private.pem", enc_key_path: nil, public_key_path: nil, private_key: nil)
      @plain_key_path = plain_key_path
      @enc_key_path = enc_key_path || "#{plain_key_path}.enc"
      @public_key_path = public_key_path || File.join(File.dirname(plain_key_path), "public.pem")
      @injected_key = private_key
      @unlocked_private_key = nil
      @unlocked_vmk = nil
      @unlocked_until = nil
      @mutex = Mutex.new
    end

    def sealed?
      @mutex.synchronize { File.exist?(@enc_key_path) }
    end

    def unlocked?
      @mutex.synchronize do
        return true if @injected_key
        return true if !File.exist?(@enc_key_path) && File.exist?(@plain_key_path)

        valid_unlocked_locked?
      end
    end

    def remaining_ttl
      @mutex.synchronize do
        return nil unless valid_unlocked_locked?

        [(@unlocked_until - Time.now).to_i, 0].max
      end
    end

    def private_key!
      @mutex.synchronize do
        return @injected_key if @injected_key

        if File.exist?(@enc_key_path)
          unless valid_unlocked_locked?
            clear_memory_locked!
            raise LockedError, "Key vault is locked. Authenticate with Passkey to unlock."
          end
          return @unlocked_private_key
        end

        raise LockedError, "Private key not found" unless File.exist?(@plain_key_path)

        OpenSSL::PKey::RSA.new(File.read(@plain_key_path))
      end
    end

    def public_key_pem
      @mutex.synchronize do
        return File.read(@public_key_path) if File.exist?(@public_key_path)
        return @injected_key.public_key.to_pem if @injected_key

        if valid_unlocked_locked?
          return @unlocked_private_key.public_key.to_pem
        end

        if !File.exist?(@enc_key_path) && File.exist?(@plain_key_path)
          pem = OpenSSL::PKey::RSA.new(File.read(@plain_key_path)).public_key.to_pem
          File.write(@public_key_path, pem)
          return pem
        end

        raise LockedError, "Public key unavailable while vault is locked"
      end
    end

    def seal_initial!(kek:, recovery_key: nil, ttl: DEFAULT_TTL)
      @mutex.synchronize do
        raw_pem = if @injected_key
                    @injected_key.to_pem
                  elsif File.exist?(@plain_key_path)
                    File.read(@plain_key_path)
                  else
                    raise Error, "No plaintext private key available to seal"
                  end

        rsa = OpenSSL::PKey::RSA.new(raw_pem)
        pub_pem = rsa.public_key.to_pem
        File.write(@public_key_path, pub_pem)

        vmk = OpenSSL::Random.random_bytes(32)
        rec_key = recovery_key || OpenSSL::Random.random_bytes(32)

        enc_blob = self.class.aes_gcm_encrypt(vmk, raw_pem)
        File.open(@enc_key_path, "wb", 0o600) { |f| f.write(enc_blob) }
        File.chmod(0o600, @enc_key_path)

        if File.exist?(@plain_key_path)
          size = File.size(@plain_key_path)
          File.open(@plain_key_path, "wb") { |f| f.write("\x00" * size) }
          File.delete(@plain_key_path)
        end

        @unlocked_private_key = rsa
        @unlocked_vmk = vmk
        @unlocked_until = Time.now + ttl

        {
          wrapped_vmk: self.class.aes_gcm_encrypt(kek, vmk),
          recovery_wrapped_vmk: self.class.aes_gcm_encrypt(rec_key, vmk),
          recovery_key_hex: rec_key.unpack1("H*")
        }
      end
    end

    def unlock_with_kek!(wrapped_vmk_json:, kek:, ttl: DEFAULT_TTL)
      @mutex.synchronize do
        raise Error, "Encrypted key file missing" unless File.exist?(@enc_key_path)

        vmk = self.class.aes_gcm_decrypt(kek, wrapped_vmk_json)
        raw_pem = self.class.aes_gcm_decrypt(vmk, File.read(@enc_key_path))
        rsa = OpenSSL::PKey::RSA.new(raw_pem)

        unless File.exist?(@public_key_path)
          File.write(@public_key_path, rsa.public_key.to_pem)
        end

        @unlocked_private_key = rsa
        @unlocked_vmk = vmk
        @unlocked_until = Time.now + ttl
        true
      end
    end

    def wrap_current_vmk(kek:)
      @mutex.synchronize do
        unless valid_unlocked_locked? && @unlocked_vmk
          clear_memory_locked!
          raise LockedError, "Key vault is locked"
        end

        self.class.aes_gcm_encrypt(kek, @unlocked_vmk)
      end
    end

    def lock!
      @mutex.synchronize do
        clear_memory_locked!
      end
    end

    private

    def valid_unlocked_locked?
      !@unlocked_private_key.nil? && !@unlocked_until.nil? && Time.now < @unlocked_until
    end

    def clear_memory_locked!
      @unlocked_vmk.clear if @unlocked_vmk.respond_to?(:clear)
      @unlocked_vmk = nil
      @unlocked_private_key = nil
      @unlocked_until = nil
    end
  end
end
