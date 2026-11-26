# frozen_string_literal: true

require "sqlite3"
require "time"

module Rubicairn
  # Thread-safe SQLite3 persistence layer using parameterized queries only.
  class DB
    SCHEMA_SQL = <<~SQL
      CREATE TABLE IF NOT EXISTS notes (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        content_raw TEXT NOT NULL,
        created_at TEXT NOT NULL,
        deleted_at TEXT
      );

      CREATE TABLE IF NOT EXISTS received_likes (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        note_id INTEGER NOT NULL,
        actor_uri TEXT NOT NULL,
        activity_id TEXT,
        created_at TEXT NOT NULL,
        UNIQUE(note_id, actor_uri)
      );

      CREATE TABLE IF NOT EXISTS followers (
        actor_uri TEXT PRIMARY KEY,
        inbox_uri TEXT NOT NULL,
        status TEXT NOT NULL DEFAULT 'pending',
        created_at TEXT NOT NULL
      );

      CREATE TABLE IF NOT EXISTS followings (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        actor_uri TEXT UNIQUE NOT NULL,
        inbox_uri TEXT NOT NULL,
        handle TEXT NOT NULL,
        rss_url TEXT NOT NULL,
        follow_activity_id TEXT NOT NULL,
        created_at TEXT NOT NULL
      );

      CREATE TABLE IF NOT EXISTS likes (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        target_object_uri TEXT UNIQUE NOT NULL,
        target_inbox_uri TEXT NOT NULL,
        activity_id TEXT NOT NULL,
        created_at TEXT NOT NULL
      );

      CREATE TABLE IF NOT EXISTS boosts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        target_object_uri TEXT UNIQUE NOT NULL,
        target_actor_uri TEXT NOT NULL,
        target_inbox_uri TEXT NOT NULL,
        activity_id TEXT NOT NULL,
        target_url TEXT,
        target_author_name TEXT,
        target_author_handle TEXT,
        target_content_text TEXT,
        created_at TEXT NOT NULL
      );

      CREATE TABLE IF NOT EXISTS failed_deliveries (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        target_inbox TEXT NOT NULL,
        payload_json TEXT NOT NULL,
        attempts INTEGER NOT NULL DEFAULT 1,
        last_error TEXT,
        created_at TEXT NOT NULL
      );

      CREATE TABLE IF NOT EXISTS profile_settings (
        key TEXT PRIMARY KEY,
        value TEXT NOT NULL
      );

      CREATE TABLE IF NOT EXISTS profile_links (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        label TEXT NOT NULL,
        url TEXT NOT NULL,
        sort_order INTEGER NOT NULL DEFAULT 0
      );

      CREATE TABLE IF NOT EXISTS webauthn_credentials (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        external_id TEXT UNIQUE NOT NULL,
        public_key TEXT NOT NULL,
        sign_count INTEGER NOT NULL DEFAULT 0,
        nickname TEXT NOT NULL,
        wrap_mode TEXT NOT NULL DEFAULT 'prf',
        prf_salt TEXT NOT NULL,
        wrapped_vmk TEXT NOT NULL,
        created_at TEXT NOT NULL,
        last_used_at TEXT
      );

      CREATE TABLE IF NOT EXISTS vault_recovery (
        id INTEGER PRIMARY KEY CHECK (id = 1),
        wrapped_vmk TEXT NOT NULL,
        created_at TEXT NOT NULL
      );
    SQL

    def initialize(db_path = "data/core.db")
      @mutex = Mutex.new
      @db = SQLite3::Database.new(db_path)
      @db.results_as_hash = true
      @db.busy_timeout = 5000
      @db.execute("PRAGMA journal_mode = WAL;")
      @db.execute("PRAGMA foreign_keys = ON;")
      init_schema!
    end

    def init_schema!
      @mutex.synchronize do
        @db.execute_batch(SCHEMA_SQL)
        migrate_boosts_metadata_columns!
      end
    end

    def migrate_boosts_metadata_columns!
      cols = @db.execute("PRAGMA table_info(boosts)").map { |r| r["name"] }
      %w[target_url target_author_name target_author_handle target_content_text].each do |col|
        @db.execute("ALTER TABLE boosts ADD COLUMN #{col} TEXT") unless cols.include?(col)
      end
    end

    def ping
      @mutex.synchronize do
        @db.get_first_value("SELECT 1") == 1
      end
    end

    def close
      @mutex.synchronize do
        @db.close unless @db.closed?
      end
    end

    # --- Notes ---

    def create_note(content_raw, created_at: now_iso)
      @mutex.synchronize do
        @db.execute(
          "INSERT INTO notes (content_raw, created_at) VALUES (?, ?)",
          [content_raw, created_at]
        )
        id = @db.last_insert_row_id
        @db.get_first_row("SELECT * FROM notes WHERE id = ?", [id])
      end
    end

    def find_note(id)
      @mutex.synchronize do
        @db.get_first_row("SELECT * FROM notes WHERE id = ?", [id])
      end
    end

    def list_public_notes(limit: 50)
      @mutex.synchronize do
        @db.execute(
          <<~SQL,
            SELECT n.*,
                   (SELECT COUNT(*) FROM received_likes rl WHERE rl.note_id = n.id) AS like_count
            FROM notes n
            WHERE n.deleted_at IS NULL
            ORDER BY n.id DESC
            LIMIT ?
          SQL
          [limit]
        )
      end
    end

    def list_all_notes(limit: 100)
      @mutex.synchronize do
        @db.execute(
          "SELECT * FROM notes ORDER BY id DESC LIMIT ?",
          [limit]
        )
      end
    end

    def soft_delete_note(id, deleted_at: now_iso)
      @mutex.synchronize do
        @db.execute(
          "UPDATE notes SET deleted_at = ? WHERE id = ? AND deleted_at IS NULL",
          [deleted_at, id]
        )
        @db.changes > 0
      end
    end

    # --- Received Likes ---

    def add_received_like(note_id:, actor_uri:, activity_id: nil, created_at: now_iso)
      @mutex.synchronize do
        @db.execute(
          "INSERT OR IGNORE INTO received_likes (note_id, actor_uri, activity_id, created_at) VALUES (?, ?, ?, ?)",
          [note_id, actor_uri, activity_id, created_at]
        )
      end
    end

    def remove_received_like(actor_uri:, note_id: nil, activity_id: nil)
      @mutex.synchronize do
        if note_id
          @db.execute(
            "DELETE FROM received_likes WHERE actor_uri = ? AND note_id = ?",
            [actor_uri, note_id]
          )
        elsif activity_id
          @db.execute(
            "DELETE FROM received_likes WHERE actor_uri = ? AND activity_id = ?",
            [actor_uri, activity_id]
          )
        end
      end
    end

    def count_received_likes(note_id)
      @mutex.synchronize do
        @db.get_first_value("SELECT COUNT(*) FROM received_likes WHERE note_id = ?", [note_id]).to_i
      end
    end

    def received_likes_by_note_ids(note_ids)
      return {} if note_ids.empty?

      placeholders = Array.new(note_ids.size, "?").join(", ")
      rows = @mutex.synchronize do
        @db.execute(
          "SELECT * FROM received_likes WHERE note_id IN (#{placeholders}) ORDER BY id DESC",
          note_ids
        )
      end
      rows.group_by { |r| r["note_id"] }
    end

    # --- Followers ---

    def upsert_follower(actor_uri:, inbox_uri:, status:, created_at: now_iso)
      @mutex.synchronize do
        @db.execute(
          <<~SQL,
            INSERT INTO followers (actor_uri, inbox_uri, status, created_at)
            VALUES (?, ?, ?, ?)
            ON CONFLICT(actor_uri) DO UPDATE SET
              inbox_uri = excluded.inbox_uri,
              status = excluded.status
          SQL
          [actor_uri, inbox_uri, status, created_at]
        )
      end
    end

    def find_follower(actor_uri)
      @mutex.synchronize do
        @db.get_first_row("SELECT * FROM followers WHERE actor_uri = ?", [actor_uri])
      end
    end

    def count_followers
      @mutex.synchronize do
        @db.get_first_value("SELECT COUNT(*) FROM followers").to_i
      end
    end

    def list_followers(status: nil)
      @mutex.synchronize do
        if status
          @db.execute(
            "SELECT * FROM followers WHERE status = ? ORDER BY created_at DESC",
            [status]
          )
        else
          @db.execute("SELECT * FROM followers ORDER BY created_at DESC")
        end
      end
    end

    def accept_follower(actor_uri)
      @mutex.synchronize do
        @db.execute(
          "UPDATE followers SET status = 'accepted' WHERE actor_uri = ?",
          [actor_uri]
        )
        @db.get_first_row("SELECT * FROM followers WHERE actor_uri = ?", [actor_uri])
      end
    end

    def delete_follower(actor_uri)
      @mutex.synchronize do
        @db.execute("DELETE FROM followers WHERE actor_uri = ?", [actor_uri])
      end
    end

    def accepted_follower_inboxes
      @mutex.synchronize do
        @db.execute(
          "SELECT DISTINCT inbox_uri FROM followers WHERE status = 'accepted'"
        ).map { |r| r["inbox_uri"] }
      end
    end

    # --- Followings ---

    def create_following(actor_uri:, inbox_uri:, handle:, rss_url:, follow_activity_id:, created_at: now_iso)
      @mutex.synchronize do
        @db.execute(
          <<~SQL,
            INSERT INTO followings (actor_uri, inbox_uri, handle, rss_url, follow_activity_id, created_at)
            VALUES (?, ?, ?, ?, ?, ?)
          SQL
          [actor_uri, inbox_uri, handle, rss_url, follow_activity_id, created_at]
        )
        @db.last_insert_row_id
      end
    end

    def find_following(id)
      @mutex.synchronize do
        @db.get_first_row("SELECT * FROM followings WHERE id = ?", [id])
      end
    end

    def following_actor?(actor_uri)
      @mutex.synchronize do
        !@db.get_first_value("SELECT 1 FROM followings WHERE actor_uri = ?", [actor_uri]).nil?
      end
    end

    def list_followings
      @mutex.synchronize do
        @db.execute("SELECT * FROM followings ORDER BY id DESC")
      end
    end

    def delete_following(id)
      @mutex.synchronize do
        @db.execute("DELETE FROM followings WHERE id = ?", [id])
      end
    end

    # --- Likes (outbound) ---

    def create_like(target_object_uri:, target_inbox_uri:, activity_id:, created_at: now_iso)
      @mutex.synchronize do
        @db.execute(
          <<~SQL,
            INSERT INTO likes (target_object_uri, target_inbox_uri, activity_id, created_at)
            VALUES (?, ?, ?, ?)
          SQL
          [target_object_uri, target_inbox_uri, activity_id, created_at]
        )
        @db.last_insert_row_id
      end
    end

    def find_like(id)
      @mutex.synchronize do
        @db.get_first_row("SELECT * FROM likes WHERE id = ?", [id])
      end
    end

    def list_likes
      @mutex.synchronize do
        @db.execute("SELECT * FROM likes ORDER BY id DESC")
      end
    end

    def delete_like(id)
      @mutex.synchronize do
        @db.execute("DELETE FROM likes WHERE id = ?", [id])
      end
    end

    # --- Boosts (outbound) ---

    def create_boost(target_object_uri:, target_actor_uri:, target_inbox_uri:, activity_id:,
                     target_url: nil, target_author_name: nil, target_author_handle: nil,
                     target_content_text: nil, created_at: now_iso)
      @mutex.synchronize do
        @db.execute(
          <<~SQL,
            INSERT INTO boosts (
              target_object_uri, target_actor_uri, target_inbox_uri, activity_id,
              target_url, target_author_name, target_author_handle, target_content_text, created_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
          SQL
          [
            target_object_uri, target_actor_uri, target_inbox_uri, activity_id,
            target_url, target_author_name, target_author_handle, target_content_text, created_at
          ]
        )
        @db.last_insert_row_id
      end
    end

    def boosted_object?(target_object_uri)
      @mutex.synchronize do
        !@db.get_first_value("SELECT 1 FROM boosts WHERE target_object_uri = ?", [target_object_uri]).nil?
      end
    end

    def find_boost(id)
      @mutex.synchronize do
        @db.get_first_row("SELECT * FROM boosts WHERE id = ?", [id])
      end
    end

    def list_boosts(limit: 50)
      @mutex.synchronize do
        @db.execute("SELECT * FROM boosts ORDER BY created_at DESC, id DESC LIMIT ?", [limit])
      end
    end

    def update_boost_metadata(id, target_url:, target_author_name:, target_author_handle:, target_content_text:)
      @mutex.synchronize do
        @db.execute(
          <<~SQL,
            UPDATE boosts
            SET target_url = ?, target_author_name = ?, target_author_handle = ?, target_content_text = ?
            WHERE id = ?
          SQL
          [target_url, target_author_name, target_author_handle, target_content_text, id]
        )
      end
    end

    def delete_boost(id)
      @mutex.synchronize do
        @db.execute("DELETE FROM boosts WHERE id = ?", [id])
      end
    end

    # --- Failed Deliveries ---

    def record_failed_delivery(target_inbox:, payload_json:, last_error:, created_at: now_iso)
      @mutex.synchronize do
        @db.execute(
          <<~SQL,
            INSERT INTO failed_deliveries (target_inbox, payload_json, attempts, last_error, created_at)
            VALUES (?, ?, 1, ?, ?)
          SQL
          [target_inbox, payload_json, last_error.to_s[0, 500], created_at]
        )
        @db.last_insert_row_id
      end
    end

    def find_failed_delivery(id)
      @mutex.synchronize do
        @db.get_first_row("SELECT * FROM failed_deliveries WHERE id = ?", [id])
      end
    end

    def list_failed_deliveries
      @mutex.synchronize do
        @db.execute("SELECT * FROM failed_deliveries ORDER BY id DESC")
      end
    end

    def increment_failed_delivery(id, last_error)
      @mutex.synchronize do
        @db.execute(
          "UPDATE failed_deliveries SET attempts = attempts + 1, last_error = ? WHERE id = ?",
          [last_error.to_s[0, 500], id]
        )
      end
    end

    def delete_failed_delivery(id)
      @mutex.synchronize do
        @db.execute("DELETE FROM failed_deliveries WHERE id = ?", [id])
      end
    end

    # --- Profile Settings & Links ---

    def get_profile_settings
      @mutex.synchronize do
        rows = @db.execute("SELECT key, value FROM profile_settings")
        rows.each_with_object({}) { |r, h| h[r["key"]] = r["value"] }
      end
    end

    def set_profile_setting(key, value)
      @mutex.synchronize do
        @db.execute(
          <<~SQL,
            INSERT INTO profile_settings (key, value)
            VALUES (?, ?)
            ON CONFLICT(key) DO UPDATE SET value = excluded.value
          SQL
          [key.to_s, value.to_s]
        )
      end
    end

    def list_profile_links
      @mutex.synchronize do
        @db.execute("SELECT * FROM profile_links ORDER BY sort_order ASC, id ASC")
      end
    end

    def add_profile_link(label:, url:, sort_order: 0)
      @mutex.synchronize do
        @db.execute(
          "INSERT INTO profile_links (label, url, sort_order) VALUES (?, ?, ?)",
          [label.to_s, url.to_s, sort_order.to_i]
        )
        @db.last_insert_row_id
      end
    end

    def delete_profile_link(id)
      @mutex.synchronize do
        @db.execute("DELETE FROM profile_links WHERE id = ?", [id])
      end
    end

    def count_public_notes
      @mutex.synchronize do
        @db.get_first_value("SELECT COUNT(*) FROM notes WHERE deleted_at IS NULL").to_i
      end
    end

    def count_followings
      @mutex.synchronize do
        @db.get_first_value("SELECT COUNT(*) FROM followings").to_i
      end
    end

    def count_accepted_followers
      @mutex.synchronize do
        @db.get_first_value("SELECT COUNT(*) FROM followers WHERE status = 'accepted'").to_i
      end
    end

    # --- WebAuthn Credentials & Vault Recovery ---

    def list_webauthn_credentials
      @mutex.synchronize do
        @db.execute("SELECT * FROM webauthn_credentials ORDER BY id ASC")
      end
    end

    def count_webauthn_credentials
      @mutex.synchronize do
        @db.get_first_value("SELECT COUNT(*) FROM webauthn_credentials").to_i
      end
    end

    def find_webauthn_credential_by_external_id(external_id)
      @mutex.synchronize do
        @db.get_first_row("SELECT * FROM webauthn_credentials WHERE external_id = ?", [external_id.to_s])
      end
    end

    def find_webauthn_credential(id)
      @mutex.synchronize do
        @db.get_first_row("SELECT * FROM webauthn_credentials WHERE id = ?", [id.to_i])
      end
    end

    def create_webauthn_credential(external_id:, public_key:, sign_count:, nickname:, wrap_mode:, prf_salt:, wrapped_vmk:, created_at: now_iso)
      @mutex.synchronize do
        @db.execute(
          <<~SQL,
            INSERT INTO webauthn_credentials
              (external_id, public_key, sign_count, nickname, wrap_mode, prf_salt, wrapped_vmk, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
          SQL
          [external_id.to_s, public_key.to_s, sign_count.to_i, nickname.to_s, wrap_mode.to_s, prf_salt.to_s, wrapped_vmk.to_s, created_at]
        )
        @db.last_insert_row_id
      end
    end

    def update_webauthn_credential_usage(id, sign_count:, last_used_at: now_iso)
      @mutex.synchronize do
        @db.execute(
          "UPDATE webauthn_credentials SET sign_count = ?, last_used_at = ? WHERE id = ?",
          [sign_count.to_i, last_used_at, id.to_i]
        )
      end
    end

    def delete_webauthn_credential(id)
      @mutex.synchronize do
        @db.execute("DELETE FROM webauthn_credentials WHERE id = ?", [id.to_i])
      end
    end

    def get_vault_recovery
      @mutex.synchronize do
        @db.get_first_row("SELECT * FROM vault_recovery WHERE id = 1")
      end
    end

    def save_vault_recovery(wrapped_vmk:, created_at: now_iso)
      @mutex.synchronize do
        @db.execute(
          <<~SQL,
            INSERT INTO vault_recovery (id, wrapped_vmk, created_at)
            VALUES (1, ?, ?)
            ON CONFLICT(id) DO UPDATE SET wrapped_vmk = excluded.wrapped_vmk, created_at = excluded.created_at
          SQL
          [wrapped_vmk.to_s, created_at]
        )
      end
    end

    private

    def now_iso
      Time.now.utc.iso8601
    end
  end
end
