-- Trigger function that fires pg_notify on table changes.
-- Used by a sidecar to detect cross-pod database mutations for
-- HA WebSocket notification replay. See docs/ha-notification-design.md.
--
-- Uses to_jsonb(NEW/OLD)->>'column' instead of direct NEW.column / OLD.column
-- to avoid PL/pgSQL compile-time column resolution. Since this function
-- handles 10 different tables with different schemas, static column
-- references would fail on tables missing those columns.
--
-- Performance: pg_notify() is async (writes to a lock-free queue, returns
-- immediately). to_jsonb() + jsonb_build_object() add CPU overhead per row,
-- but payloads stay well under the 8000-byte NOTIFY limit since only key
-- columns are included (large columns like ciphers.data are never accessed).
-- No additional queries are performed inside the trigger — all work is done
-- on the NEW/OLD row already in memory.
CREATE OR REPLACE FUNCTION notify_table_change()
RETURNS TRIGGER AS $$
DECLARE
    row_id TEXT;
    changed_cols JSONB := '[]'::jsonb;
BEGIN
    -- Composite-key and child tables use the parent cipher_uuid as identifier
    IF TG_TABLE_NAME IN ('folders_ciphers', 'ciphers_collections', 'attachments', 'archives') THEN
        row_id := COALESCE(to_jsonb(NEW)->>'cipher_uuid', to_jsonb(OLD)->>'cipher_uuid');
    ELSE
        row_id := COALESCE(to_jsonb(NEW)->>'uuid', to_jsonb(OLD)->>'uuid');
    END IF;

    -- For users table, track which security/notification-relevant columns changed
    IF TG_TABLE_NAME = 'users' AND TG_OP = 'UPDATE' THEN
        WITH cols AS (
            SELECT 'password_hash' AS col WHERE to_jsonb(NEW)->>'password_hash' IS DISTINCT FROM to_jsonb(OLD)->>'password_hash'
            UNION ALL SELECT 'security_stamp' WHERE to_jsonb(NEW)->>'security_stamp' IS DISTINCT FROM to_jsonb(OLD)->>'security_stamp'
            UNION ALL SELECT 'client_kdf_type' WHERE to_jsonb(NEW)->>'client_kdf_type' IS DISTINCT FROM to_jsonb(OLD)->>'client_kdf_type'
            UNION ALL SELECT 'client_kdf_iter' WHERE to_jsonb(NEW)->>'client_kdf_iter' IS DISTINCT FROM to_jsonb(OLD)->>'client_kdf_iter'
            UNION ALL SELECT 'client_kdf_memory' WHERE to_jsonb(NEW)->>'client_kdf_memory' IS DISTINCT FROM to_jsonb(OLD)->>'client_kdf_memory'
            UNION ALL SELECT 'client_kdf_parallelism' WHERE to_jsonb(NEW)->>'client_kdf_parallelism' IS DISTINCT FROM to_jsonb(OLD)->>'client_kdf_parallelism'
            UNION ALL SELECT 'email' WHERE to_jsonb(NEW)->>'email' IS DISTINCT FROM to_jsonb(OLD)->>'email'
            UNION ALL SELECT 'api_key' WHERE to_jsonb(NEW)->>'api_key' IS DISTINCT FROM to_jsonb(OLD)->>'api_key'
            UNION ALL SELECT 'enabled' WHERE to_jsonb(NEW)->>'enabled' IS DISTINCT FROM to_jsonb(OLD)->>'enabled'
            UNION ALL SELECT 'equivalent_domains' WHERE to_jsonb(NEW)->>'equivalent_domains' IS DISTINCT FROM to_jsonb(OLD)->>'equivalent_domains'
        )
        SELECT jsonb_agg(col) INTO changed_cols FROM cols;
    END IF;

    PERFORM pg_notify('vw_events', jsonb_build_object(
        'table', TG_TABLE_NAME,
        'id', row_id,
        'operation', LOWER(TG_OP),
        'changed_columns', COALESCE(changed_cols, '[]'::jsonb),
        'old', CASE
            -- DELETE: handler needs old row to reconstruct affected users (row is gone)
            WHEN TG_OP = 'DELETE' THEN
                CASE TG_TABLE_NAME
                    WHEN 'ciphers' THEN jsonb_build_object(
                        'user_uuid', to_jsonb(OLD)->>'user_uuid',
                        'organization_uuid', to_jsonb(OLD)->>'organization_uuid'
                    )
                    WHEN 'folders' THEN jsonb_build_object(
                        'user_uuid', to_jsonb(OLD)->>'user_uuid'
                    )
                    WHEN 'sends' THEN jsonb_build_object(
                        'user_uuid', to_jsonb(OLD)->>'user_uuid',
                        'organization_uuid', to_jsonb(OLD)->>'organization_uuid'
                    )
                    WHEN 'users_organizations' THEN jsonb_build_object(
                        'user_uuid', to_jsonb(OLD)->>'user_uuid',
                        'org_uuid', to_jsonb(OLD)->>'org_uuid',
                        'status', to_jsonb(OLD)->>'status'
                    )
                    WHEN 'auth_requests' THEN jsonb_build_object(
                        'user_uuid', to_jsonb(OLD)->>'user_uuid'
                    )
                    ELSE '{}'::jsonb
                END
            -- UPDATE: only include old values for tables that need before/after comparison
            WHEN TG_OP = 'UPDATE' THEN
                CASE TG_TABLE_NAME
                    WHEN 'users_organizations' THEN jsonb_build_object(
                        'status', to_jsonb(OLD)->>'status',
                        'user_uuid', to_jsonb(OLD)->>'user_uuid'
                    )
                    WHEN 'folders' THEN jsonb_build_object(
                        'user_uuid', to_jsonb(OLD)->>'user_uuid'
                    )
                    ELSE '{}'::jsonb
                END
            ELSE '{}'::jsonb
        END,
        'new', CASE
            WHEN TG_OP IN ('INSERT', 'UPDATE') AND TG_TABLE_NAME = 'users_organizations' THEN
                jsonb_build_object('status', to_jsonb(NEW)->>'status')
            WHEN TG_OP IN ('INSERT', 'UPDATE') AND TG_TABLE_NAME = 'folders' THEN
                jsonb_build_object('user_uuid', to_jsonb(NEW)->>'user_uuid')
            ELSE '{}'::jsonb
        END
    )::text);

    RETURN COALESCE(NEW, OLD);
END;
$$ LANGUAGE plpgsql;

-- Core data tables
CREATE TRIGGER ciphers_notify
    AFTER INSERT OR UPDATE OR DELETE ON ciphers
    FOR EACH ROW EXECUTE FUNCTION notify_table_change();

CREATE TRIGGER attachments_notify
    AFTER INSERT OR UPDATE OR DELETE ON attachments
    FOR EACH ROW EXECUTE FUNCTION notify_table_change();

CREATE TRIGGER ciphers_collections_notify
    AFTER INSERT OR UPDATE OR DELETE ON ciphers_collections
    FOR EACH ROW EXECUTE FUNCTION notify_table_change();

CREATE TRIGGER folders_ciphers_notify
    AFTER INSERT OR UPDATE OR DELETE ON folders_ciphers
    FOR EACH ROW EXECUTE FUNCTION notify_table_change();

CREATE TRIGGER folders_notify
    AFTER INSERT OR UPDATE OR DELETE ON folders
    FOR EACH ROW EXECUTE FUNCTION notify_table_change();

CREATE TRIGGER sends_notify
    AFTER INSERT OR UPDATE OR DELETE ON sends
    FOR EACH ROW EXECUTE FUNCTION notify_table_change();

CREATE TRIGGER archives_notify
    AFTER INSERT OR UPDATE OR DELETE ON archives
    FOR EACH ROW EXECUTE FUNCTION notify_table_change();

-- User/security tables
CREATE TRIGGER users_notify
    AFTER UPDATE ON users
    FOR EACH ROW EXECUTE FUNCTION notify_table_change();

CREATE TRIGGER auth_requests_notify
    AFTER INSERT OR UPDATE ON auth_requests
    FOR EACH ROW EXECUTE FUNCTION notify_table_change();

-- Organization membership
CREATE TRIGGER users_organizations_notify
    AFTER INSERT OR UPDATE OR DELETE ON users_organizations
    FOR EACH ROW EXECUTE FUNCTION notify_table_change();
