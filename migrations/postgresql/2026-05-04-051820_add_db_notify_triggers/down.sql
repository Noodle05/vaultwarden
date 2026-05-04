DROP TRIGGER IF EXISTS ciphers_notify ON ciphers;
DROP TRIGGER IF EXISTS attachments_notify ON attachments;
DROP TRIGGER IF EXISTS ciphers_collections_notify ON ciphers_collections;
DROP TRIGGER IF EXISTS folders_ciphers_notify ON folders_ciphers;
DROP TRIGGER IF EXISTS folders_notify ON folders;
DROP TRIGGER IF EXISTS sends_notify ON sends;
DROP TRIGGER IF EXISTS archives_notify ON archives;
DROP TRIGGER IF EXISTS users_notify ON users;
DROP TRIGGER IF EXISTS auth_requests_notify ON auth_requests;
DROP TRIGGER IF EXISTS users_organizations_notify ON users_organizations;

DROP FUNCTION IF EXISTS notify_table_change;
