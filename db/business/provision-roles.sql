-- Run manually as dedicated ciam_business database owner AFTER schema migration.
-- Set :runtime_password using a local psql variable, never commit it.
-- psql -v ON_ERROR_STOP=1 -v runtime_password='...' -f db/business/provision-roles.sql
DO $$ BEGIN
 IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname='ciam_business_runtime') THEN
   CREATE ROLE ciam_business_runtime LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION;
 END IF;
END $$;
ALTER ROLE ciam_business_runtime PASSWORD :'runtime_password';
REVOKE ALL ON SCHEMA public FROM PUBLIC;
REVOKE ALL ON SCHEMA business FROM PUBLIC;
GRANT USAGE ON SCHEMA business TO ciam_business_runtime;
GRANT SELECT ON business.schema_migrations,business.brands,business.jsonl_imports TO ciam_business_runtime;
GRANT SELECT,INSERT,UPDATE ON business.service_requests,business.operation_idempotency TO ciam_business_runtime;
GRANT SELECT,INSERT ON business.case_events,business.seller_decisions TO ciam_business_runtime;
REVOKE DELETE,TRUNCATE,REFERENCES,TRIGGER ON ALL TABLES IN SCHEMA business FROM ciam_business_runtime;
-- NB: no WSO2 identity tables exist or are accessible in this database.
