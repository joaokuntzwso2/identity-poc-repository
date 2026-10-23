-- Identity evaluation extension: PostgreSQL 14+ consent audit, isolated by issuer/brand/client.
-- This is an AE extension. NOT proof of WSO2 Consent Management v2 or LGPD compliance.
BEGIN;
CREATE SCHEMA IF NOT EXISTS identity_poc;
CREATE TABLE IF NOT EXISTS identity_poc.consent_state (
  subject_key char(64) NOT NULL,
  issuer text NOT NULL,
  brand text NOT NULL,
  client_key text NOT NULL,
  target_brand text NOT NULL,
  purpose text NOT NULL,
  scope text NOT NULL,
  revision bigint NOT NULL DEFAULT 0 CHECK (revision >= 0),
  decision text NOT NULL DEFAULT 'DENIED' CHECK (decision IN ('GRANTED','REVOKED','DENIED')),
  changed_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY(subject_key,issuer,brand,client_key,target_brand,purpose,scope),
  CHECK (brand <> target_brand)
);
CREATE TABLE IF NOT EXISTS identity_poc.consent_events (
  event_id uuid PRIMARY KEY,
  subject_key char(64) NOT NULL,
  issuer text NOT NULL,
  brand text NOT NULL,
  client_key text NOT NULL,
  target_brand text NOT NULL,
  purpose text NOT NULL,
  scope text NOT NULL,
  revision bigint NOT NULL CHECK (revision > 0),
  decision text NOT NULL CHECK (decision IN ('GRANTED','REVOKED')),
  recorded_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  UNIQUE(subject_key,issuer,brand,client_key,target_brand,purpose,scope,revision),
  FOREIGN KEY(subject_key,issuer,brand,client_key,target_brand,purpose,scope)
    REFERENCES identity_poc.consent_state(subject_key,issuer,brand,client_key,target_brand,purpose,scope)
);
-- DB-enforced append-only history. Admins with DB-owner privileges must still be controlled.
CREATE OR REPLACE FUNCTION identity_poc.prevent_consent_event_mutation()
RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN
 RAISE EXCEPTION 'consent event history is append-only';
END $$;
DROP TRIGGER IF EXISTS consent_events_immutable ON identity_poc.consent_events;
CREATE TRIGGER consent_events_immutable BEFORE UPDATE OR DELETE ON identity_poc.consent_events
FOR EACH ROW EXECUTE FUNCTION identity_poc.prevent_consent_event_mutation();
CREATE INDEX IF NOT EXISTS consent_events_lookup ON identity_poc.consent_events
 (subject_key,issuer,brand,client_key,recorded_at DESC);
COMMIT;
