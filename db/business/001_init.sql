-- P1.17: execute ONLY against a dedicated, application-owned database as the migration role.
CREATE SCHEMA IF NOT EXISTS business;
CREATE TABLE IF NOT EXISTS business.schema_migrations (
 version integer PRIMARY KEY, checksum text NOT NULL CHECK(length(checksum)=64), applied_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS business.brands (
 brand varchar(32) PRIMARY KEY CHECK (brand IN ('aurora','brisa')),
 issuer varchar(1024) NOT NULL UNIQUE CHECK (issuer ~ '^https?://[^ ]+$'),
 created_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS business.service_requests (
 id uuid NOT NULL,
 brand varchar(32) NOT NULL REFERENCES business.brands(brand),
 PRIMARY KEY (brand,id),
 owner_actor char(64) NOT NULL CHECK(owner_actor ~ '^[0-9a-f]{64}$'),
 owner_issuer varchar(1024),
 owner_subject varchar(1024),
 title varchar(120) NOT NULL CHECK(length(btrim(title)) >= 3),
 description varchar(1000) NOT NULL,
 status varchar(16) NOT NULL DEFAULT 'OPEN' CHECK(status IN ('OPEN','APPROVED')),
 created_at timestamptz NOT NULL,
 approved_at timestamptz,
 approved_by char(64) CHECK(approved_by IS NULL OR approved_by ~ '^[0-9a-f]{64}$'),
 CHECK ((owner_issuer IS NULL) = (owner_subject IS NULL)),
 CHECK (status = 'OPEN' AND approved_at IS NULL AND approved_by IS NULL
     OR status = 'APPROVED' AND approved_at IS NOT NULL AND approved_by IS NOT NULL)
);
CREATE INDEX IF NOT EXISTS ix_request_owner ON business.service_requests(brand,owner_actor,created_at,id);
CREATE INDEX IF NOT EXISTS ix_request_review ON business.service_requests(brand,created_at,id);
CREATE TABLE IF NOT EXISTS business.case_events (
 brand varchar(32) NOT NULL,
 case_id uuid NOT NULL,
 sequence integer NOT NULL CHECK (sequence BETWEEN 1 AND 2),
 action varchar(16) NOT NULL CHECK (action IN ('created','approved')),
 actor char(64) NOT NULL CHECK(actor ~ '^[0-9a-f]{64}$'),
 actor_issuer varchar(1024),
 actor_subject varchar(1024),
 happened_at timestamptz NOT NULL,
 source varchar(16) NOT NULL CHECK (source IN ('jsonl','application')),
 ledger_position integer CHECK (ledger_position > 0),
 UNIQUE (brand,ledger_position),
 PRIMARY KEY (brand, case_id, sequence),
 FOREIGN KEY (brand,case_id) REFERENCES business.service_requests(brand,id) ON DELETE RESTRICT,
 CHECK ((sequence=1 AND action='created') OR (sequence=2 AND action='approved')),
 CHECK ((actor_issuer IS NULL) = (actor_subject IS NULL))
);
-- A seller decision is a single, independently constrained business fact per request.
-- Historical decisions contain only their irreversible actor fingerprint.
CREATE TABLE IF NOT EXISTS business.seller_decisions (
 brand varchar(32) NOT NULL,
 case_id uuid NOT NULL,
 decision varchar(16) NOT NULL DEFAULT 'APPROVED' CHECK (decision='APPROVED'),
 seller_actor char(64) NOT NULL CHECK(seller_actor ~ '^[0-9a-f]{64}$'),
 seller_issuer varchar(1024),
 seller_subject varchar(1024),
 assurance_auth_time timestamptz,
 decided_at timestamptz NOT NULL,
 PRIMARY KEY (brand,case_id),
 FOREIGN KEY (brand,case_id) REFERENCES business.service_requests(brand,id) ON DELETE RESTRICT,
 CHECK ((seller_issuer IS NULL) = (seller_subject IS NULL))
);
CREATE TABLE IF NOT EXISTS business.operation_idempotency (
 brand varchar(32) NOT NULL REFERENCES business.brands(brand),
 actor char(64) NOT NULL CHECK(actor ~ '^[0-9a-f]{64}$'),
 operation varchar(24) NOT NULL CHECK(operation IN ('create','approve')),
 key_hash char(64) NOT NULL CHECK(key_hash ~ '^[0-9a-f]{64}$'),
 request_hash char(64) NOT NULL CHECK(request_hash ~ '^[0-9a-f]{64}$'),
 result jsonb,
 created_at timestamptz NOT NULL DEFAULT now(),
 PRIMARY KEY (brand,actor,operation,key_hash)
);
CREATE TABLE IF NOT EXISTS business.jsonl_imports (
 brand varchar(32) PRIMARY KEY REFERENCES business.brands(brand),
 file_sha256 char(64) NOT NULL CHECK(file_sha256 ~ '^[0-9a-f]{64}$'),
 case_count integer NOT NULL CHECK(case_count >= 0),
 event_count integer NOT NULL CHECK(event_count >= 0),
 imported_at timestamptz NOT NULL DEFAULT now()
);
CREATE FUNCTION business.check_request_transition() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF OLD.brand <> NEW.brand OR OLD.id <> NEW.id OR OLD.owner_actor <> NEW.owner_actor OR
    OLD.title <> NEW.title OR OLD.description <> NEW.description OR OLD.created_at <> NEW.created_at OR
    OLD.owner_issuer IS DISTINCT FROM NEW.owner_issuer OR OLD.owner_subject IS DISTINCT FROM NEW.owner_subject THEN
   RAISE EXCEPTION 'request immutable fields changed';
 END IF;
 IF OLD.status <> 'OPEN' OR NEW.status <> 'APPROVED' OR NEW.approved_at IS NULL OR NEW.approved_by IS NULL THEN
   RAISE EXCEPTION 'invalid request status transition';
 END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER trg_request_transition BEFORE UPDATE ON business.service_requests
 FOR EACH ROW EXECUTE FUNCTION business.check_request_transition();
-- Migration principal owns objects. The runtime principal must be separately created
-- by the operator and granted only the minimal DML in the runbook.
