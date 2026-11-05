-- Execute as a dedicated Magalu risk DB owner against a SEPARATE database (ciam_risk),
-- not ciam_identity/ciam_shared/ciam_agent or any WSO2-managed schema.
CREATE SCHEMA IF NOT EXISTS magalu_risk;
CREATE TABLE IF NOT EXISTS magalu_risk.events (
  id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  tenant VARCHAR(80) NOT NULL,
  account_key CHAR(32),
  ip_key CHAR(32),
  network_key CHAR(32),
  device_key CHAR(32),
  session_key CHAR(32),
  agent_key CHAR(32),
  event_ms BIGINT NOT NULL,
  outcome VARCHAR(10) NOT NULL CHECK (outcome IN ('ATTEMPT','FAILURE','SUCCESS')),
  automation BOOLEAN NOT NULL DEFAULT FALSE,
  challenge_failed BOOLEAN NOT NULL DEFAULT FALSE
);
CREATE INDEX IF NOT EXISTS risk_tenant_time_idx ON magalu_risk.events(tenant,event_ms DESC);
CREATE INDEX IF NOT EXISTS risk_baseline_idx ON magalu_risk.events(tenant,account_key,event_ms DESC)
  WHERE outcome='SUCCESS';
-- Schedule separately: DELETE FROM magalu_risk.events WHERE event_ms <
-- (extract(epoch from now())*1000)::bigint - 7776000000;  -- maximum 90 days
-- For privacy/operability use regular small batches (e.g. 2000 rows) and retention
-- set by most restrictive approved tenant policy. Do not place arbitrary raw PII here.
