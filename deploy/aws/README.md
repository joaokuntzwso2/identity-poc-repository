# AWS / localhost deployment boundary (generic public example)

The WSO2 image used in AWS must be the **same WSO2 7.3.0 update >=18 build** used in the local environment, pinned by an immutable digest and independently recorded product update provenance. `wso2/wso2is:7.3.0` is GA without WSO2 Updates and is deliberately NOT selected.

Recommended separation:

- Public HTTPS ALB / reverse proxy routes `/aurora.html`, `/brisa.html`, `/aurora-mobile.html`, `/brisa-mobile.html`, `/` to the Experience Center and session-backed identity BFF. Serve the pairwise sector documents on stable public HTTPS URLs accessible from WSO2.
- WSO2 IS inside private subnets/container network with externally consistent issuer and redirects. Do **not** expose 9443 directly or publish admin APIs. Console access restricted to administrators.
- External durable PostgreSQL (RDS/Aurora PostgreSQL), provisioned credentials in Secrets Manager and KMS; BFF session store shared across replicas, HTTPS secure cookies, CSRF protection. No SQLite preview store for multi-replica production.
- TLS at edge plus validated TLS for BFF-to-WSO2, strict `issuer` pinning, no redirect rewriting. WSO2 federation, session, tenant and org configuration must be applied by real APIs and proven.
- IAM roles for tasks, CloudWatch/OTel logs, audit log sink, backups, restore drills, autoscaling/load tests, health checks, WAF, and deployment rollback procedures. Do not infer an SLA from this example.
- **Reset demo endpoint**: operator server stays loopback-only and disabled in AWS. To expose remote reset later, design a separate backend authenticated with operator OIDC, role enforcement, CSRF and step-up, protected by VPN/IP allowlist and privileged command queue. Never publish an unauthenticated reset route via ALB.

Local development with real IS: WSO2 inside Docker, host BFF uses `https://localhost:9443` with CA trust. WSO2 inside Docker may **not** resolve host-side `localhost`; configure domain routing and `host.docker.internal`/network alias for publicly served callback sector documents. Avoid public redirects to 127.0.0.1 for users who aren't on the same machine. Mobile browser previews are not native RFC 8252 clients.

Infrastructure-as-code (VPC, ALB, ECS/EKS, RDS, secrets, security groups) is still a required deployment deliverable; this is a secure topology specification, **not an applied AWS stack**.
