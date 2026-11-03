# P1.23 — Carbon Super API-resource inventory pagination

## Problem and evidence

The live Carbon Super readback returned HTTP 200 with 100 resource identifiers while
`totalResults` reported **184**. The previous source intentionally classified a
partial first page as `PARTIAL_OR_UNVERIFIED`; strict preflight accordingly emitted
`CARBON_COLLECTION_NOT_FULL_superApiResources`. No missing API authorization was
inferred. Client, profile and Phase 4 business management readbacks had passed.

## Scope of this correction

The Carbon Super GET-only producer now follows strictly validated WSO2 **forward
`after` cursors** for `/api/server/v1/api-resources` only. The API documentation
specifies cursor pagination (`after`, `before`) for this endpoint; its old `offset=0`
initial query is not used as a pagination mechanism. A forwarded link may be a
same-endpoint relative URL, a query-relative URL, or an HTTPS link advertised by
local WSO2 on `localhost`/`127.0.0.1` port 9443/9444. Only the validated cursor
is extracted, and the actual GET goes to the existing pinned local port 9444.
No link-supplied network destination is contacted.

Hard limits: 100 resources/page, 10 pages, 1000 total resources, 200 KB body/page,
12s/page request timeout. Non-200, duplicate resource identifiers, invalid cursors,
repeat cursors, changed totals, invalid schema, >10 pages and unfinished results
are `PARTIAL_OR_UNVERIFIED`. No response bodies, private tokens, raw cursors,
passwords or remote URLs are added to the executive preflight report.

When fully collected, the existing `superApiResources` entry is
`FULL_PAGINATED`, with pageCount/totalResults, bounded pagesFetched,
`paginationMode: WSO2_AFTER_CURSOR` and 184 validated unique identifiers in
private command output. The strict management parser requires all matching counts,
valid metadata and complete unique identifiers before returning PASS. Existing
`FULL_FIRST_PAGE` acceptance for single pages and the other four Carbon
collections are retained.

## Acceptance and non-goals

Python and Node regression suites use stubbed pages; no WSO2 instance is
modified. After a new Git commit, restart only the BFF for release provenance,
then run a `--deep-readback --no-browser` preflight. If the live response links
are a different shape than the validated cursor forms, Carbon Super correctly
remains BLOCKED; do not forge completion by changing the evidence check.

This does not test the browser, MFA, approval persistence, ledger durability or
manual WCAG acceptance. There are no remote mutations, role scope changes or
private journal migrations.
