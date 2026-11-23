# Security changelog

Short, newest first. Every entry is a control that is in the code; the last
section lists proposals that still need an owner decision.

## 2026-11-22 - stage 1.3/1.4, checkout, price and provider adapters

- The price is a row (`billing_plans`), seeded at 4.20 USD with a one-year
  period, stored as `DECIMAL(18,6)`, never deleted, and read as a decimal string
  so no floating-point number ever describes money.
- `POST /billing/checkout` takes no amount: the payment row is written with the
  stored price and the provider's currency (`USDT`/TRC20 for NOWPayments, `USD`
  for PayPal) before the athlete is redirected. A second checkout while the
  period is already covered is a 409, so nobody pays twice for one period.
- Nothing is sold when a provider is half-configured: the boot check refuses a
  partial key set, and an unconfigured provider answers a generic 503.
- Provider callbacks are verified end to end: NOWPayments by HMAC-SHA512 over the
  key-sorted body, PayPal by its own verification API with a cached OAuth token.
  A timeout or any non-`SUCCESS` answer refuses the delivery.
- The PayPal base URL is restricted to the two real hosts, so a bad configuration
  cannot be turned into a request to an arbitrary address (SSRF).
- `PATCH /billing/price` needs a staff role and a fresh second factor, and writes
  the old and new amount into the append-only audit chain.
- A verified provider event this service does not model is stored as
  `ignored_event` and changes nothing; it is never treated as a payment.
- Identity documents, passwords and card data are never part of a provider
  request: the checkout stores an order reference and the provider's own id.

## 2026-11-22 - stage 1.2b, inbound webhook route

- `POST /billing/webhook/:provider` is public by necessity (the caller is a
  payment provider, not a user) and trusts nothing in the request.
- The exact bytes are kept by the JSON parser (`verify` hook) because a provider
  signature covers the bytes that were sent, not a re-serialized object.
- A body that is not JSON, or is empty, is refused with the generic 400 before
  any signature work; provider names must match a short enum-like shape, and a
  provider with no configured verifier answers 404 without reading the body.
- Per-address limits in their own bucket (120/min, 2000/h) through the existing
  Redis-backed, fail-closed store; a Redis outage answers 503, never "allowed".
- No verifier is wired yet, so no delivery can activate a subscription: the
  route exists in the closed state that stage 1.3 opens deliberately.

## 2026-11-21 - stage 1.2a, webhook core

- Signature-verified, idempotent deliveries: duplicate and concurrent replays
  store one row and change nothing.
- Amount, currency and network are checked against the stored payment row, never
  against the request body; a mismatch fails the payment and is audited.
- Status transitions are guarded (`NONE`/`PENDING` -> `ACTIVE`, `CONFIRMED` ->
  `REFUNDED`/`CHARGEBACK`); an already refunded payment can never be reactivated.
- `payments` terms and `webhook_events` rows are immutable after insert, and the
  runtime role has no `DELETE` on any billing table (migration
  `20261121130000_billing_hardening`).
- The forged-signature test now counts only the delivered event, because the
  runtime role cannot clean up rows from earlier runs. The assertion is narrower
  by scope, not weaker: a forged delivery still stores nothing.

## Proposed (needs owner approval before implementing)

| Priority | Proposal                                                     | Why it matters                                                                                                                |
| -------- | ------------------------------------------------------------ | ----------------------------------------------------------------------------------------------------------------------------- |
| High     | Webhook IP allow-list plus a timestamp window                | A valid signature from a leaked body is still a valid signature; an allow-list and a freshness check cut replay and spoofing. |
| High     | Secret rotation procedure for the provider keys              | The development `.env` was shared in a zip; the keys must be assumed exposed.                                                 |
| Medium   | A tighter per-route body cap for the webhook (e.g. 64 KB)    | Today it uses the global JSON limit; a dedicated parser would bound the signature-check cost.                                 |
| Medium   | Cloudflare/WAF rules and a CSP report endpoint               | Blocks crude floods and surfaces XSS attempts that the nonce already prevents.                                                |
| Medium   | Encrypted backups and a restore drill that is part of deploy | A backup nobody restored is a hope, not a control.                                                                            |
| Low      | SBOM plus pinned dependency review in CI                     | Makes a supply-chain change visible before it ships.                                                                          |
| Low      | Alerting on code-request and document-download spikes        | Both are early signs of enumeration or scraping.                                                                              |
