# Pull request

## Summary

<!-- What changes, and why. Link the issue or ticket. -->

## Security checklist

- [ ] No secrets or real credentials in the diff (placeholders only, `.env.example` unchanged in kind)
- [ ] Every new input is validated by a DTO whitelist (no `forbidNonWhitelisted` bypass, no raw body pass-through)
- [ ] Authorization is enforced server-side, including the ownership check for the addressed resource (no IDOR)
- [ ] The new endpoint has a rate limit
- [ ] Admin and payment actions write an audit-log entry
- [ ] No PII, OTP or tokens in logs (and none added to error messages returned to clients)
- [ ] Database migration reviewed: it does not widen `kfa_app` privileges
- [ ] Tests added (unit and/or e2e) covering the new behaviour and its denial paths

## Notes for reviewers

<!-- Anything unverifiable locally, follow-up work, or intentional trade-offs. -->
