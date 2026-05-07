# Agent Guide: `tests/`

This file describes the test suite for LLMs working on the VPN Panel project.

## Test Files

| File | Coverage |
|------|---------|
| `test_telegram_bot.py` | Telegram bot behavior: invite flow, access policy, billing, menus, localization, command docs DSL |
| `test_routing_overrides.py` | Routing API: CRUD for per-destination rules, toggle, preview, export |
| `test_quickstart.sh` | Shell regression coverage for `deploy/quickstart.sh`: remote bootstrap detection, Xray install failure handling, and config-path validation |

## How to Run

```bash
# Full suite (from repo root, with .venv active):
python -m unittest discover tests
bash tests/test_quickstart.sh

# Individual suites:
python -m unittest tests.test_telegram_bot
python -m unittest tests.test_routing_overrides
bash tests/test_quickstart.sh
```

All tests must pass before any commit to the main branch. No external services or databases are required — tests use in-memory state and mock the Telegram HTTP calls.

## What `test_telegram_bot.py` Covers

- **Invite flow**: invite creation, claim matching (by user ID, username hint, phone hint), auto-approve vs. pending claim, idempotent re-activation, lead vs. accepted invite distinction.
- **Access policy**: unknown users are silently ignored; admin vs. user command visibility; private vs. group chat restrictions.
- **Billing**: `/pay` package selection (1/3/6/12 months), discount stacking (personal + package, capped at 100%), zero-amount activation without invoice, payment record field validation.
- **Menus and command docs**: default/fallback DSL parsing, root keyboard rendering for user and admin roles, inline submenu callbacks (`menu:open:*`, `menu:tap:*`), helper card rendering.
- **Localization**: `ru`/`en` language detection, `/language` command, bilingual onboarding prompt.
- **Subscription maintenance**: grant, trial, Stars payment, revoke all update expiry correctly; bound peer is enabled/disabled in sync.
- **Support tickets**: `/support` compose mode, one open ticket per user, admin commands (`/tickets`, `/ticket`, `/replyticket`, `/archiveticket`).

## What `test_routing_overrides.py` Covers

- CRUD operations on routing rules (add, update, delete).
- Toggle rule active/inactive.
- Routing check for a given domain.
- Preview and export of the merged routing fragment.
- Validation error handling.

## Patterns for New Tests

- Use `unittest.TestCase` with in-memory store setup in `setUp`.
- Mock Telegram API calls with `unittest.mock.patch`; do not make real HTTP requests.
- Test both `ru` and `en` paths for any user-facing text change.
- For billing changes: always cover package discount (1/3/6/12), stacking, zero-amount, and payment record fields.
- For menu/docs changes: cover default parsing, persisted config loading, user/admin keyboard visibility, and all callback prefixes used.
- Tests that require a skipped external dependency must use `@unittest.skip` with a clear reason string.
