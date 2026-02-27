# Ghosted - Email Unsubscribe Tool

**Date:** 2026-02-27
**Status:** Approved

## Overview

Ghosted is a web app that scans your Gmail for subscriptions, lets you review them, and mass-unsubscribes with one click. It also archives old emails from unsubscribed senders. Built for personal use first, designed to grow into a multi-user product.

**Tagline:** Ghost your subscriptions.

## Architecture

- **Frontend:** React + Vite (deployed to Netlify)
- **Backend:** Express.js + Node.js (deployed to Railway)
- **Database:** PostgreSQL (Railway)
- **Auth:** Google OAuth 2.0 (also grants Gmail API access)
- **Email API:** Gmail API

```
Frontend (React/Vite)  -->  Backend (Express)  -->  Gmail API (Google)
     Netlify                  Railway
                               |
                          PostgreSQL
```

### Why Vite instead of CDN?

This project will have multiple pages, components, and API calls. Vite provides fast development with hot reload, proper ES module imports, and better tooling than loading React from a CDN.

## User Flow

1. **Land** - Welcome page explaining what Ghosted does
2. **Sign in** - "Sign in with Google" via OAuth (authenticates + grants Gmail permission)
3. **Scan** - Backend scans last 6 months of email, finds `List-Unsubscribe` headers, groups by sender. Progress bar shown.
4. **Review** - Checklist of subscriptions showing sender name, email count, last received date. Sorted by volume (most emails first). Select All / Deselect All toggle.
5. **Ghost** - Unsubscribes from selected senders + archives old emails. Shows summary when done.

### UI Details

- Ghost button includes a ghost icon for branding
- Each subscription row shows: sender name, email count (last 6 months), last received date
- Subscriptions sorted by email volume (most annoying first)
- "Select All" / "Deselect All" toggle for bulk actions
- Senders without `List-Unsubscribe` headers flagged separately as "no unsubscribe option found"

## How Unsubscribing Works

### Finding Subscriptions

Bulk email senders are required by CAN-SPAM law to include a `List-Unsubscribe` header in their emails. Ghosted uses the Gmail API to scan email headers (not body content) from the last 6 months and groups them by sender.

### Unsubscribe Methods (tried in order)

| Priority | Method | How it works |
|----------|--------|-------------|
| 1 | One-click POST (`List-Unsubscribe-Post` header, RFC 8058) | HTTP POST request - modern, most reliable |
| 2 | URL-based (`https://...` in `List-Unsubscribe`) | HTTP GET/POST to the unsubscribe URL |
| 3 | Email-based (`mailto:...` in `List-Unsubscribe`) | Sends email to the unsubscribe address |

### Archiving

After unsubscribing, Ghosted uses the Gmail API to archive (not delete) all emails from that sender. Emails are removed from the inbox but remain searchable.

### Limitations

Some senders (often the sketchiest spammers) don't include `List-Unsubscribe` headers. Ghosted flags these separately so the user knows to mark them as spam manually in Gmail.

## Data Storage

### PostgreSQL Tables

| Table | Columns | Purpose |
|-------|---------|---------|
| **users** | Google ID, email, display name, encrypted refresh token | User accounts, re-access Gmail without re-auth |
| **scans** | User ID, scan date, status | Track scan history, avoid unnecessary re-scans |
| **subscriptions** | Sender name, sender email, email count, unsubscribe method, status (active/ghosted/no-unsub) | Persist subscription list between sessions |

### What is NOT stored

- Email content (only headers are read, never stored)
- Gmail passwords (OAuth means Ghosted never sees passwords)
- Non-subscription contacts

### Privacy Principle

Ghosted stores the minimum needed to function. It reads email headers to find subscriptions but does not store or log email content.

## Security

### Google OAuth Scopes

- `gmail.readonly` - Read email headers to find subscriptions
- `gmail.modify` - Archive emails
- `gmail.send` - Send mailto-based unsubscribe requests

No access to: delete emails, change settings, or access contacts.

### Token Security

- Refresh tokens encrypted at rest (AES-256)
- Access tokens are short-lived (1 hour), generated fresh from refresh tokens, never stored
- All communication over HTTPS

### Google Verification

- **Testing mode** (personal use): No verification needed, manually add test user accounts
- **Public release**: Must submit for Google's app verification review

### Rate Limits

- Gmail API quota: ~250 units/second per user
- Ghosted batches API requests and shows progress bar to stay within limits

## Hosting

| Component | Platform | Notes |
|-----------|----------|-------|
| Frontend | Netlify | Free tier, same as Stash |
| Backend | Railway | Free/hobby tier, same as Stash |
| Database | Railway PostgreSQL | Can share instance or create dedicated |

## Future Growth Path

1. **Phase 1 (now):** Personal tool - works for your Gmail account in testing mode
2. **Phase 2:** Multi-user - submit for Google verification, open to public signups
3. **Phase 3:** Additional features - scheduled re-scans, email sender reputation, subscription categories
