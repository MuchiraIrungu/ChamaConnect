# ChamaConnect Security Audit & Fix
### ChamaConnect Virtual Hackathon 2026 — Collins Muchira

---

## Overview

This repository contains a security audit of [ChamaConnect](https://chamaconnect.io) — a blockchain-enabled FinTech platform for group savings management (chamas/circles) in Kenya — submitted as part of the ChamaConnect Virtual Hackathon 2026, organised by MUIAA Ltd in partnership with the Salamander Community.

Through systematic manual testing of the production application, **11 confirmed vulnerabilities** were identified, 5 of which are Critical severity. This repository provides:

1. Full documentation of each bug (problem, root cause, steps to reproduce)
2. A working Django REST API demonstrating the corrected authentication architecture
3. A technical proposal PDF with expected impact analysis

---

## Critical Findings Summary

| ID | Severity | Title |
|----|----------|-------|
| BUG-01 | 🔴 Critical | JWT issued without expiry claim — tokens never expire |
| BUG-02 | 🔴 Critical | Token not invalidated server-side on logout |
| BUG-03 | 🔴 Critical | Dashboard accessible after cookie deletion (auth guard bypass) |
| BUG-04 | 🔴 Critical | OTP codes stored in plaintext in browser localStorage |
| BUG-05 | 🔴 Critical | Full user financial state persisted unencrypted in localStorage |
| BUG-06 | 🟠 High | No brute-force protection on login endpoint |
| BUG-07 | 🟠 High | Account deletion OTP has no frontend input UI — flow is broken |
| BUG-08 | 🟠 High | No login notification for new device or session |
| BUG-09 | 🟡 Medium | Transactions endpoint returns HTTP 200 for arbitrary group IDs |
| BUG-10 | 🟡 Medium | Rejected/failed transactions included in financial reports |
| BUG-11 | 🟡 Medium | Chart component renders with invalid dimensions (-1 x -1) |

---

## Bug Details

### BUG-01 — JWT Has No Expiry Claim
**Steps to reproduce:**
1. Log in to chamaconnect.io
2. Open DevTools → Application → Local Storage → `auth-storage`
3. Copy the `state.token` value
4. Decode the JWT payload at [jwt.io](https://jwt.io)
5. Observe: `iat` (issued-at) is present but `exp` (expiry) is absent

**Evidence:**
```json
{
  "id": "69e2110c3e9a7937fd3ca476",
  "isSuperadmin": false,
  "iat": 1777147088
}
```
No `exp` field — the token is permanently valid.

**Root cause:** `jwt.sign()` called without the `expiresIn` option.

**Fix:** Issue short-lived access tokens (15 min) + rotating refresh tokens (7 days). See `authentication/views.py → issue_tokens()`.

---

### BUG-02 — Token Not Invalidated on Logout
**Steps to reproduce:**
1. Log in → copy token from `localStorage["auth-storage"].state.token`
2. Log out via the UI
3. Make any API call with the copied token in the `Authorization: Bearer` header
4. Observe: server returns HTTP 200 with full user data

**Root cause:** No server-side token blacklist. Logout only clears localStorage client-side.

**Fix:** `djangorestframework-simplejwt` token blacklisting — on logout, refresh token is added to `BlacklistedToken` table. Every subsequent validation rejects it. See `authentication/views.py → LogoutView`.

---

### BUG-03 — Dashboard Accessible After Cookie Deletion
**Steps to reproduce:**
1. Log in to chamaconnect.io/admin/dashboard
2. DevTools → Application → Cookies → delete all cookies for the domain
3. Navigate directly to `https://chamaconnect.io/admin/dashboard`
4. Observe: dashboard loads fully — no redirect to login

**Root cause:** Route guard checks a cookie; actual session data comes from localStorage. The two storage mechanisms are out of sync.

**Fix:** Use HttpOnly, Secure, SameSite=Strict cookies as the single source of truth. Validate session server-side in Next.js middleware on every protected route.

---

### BUG-04 — OTP Values in Plaintext in localStorage
**Steps to reproduce:**
1. Request a password reset or account deletion
2. Open DevTools → Application → Local Storage → `auth-storage`
3. Expand `state.user.otpMessages`
4. Observe: plaintext OTP codes visible — no email needed to obtain them

**Evidence:**
```json
"otpMessages": [
  { "token": "810469", "messageType": "OtpPasswordReset" },
  { "token": "409948", "messageType": "OtpPasswordReset" },
  { "token": "996219", "messageType": "OtpPasswordReset" }
]
```

**Root cause:** `/api/auth/me` returns the full user record including OTP history. Zustand `persist()` middleware writes this entire response to localStorage.

**Fix:** OTPs are never returned in any API response. Generated server-side, stored server-side (DB/cache), emailed only. See `authentication/views.py → RequestOTPView` and `send_otp_email()`.

---

### BUG-05 — Full Financial State in localStorage
**Steps to reproduce:**
1. Log in to chamaconnect.io
2. Open DevTools → Application → Local Storage → `auth-storage`
3. Observe the full contents

**Data confirmed in localStorage:**
- Full JWT token
- Phone number, email, full legal name
- Blockchain wallet address
- All OTP codes with values (see BUG-04)
- Complete M-Pesa transaction history with M-Pesa checkout IDs
- Group membership details and role assignments
- Payment records with amounts and methods

**Root cause:** Zustand `persist()` applied to the entire auth slice without a `partialize` option. Every field — including server-fetched sensitive data — is serialised to localStorage on every state update.

**Fix:** Persist only `{ token, userId }`. All other data fetched on demand via dedicated endpoints and kept in memory only.

---

### BUG-06 — No Brute-Force Protection on Login
**Steps to reproduce:**
1. Attempt login with wrong password
2. Repeat 20+ times
3. Observe: every attempt returns HTTP 401 with no lockout, slowdown, or CAPTCHA

**Root cause:** No rate limiting middleware on the authentication endpoints.

**Fix:** `LoginAttempt` model tracks failures per IP + email. After 5 failures in 15 minutes, endpoint returns HTTP 429. See `authentication/models.py → LoginAttempt` and `views.py → LoginView`.

---

### BUG-07 — Account Deletion OTP Has No Frontend Input
**Steps to reproduce:**
1. Go to account settings → request account deletion
2. Receive email: "Your verification code: 996219"
3. Observe: no modal, no input field, no link appears in the app
4. The deletion flow cannot be completed by any user

**Root cause:** Backend deletion flow implemented (email sent), frontend OTP confirmation step never built.

**Fix:** Two-step deletion endpoint — `POST /api/auth/delete/request` sends OTP, `POST /api/auth/delete/confirm` accepts the code and completes deletion. See `authentication/views.py → RequestAccountDeletionView` and `ConfirmAccountDeletionView`.

---

### BUG-08 — No New Device Login Notification
**Steps to reproduce:**
1. Log in from a second browser or device
2. Observe: no email or in-app alert is sent to the account owner

**Fix:** Device fingerprinting on every login. New fingerprint → immediate email alert. See `authentication/models.py → KnownDevice` and `views.py → send_new_device_alert()`.

---

### BUG-09 — Transactions Endpoint Returns 200 for Arbitrary Group IDs
**Steps to reproduce:**
```javascript
fetch('/api/proxy/transactions/groups/69e2179c3e9a7937fd3ca400?offset=0&limit=10', {
  headers: { 'Authorization': 'Bearer YOUR_TOKEN' }
}).then(r => r.json()).then(console.log)
// Returns: { status: 'success', data: [] } — should return 403
```

**Root cause:** No group existence or membership check before executing the transaction query.

**Fix:** Guard every group-scoped endpoint with: (1) verify group exists, (2) verify requesting user is an active member.

---

### BUG-10 — Rejected Transactions in Financial Reports
**Evidence:**
- Transaction: `{ status: "REJECTED", description: "Failed: Request Cancelled by user." }`
- Weekly email report: `Total Contributions: KES 100.00, Net Change: KES 100.00`

**Root cause:** Report query aggregates all transactions without filtering on `status`.

**Fix:** Filter to `status IN ('COMPLETED', 'SUCCESS')` for financial summaries. Show failed transactions in a separate clearly labelled section.

---

### BUG-11 — Chart Rendering Error (width/height -1)
**Evidence (browser console):**
```
The width(-1) and height(-1) of chart should be greater than 0
nQ @ 9cf8216a24f26975.js:1
```

**Root cause:** Recharts `ResponsiveContainer` renders before CSS layout resolves, calculating dimensions as -1.

**Fix:** Set explicit `minHeight` on the container div, or defer chart rendering with `useEffect` until after mount. Add `minWidth={0}` prop to `ResponsiveContainer`.

---

## Solution — Project Setup

### Prerequisites
- Python 3.10+
- pip

### Installation

```bash
# 1. Clone the repository
git clone https://github.com/YOUR_USERNAME/chamaconnect-fix.git
cd chamaconnect-fix

# 2. Create and activate a virtual environment
python -m venv venv
source venv/bin/activate        # Windows: venv\Scripts\activate

# 3. Install dependencies
pip install -r requirements.txt

# 4. Run migrations
python manage.py migrate

# 5. Create a test superuser (optional, for Django admin)
python manage.py createsuperuser

# 6. Start the development server
python manage.py runserver
```

The API will be available at `http://127.0.0.1:8000/`

---

## API Endpoints

| Method | Endpoint | Auth Required | Description |
|--------|----------|---------------|-------------|
| POST | `/api/auth/register/` | No | Create account |
| POST | `/api/auth/login/` | No | Login — returns access + refresh tokens |
| POST | `/api/auth/logout/` | Yes | Blacklists refresh token server-side |
| POST | `/api/auth/token/refresh/` | No | Rotate access token using refresh token |
| GET | `/api/auth/profile/` | Yes | Get current user (safe fields only) |
| PATCH | `/api/auth/profile/` | Yes | Update name/phone |
| POST | `/api/auth/password/change/` | Yes | Change password (authenticated) |
| POST | `/api/auth/password/reset/` | No | Reset password with OTP |
| POST | `/api/auth/otp/request/` | No | Request OTP via email |
| POST | `/api/auth/otp/verify/` | No | Verify OTP code |
| POST | `/api/auth/delete/request/` | Yes | Initiate account deletion — sends OTP |
| POST | `/api/auth/delete/confirm/` | Yes | Confirm deletion with OTP code |

---

## Example API Usage

### Register
```bash
curl -X POST http://127.0.0.1:8000/api/auth/register/ \
  -H "Content-Type: application/json" \
  -d '{
    "email": "test@example.com",
    "first_name": "Jane",
    "last_name": "Doe",
    "phone": "+254700000000",
    "password": "SecurePass123!",
    "password2": "SecurePass123!"
  }'
```

### Login (note the expiry in the returned access token)
```bash
curl -X POST http://127.0.0.1:8000/api/auth/login/ \
  -H "Content-Type: application/json" \
  -d '{"email": "test@example.com", "password": "SecurePass123!"}'
```

### Logout (server-side blacklist)
```bash
curl -X POST http://127.0.0.1:8000/api/auth/logout/ \
  -H "Authorization: Bearer ACCESS_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"refresh": "YOUR_REFRESH_TOKEN"}'
```

### Trigger brute-force lockout
```bash
# Run 6 times — 6th attempt returns HTTP 429
for i in {1..6}; do
  curl -s -o /dev/null -w "%{http_code}\n" \
    -X POST http://127.0.0.1:8000/api/auth/login/ \
    -H "Content-Type: application/json" \
    -d '{"email": "test@example.com", "password": "wrong"}'
done
# Output: 401 401 401 401 401 429
```

### Account deletion (the complete flow ChamaConnect is missing)
```bash
# Step 1 — request deletion (OTP printed to console in dev mode)
curl -X POST http://127.0.0.1:8000/api/auth/delete/request/ \
  -H "Authorization: Bearer ACCESS_TOKEN"

# Step 2 — confirm with OTP from email
curl -X POST http://127.0.0.1:8000/api/auth/delete/confirm/ \
  -H "Authorization: Bearer ACCESS_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"code": "123456"}'
```

---

## Requirements

```
Django==4.2
djangorestframework==3.15
djangorestframework-simplejwt==5.3
django-cors-headers==4.3
```

---

## Project Structure

```
chamaconnect-fix/
├── README.md
├── requirements.txt
├── manage.py
├── screenshots/
│   ├── bug01-no-expiry-jwt.png
│   ├── bug02-token-persists-after-logout.png
│   ├── bug03-dashboard-no-cookie.png
│   ├── bug04-otp-in-localstorage.png
│   └── bug05-full-state-dump.png
├── core/
│   ├── settings.py
│   ├── urls.py
│   └── wsgi.py
└── authentication/
    ├── models.py       — User, LoginAttempt, KnownDevice, OTP
    ├── serializers.py  — input validation + safe output shaping
    ├── views.py        — endpoint logic with inline bug-fix comments
    └── urls.py         — route definitions
```

---

## Submission Details

- **Participant:** Collins Muchira
- **Email:** cmuchirairungu063@gmail.com
- **Hackathon:** ChamaConnect Virtual Hackathon 2026
- **Organiser:** MUIAA Ltd × Salamander Community
- **Deadline:** Sunday April 27, 2026 @ 11:59 PM