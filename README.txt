MPL MINI PRO LEAGUE — FULL-STACK STARTER

This is a working local application with:
- Public team registration (11–13 total squad members, including 0–2 substitutes)
- SQLite database storage
- Private host login
- Initial Super Administrator username: sujal
- Administrator-only team status updates and host-account creation
- Payment status tracking (Pending / Paid)
- Age review status (Pending / Verified / Needs review)
- CSV export for Excel
- Password hashing, session cookies, rate-limited login, security headers

IMPORTANT
1. It is not published online yet. It runs locally until deployed to a suitable Node.js host.
2. Do NOT use real player data until deployment security, privacy notice, backups, access rules, and age cutoff policy have been reviewed.
3. This application does NOT collect Aadhaar numbers or images and does not perform Aadhaar verification. An appropriate authorized verification process must happen separately. Mark "Verified" only after that check.
4. The helper age calculation uses today's date and is not the tournament's official cutoff rule. Define the tournament cutoff date/rules before accepting real U-19 registrations.
5. UPI QR and automatic payment processing are not connected yet. Payment is manually marked Paid by the administrator.
6. Use HTTPS in production, set NODE_ENV=production, and use a strong random SESSION_SECRET.
7. Use a persistent disk for the SQLite database and session store. Do not deploy to an ephemeral filesystem.
8. Only share the admin password with the owner. Do not send passwords in chat or commit .env to source control.

SETUP ON WINDOWS
1. Install Node.js LTS (20 or newer) from the official Node.js website.
2. Open this folder in File Explorer.
3. Copy .env.example to a new file named .env.
4. Edit .env:
   - Keep ADMIN_USERNAME=sujal
   - Replace ADMIN_PASSWORD with a strong, unique password (at least 16 characters recommended).
   - Replace SESSION_SECRET with a long random secret.
5. Open Command Prompt in this folder (File Explorer address bar: type cmd and press Enter).
6. Run:
   npm install
   npm start
7. Open http://localhost:3000 in your browser.
8. Log in at http://localhost:3000/login using the username and password from .env.

Do not publish the website or share the link as a production tournament site until it is deployed with HTTPS and tested.
