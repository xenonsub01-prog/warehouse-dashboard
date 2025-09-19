
Warehouse Demo (Owner bypass + Short links)

NEW
---
- Open as OWNER without token using URL param: ?admin=OWNER_KEY
  (run_app.bat opens the app already with your OWNER_KEY)
- Generate SHORT client links using codes: ?c=AbC123XyZ1 (maps to JWT internally)

HOW TO USE
----------
1) Double-click setup.bat
2) Double-click run_app.bat  -> opens as owner automatically.
3) In sidebar Admin:
   - Set Base URL to your public URL (or keep localhost)
   - Enter company and email
   - Choose expiry (hours/days) and role
   - Tick "Use short code link" for short URLs
   - Click "Generate Token & Link"
   - Copy the "Short URL" or download the token file
