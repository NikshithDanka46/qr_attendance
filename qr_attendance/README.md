# ATTENDR — Smart Attendance Management System
## Complete Setup & Deployment Guide

---

## 📁 PROJECT STRUCTURE

```
attendr/
├── app.py                    ← Main Flask application (ALL backend logic)
├── requirements.txt          ← Python dependencies
├── README.md                 ← This file
├── templates/
│   ├── base.html             ← Global layout, sidebar, design system
│   ├── login.html            ← Login page
│   ├── register.html         ← Student registration
│   ├── admin_dashboard.html  ← Admin overview with charts
│   ├── session_live.html     ← Live QR session screen
│   ├── student_dashboard.html← Student attendance overview
│   ├── scan_qr.html          ← Camera QR scanner
│   ├── start_class.html      ← Create new session
│   ├── attendance_dashboard.html ← Filter/view all records
│   ├── student_info.html     ← Student management
│   ├── recent_class.html     ← Recent class + manual entry
│   └── suspicious_panel.html ← Security activity log
└── static/
    └── qr/                   ← Auto-created for QR images (not needed in new version)
```

---

## ⚡ QUICK START (LOCAL)

### Step 1 — Clone / copy files
```bash
mkdir attendr && cd attendr
# paste all files into this folder
```

### Step 2 — Create virtual environment
```bash
python -m venv venv

# Linux/Mac:
source venv/bin/activate

# Windows:
venv\Scripts\activate
```

### Step 3 — Install dependencies
```bash
pip install -r requirements.txt
```

### Step 4 — Run the app
```bash
python app.py
```

### Step 5 — Open in browser
```
http://localhost:5000
```

### Default admin login:
- **PIN:** `admin`
- **Password:** `admin123`

> ⚠️ Change admin password immediately in production!

---

## 🌐 PRODUCTION DEPLOYMENT

### Option A: Render.com (Free, Recommended)

1. Push code to GitHub repository
2. Go to https://render.com → New → Web Service
3. Connect your GitHub repo
4. Set these:
   - **Build Command:** `pip install -r requirements.txt`
   - **Start Command:** `gunicorn app:app`
   - **Environment Variables:**
     ```
     SECRET_KEY = your-super-secret-key-here
     DATABASE_URL = (leave empty for SQLite, or add PostgreSQL URL)
     ```
5. Click **Deploy**

### Option B: Railway.app

1. Push to GitHub
2. railway.app → New Project → Deploy from GitHub
3. Add env var: `SECRET_KEY=your-key`
4. Done — auto deploys

### Option C: VPS (Ubuntu)

```bash
# Install dependencies
sudo apt update && sudo apt install python3-pip python3-venv nginx -y

# Setup
cd /var/www/
git clone <your-repo> attendr
cd attendr
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt

# Run with gunicorn
gunicorn -w 4 -b 0.0.0.0:5000 app:app

# Optional: setup nginx as reverse proxy
```

### Option D: PythonAnywhere (Free tier)

1. Upload all files via Files tab
2. Create a new Web App → Flask
3. Set WSGI file to point to `app.py`
4. Install requirements in bash console

---

## ⚙️ CONFIGURATION

Edit these at the top of `app.py`:

```python
CAMPUS_LAT = 18.6851959      # Your campus latitude
CAMPUS_LON = 78.1132355      # Your campus longitude
ALLOWED_RADIUS = 80          # Metres from campus (80m default)
QR_ROTATE_SECONDS = 15       # QR token lifespan
SUSPENSION_THRESHOLD = 3     # Suspicious attempts before auto-suspend
```

### Environment Variables (production):
```env
SECRET_KEY=your-long-random-secret-key-minimum-32-chars
DATABASE_URL=sqlite:///attendr.db
```

For PostgreSQL:
```env
DATABASE_URL=postgresql://user:password@host:5432/dbname
```

---

## 🔐 SECURITY FEATURES

| Feature | Details |
|---------|---------|
| QR Token Rotation | Every 15 seconds, server-side validated |
| Geolocation Check | Must be within 80m of campus |
| Session Isolation | Year + Branch must match session |
| Anti-Duplicate | DB unique constraint (student, session) |
| Rate Limiting | Suspicious log + auto-suspend at 3 events |
| Password Hashing | Werkzeug PBKDF2 SHA-256 |
| CSRF Protection | Flask session tokens |
| Token Expiry | Server validates timestamp, not just token string |
| Batch Mismatch | Students can't attend other batch sessions |

---

## 📊 FEATURES OVERVIEW

### Admin
- 📊 Dashboard with live stats & 7-day chart
- 🎯 Filter stats by Year + Branch
- ▶️ Start class session with auto QR generation
- 📡 Live session monitor with rotating QR
- 🔄 QR rotates every 15s without resetting session timer
- ⏹️ Manual stop session
- 📋 Attendance records with multi-filter
- 👥 Student management (add, suspend, delete)
- ✏️ Manual attendance entry by PIN
- 🔍 Recent class viewer
- 🛡️ Suspicious activity panel
- 📥 CSV export

### Student
- 📈 Overall attendance percentage with animated ring
- 📚 Subject-wise breakdown with warning at <75%
- 📷 Camera QR scanner with geolocation
- ⚠️ Real-time error messages for each failure reason
- 📱 Manual code entry fallback

---

## 🐛 TROUBLESHOOTING

**QR not generating?**
```bash
pip install qrcode[pil] Pillow
```

**Camera not working on mobile?**
- Must use HTTPS in production (camera requires secure context)
- On Render/Railway it's HTTPS automatically

**Location always fails?**
- Enable location in browser settings
- HTTPS required for geolocation on mobile Chrome

**Database errors?**
```bash
# Reset database
rm attendr.db
python app.py  # recreates it
```

**Students can't find their session?**
- Check Year and Branch match exactly between student profile and session
- Year format must match: "1st Year", "2nd Year" etc.
- Branch must be uppercase: CS, IT, EC

---

## 📝 API ENDPOINTS

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/session/<id>/status` | Live QR + attendance count |
| POST | `/api/session/<id>/stop` | Stop session (admin) |
| POST | `/api/mark_attendance` | Mark attendance (student) |
| GET | `/api/admin/stats` | Dashboard stats with filters |
| GET | `/api/student/stats` | Student attendance breakdown |
| GET | `/admin/export/csv` | Download full CSV |

---

## 🆕 WHAT'S NEW VS OLD VERSION

| Feature | Old | New |
|---------|-----|-----|
| QR Rotation | Static | Every 15s with countdown ring |
| Security logging | None | Full suspicious activity panel |
| Auto-suspend | None | After 3 suspicious events |
| Batch mismatch check | None | ✅ Enforced |
| Live session monitor | None | Real-time with counter |
| Dashboard charts | None | 7-day bar chart |
| Student stats | Basic | Animated ring + subject breakdown |
| Manual attendance | Basic | Full with PIN lookup |
| CSV Export | None | Full export |
| Responsive UI | None | Sidebar layout |
| Toast notifications | None | ✅ All actions |
| Token expiry validation | Basic | Server-side timestamp check |
| Session auto-close | None | ✅ On expiry |
