import os
import re
import math
import secrets
import json
import csv
import io
from datetime import datetime, timedelta
from functools import wraps

from flask import (Flask, render_template, request, redirect, url_for,
                   flash, jsonify, session, make_response, send_file)
from flask_sqlalchemy import SQLAlchemy
from flask_login import (LoginManager, UserMixin, login_user,
                         login_required, logout_user, current_user)
from werkzeug.security import generate_password_hash, check_password_hash
from sqlalchemy import func, and_, or_
import qrcode
import qrcode.image.svg

# ─────────────────────────────────────────────
# APP CONFIG
# ─────────────────────────────────────────────

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'attendr-super-secret-2024-xyz')
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL', 'sqlite:///attendr.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SQLALCHEMY_ENGINE_OPTIONS'] = {
    'pool_pre_ping': True,
    'pool_recycle': 300,
}

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'
login_manager.login_message = ''

# ─────────────────────────────────────────────
# CAMPUS CONFIG
# ─────────────────────────────────────────────

CAMPUS_LAT = 18.6851959
CAMPUS_LON = 78.1132355
ALLOWED_RADIUS = 80          # metres
QR_ROTATE_SECONDS = 15       # QR token lifespan
SUSPENSION_THRESHOLD = 3     # suspicious attempts before flag

# ─────────────────────────────────────────────
# MODELS
# ─────────────────────────────────────────────

class User(UserMixin, db.Model):
    __tablename__ = 'user'

    id           = db.Column(db.Integer, primary_key=True)
    pin          = db.Column(db.String(30), unique=True, nullable=False, index=True)
    name         = db.Column(db.String(120), nullable=False)
    password     = db.Column(db.String(256), nullable=False)
    role         = db.Column(db.String(10), default='student', nullable=False)
    year         = db.Column(db.String(10), nullable=True)
    branch       = db.Column(db.String(20), nullable=True)
    is_active    = db.Column(db.Boolean, default=True)
    is_suspended = db.Column(db.Boolean, default=False)
    last_login   = db.Column(db.DateTime, nullable=True)
    created_at   = db.Column(db.DateTime, default=datetime.utcnow)

    attendances      = db.relationship('Attendance', backref='student', lazy='dynamic',
                                       foreign_keys='Attendance.student_id')
    suspicious_logs  = db.relationship('SuspiciousLog', backref='user', lazy='dynamic')

    @property
    def branch_upper(self):
        return (self.branch or '').upper()

    def suspicious_count(self):
        return SuspiciousLog.query.filter_by(user_id=self.id).count()


class Subject(db.Model):
    __tablename__ = 'subject'

    id       = db.Column(db.Integer, primary_key=True)
    name     = db.Column(db.String(120), nullable=False)
    branch   = db.Column(db.String(20), nullable=True)
    year     = db.Column(db.String(10), nullable=True)
    sessions = db.relationship('ClassSession', backref='subject', lazy='dynamic')

    __table_args__ = (db.UniqueConstraint('name', 'branch', 'year', name='uq_subject_batch'),)


class ClassSession(db.Model):
    __tablename__ = 'class_session'

    id                 = db.Column(db.Integer, primary_key=True)
    subject_id         = db.Column(db.Integer, db.ForeignKey('subject.id'), nullable=False)
    created_by_id      = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    year               = db.Column(db.String(10), nullable=False)
    branch             = db.Column(db.String(20), nullable=False)
    duration           = db.Column(db.Integer, nullable=False)   # minutes
    qr_token           = db.Column(db.String(64), nullable=False)
    token_generated_at = db.Column(db.DateTime, default=datetime.utcnow)
    expires_at         = db.Column(db.DateTime, nullable=False)
    is_active          = db.Column(db.Boolean, default=True)
    created_at         = db.Column(db.DateTime, default=datetime.utcnow)

    attendances  = db.relationship('Attendance', backref='session', lazy='dynamic')
    created_by   = db.relationship('User', foreign_keys=[created_by_id])

    def is_expired(self):
        return datetime.utcnow() > self.expires_at

    def seconds_remaining(self):
        delta = self.expires_at - datetime.utcnow()
        return max(0, int(delta.total_seconds()))

    def token_age_seconds(self):
        if not self.token_generated_at:
            return QR_ROTATE_SECONDS + 1
        delta = datetime.utcnow() - self.token_generated_at
        return delta.total_seconds()

    def qr_seconds_remaining(self):
        age = self.token_age_seconds()
        remaining = QR_ROTATE_SECONDS - age
        return max(0, int(remaining))


class Attendance(db.Model):
    __tablename__ = 'attendance'

    id            = db.Column(db.Integer, primary_key=True)
    student_id    = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    session_id    = db.Column(db.Integer, db.ForeignKey('class_session.id'), nullable=False)
    ip_address    = db.Column(db.String(64), nullable=True)
    latitude      = db.Column(db.String(30), nullable=True)
    longitude     = db.Column(db.String(30), nullable=True)
    is_manual     = db.Column(db.Boolean, default=False)
    timestamp     = db.Column(db.DateTime, default=datetime.utcnow)

    __table_args__ = (db.UniqueConstraint('student_id', 'session_id', name='uq_student_session'),)


class SuspiciousLog(db.Model):
    __tablename__ = 'suspicious_log'

    id         = db.Column(db.Integer, primary_key=True)
    user_id    = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    ip_address = db.Column(db.String(64), nullable=True)
    reason     = db.Column(db.String(256), nullable=False)
    detail     = db.Column(db.String(512), nullable=True)
    timestamp  = db.Column(db.DateTime, default=datetime.utcnow)


class LoginAttempt(db.Model):
    __tablename__ = 'login_attempt'

    id         = db.Column(db.Integer, primary_key=True)
    pin        = db.Column(db.String(30), nullable=True)
    ip_address = db.Column(db.String(64), nullable=True)
    success    = db.Column(db.Boolean, default=False)
    timestamp  = db.Column(db.DateTime, default=datetime.utcnow)


# ─────────────────────────────────────────────
# LOGIN LOADER
# ─────────────────────────────────────────────

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


# ─────────────────────────────────────────────
# DECORATORS
# ─────────────────────────────────────────────

def admin_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not current_user.is_authenticated or current_user.role != 'admin':
            return jsonify({'error': 'Forbidden'}), 403
        return f(*args, **kwargs)
    return decorated


def student_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not current_user.is_authenticated or current_user.role != 'student':
            return jsonify({'error': 'Forbidden'}), 403
        return f(*args, **kwargs)
    return decorated


# ─────────────────────────────────────────────
# UTILITIES
# ─────────────────────────────────────────────

def haversine(lat1, lon1, lat2, lon2):
    R = 6371000
    phi1, phi2 = math.radians(lat1), math.radians(lat2)
    dphi   = math.radians(lat2 - lat1)
    dlambda = math.radians(lon2 - lon1)
    a = (math.sin(dphi / 2) ** 2 +
         math.cos(phi1) * math.cos(phi2) * math.sin(dlambda / 2) ** 2)
    a = min(1.0, max(0.0, a))
    return R * 2 * math.atan2(math.sqrt(a), math.sqrt(1 - a))


def log_suspicious(reason, detail=None, user_id=None, ip=None):
    entry = SuspiciousLog(
        user_id=user_id,
        ip_address=ip or request.remote_addr,
        reason=reason,
        detail=detail
    )
    db.session.add(entry)
    # Auto-suspend after threshold
    if user_id:
        count = SuspiciousLog.query.filter_by(user_id=user_id).count()
        if count >= SUSPENSION_THRESHOLD:
            u = User.query.get(user_id)
            if u:
                u.is_suspended = True
    db.session.commit()


def rotate_qr_if_needed(sess):
    """Rotate token if older than QR_ROTATE_SECONDS. Returns True if rotated."""
    if sess.token_age_seconds() >= QR_ROTATE_SECONDS:
        sess.qr_token = secrets.token_hex(24)
        sess.token_generated_at = datetime.utcnow()
        db.session.commit()
        return True
    return False


def get_or_create_subject(name, year, branch):
    name = name.strip().lower()
    subj = Subject.query.filter_by(name=name, year=year, branch=branch).first()
    if not subj:
        subj = Subject(name=name, year=year, branch=branch)
        db.session.add(subj)
        db.session.commit()
    return subj



def generate_qr_image(data: str, session_id: int) -> str:
    os.makedirs('static/qr', exist_ok=True)
    path = f'static/qr/qr_{session_id}.png'
    img = qrcode.make(data)
    img.save(path)
    return f'qr/qr_{session_id}.png'


def student_stats(student):
    """Strict year+branch filtering — a 1st year CS student ONLY sees
    sessions where year='1st Year' AND branch='CS'. Never cross-batch."""
    sy = (student.year   or '').strip()
    sb = (student.branch or '').strip().upper()

    # Total sessions for THIS EXACT batch only
    total_sessions = (ClassSession.query
                      .filter(ClassSession.year == sy,
                              func.upper(ClassSession.branch) == sb)
                      .count())

    # Only count attendance records linked to sessions of this batch
    attended = (Attendance.query
                .join(ClassSession, Attendance.session_id == ClassSession.id)
                .filter(Attendance.student_id == student.id,
                        ClassSession.year == sy,
                        func.upper(ClassSession.branch) == sb)
                .count())

    overall_pct = round((attended / total_sessions * 100), 1) if total_sessions else 0

    # Subjects belonging to this exact batch
    subjects = (Subject.query
                .filter(Subject.year == sy,
                        func.upper(Subject.branch) == sb)
                .all())

    breakdown = []
    for subj in subjects:
        # Sessions for this subject AND this batch — not all sessions for the subject
        conducted = (ClassSession.query
                     .filter(ClassSession.subject_id == subj.id,
                             ClassSession.year == sy,
                             func.upper(ClassSession.branch) == sb)
                     .count())
        att = (Attendance.query
               .join(ClassSession, Attendance.session_id == ClassSession.id)
               .filter(Attendance.student_id == student.id,
                       ClassSession.subject_id == subj.id,
                       ClassSession.year == sy,
                       func.upper(ClassSession.branch) == sb)
               .count())
        pct = round((att / conducted * 100), 1) if conducted else 0
        breakdown.append({
            'subject':    subj.name.title(),
            'conducted':  conducted,
            'attended':   att,
            'percentage': pct,
            'warning':    pct < 75
        })

    return {
        'total_sessions': total_sessions,
        'attended':       attended,
        'overall_pct':    overall_pct,
        'breakdown':      breakdown,
        'warning':        overall_pct < 75
    }


# ─────────────────────────────────────────────
# ROUTES — AUTH
# ─────────────────────────────────────────────

@app.route('/')
def home():
    if current_user.is_authenticated:
        return redirect(url_for('admin_dashboard') if current_user.role == 'admin'
                        else url_for('student_dashboard'))
    return redirect(url_for('login'))


@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('home'))

    if request.method == 'POST':
        pin      = request.form.get('pin', '').strip()
        password = request.form.get('password', '').strip()
        ip       = request.remote_addr

        # Log attempt
        attempt = LoginAttempt(pin=pin, ip_address=ip)

        if not pin or not password:
            flash('PIN and password are required.', 'error')
            return redirect(url_for('login'))

        user = User.query.filter_by(pin=pin).first()

        if not user:
            attempt.success = False
            db.session.add(attempt)
            db.session.commit()
            log_suspicious('INVALID_PIN', f'PIN: {pin}', ip=ip)
            flash('Invalid credentials.', 'error')
            return redirect(url_for('login'))

        if user.is_suspended:
            flash('Account suspended due to suspicious activity. Contact admin.', 'error')
            return redirect(url_for('login'))

        if not check_password_hash(user.password, password):
            attempt.success = False
            db.session.add(attempt)
            db.session.commit()
            log_suspicious('WRONG_PASSWORD', f'PIN: {pin}', user_id=user.id, ip=ip)
            flash('Invalid credentials.', 'error')
            return redirect(url_for('login'))

        attempt.success = True
        db.session.add(attempt)
        user.last_login = datetime.utcnow()
        db.session.commit()

        login_user(user)
        next_page = request.args.get('next')
        if next_page:
            return redirect(next_page)
        return redirect(url_for('admin_dashboard') if user.role == 'admin'
                        else url_for('student_dashboard'))

    return render_template('login.html')


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        pin    = request.form.get('pin', '').strip()
        name   = request.form.get('name', '').strip()
        pw     = request.form.get('password', '').strip()
        year   = request.form.get('year', '').strip()
        branch = request.form.get('branch', '').strip().upper()

        if not all([pin, name, pw, year, branch]):
            flash('All fields are required.', 'error')
            return redirect(url_for('register'))

        if User.query.filter_by(pin=pin).first():
            flash('PIN already registered.', 'error')
            return redirect(url_for('register'))

        user = User(
            pin=pin, name=name,
            password=generate_password_hash(pw),
            year=year, branch=branch, role='student'
        )
        db.session.add(user)
        db.session.commit()
        flash('Registration successful! Please login.', 'success')
        return redirect(url_for('login'))

    return render_template('register.html')


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))


# ─────────────────────────────────────────────
# ROUTES — STUDENT
# ─────────────────────────────────────────────

@app.route('/student/dashboard')
@login_required
def student_dashboard():
    if current_user.role != 'student':
        return redirect(url_for('admin_dashboard'))

    stats = student_stats(current_user)

    # Active session for this student's batch
    active = ClassSession.query.filter_by(
        year=current_user.year,
        branch=current_user.branch_upper,
        is_active=True
    ).filter(ClassSession.expires_at > datetime.utcnow()).first()

    # Recent class sessions (last 10)
    recent_sessions = (ClassSession.query
                       .filter_by(year=current_user.year, branch=current_user.branch_upper)
                       .order_by(ClassSession.created_at.desc())
                       .limit(10).all())

    # Mark which ones student attended
    attended_ids = {
        a.session_id for a in
        Attendance.query.filter_by(student_id=current_user.id).all()
    }

    return render_template('student_dashboard.html',
                           stats=stats,
                           active_session=active,
                           recent_sessions=recent_sessions,
                           attended_ids=attended_ids)


@app.route('/student/scan', methods=['GET'])
@login_required
def scan_qr():
    if current_user.role != 'student':
        return redirect(url_for('admin_dashboard'))
    return render_template('scan_qr.html')


@app.route('/api/mark_attendance', methods=['POST'])
@login_required
def mark_attendance():
    if current_user.role != 'student':
        return jsonify({'success': False, 'message': 'Forbidden'}), 403

    if current_user.is_suspended:
        return jsonify({'success': False, 'message': 'Account suspended.'})

    data = request.get_json(silent=True) or {}

    qr_raw = data.get('qr', '').strip()
    lat    = data.get('lat')
    lon    = data.get('lon')

    # ── Parse QR ──
    if ':' not in qr_raw:
        return jsonify({'success': False, 'message': 'Invalid QR format.'})

    try:
        session_id_str, token = qr_raw.split(':', 1)
        session_id = int(session_id_str)
    except (ValueError, TypeError):
        return jsonify({'success': False, 'message': 'Malformed QR data.'})

    sess = ClassSession.query.get(session_id)

    if not sess:
        return jsonify({'success': False, 'message': 'Session not found.'})

    # ── Session active? ──
    if not sess.is_active:
        return jsonify({'success': False, 'message': 'Session is no longer active.'})

    # ── Session expired? ──
    if sess.is_expired():
        sess.is_active = False
        db.session.commit()
        return jsonify({'success': False, 'message': 'Class session has ended.'})

    # ── Token valid & not stale? ──
    if sess.qr_token != token:
        log_suspicious('TOKEN_MISMATCH', f'session={session_id}',
                       user_id=current_user.id, ip=request.remote_addr)
        return jsonify({'success': False, 'message': 'QR expired — get latest QR.'})

    if sess.token_age_seconds() > QR_ROTATE_SECONDS + 2:   # 2s grace
        return jsonify({'success': False, 'message': 'QR token expired. Scan fresh QR.'})

    # ── Batch match ──
    if (sess.year != current_user.year or
            sess.branch.upper() != current_user.branch_upper):
        log_suspicious('BATCH_MISMATCH',
                       f'Student batch {current_user.year}/{current_user.branch_upper} '
                       f'vs session {sess.year}/{sess.branch}',
                       user_id=current_user.id, ip=request.remote_addr)
        return jsonify({'success': False,
                        'message': 'This session is not for your batch.'})

    # ── Duplicate check (same student) ──
    if Attendance.query.filter_by(student_id=current_user.id,
                                  session_id=sess.id).first():
        return jsonify({'success': False, 'message': 'Attendance already marked for this session.'})

    # ── IP device lock: one device (IP) can only mark ONE student per session ──
    # Prevents: student marks, logs out, friend logs in on same phone and marks
    ip = request.remote_addr
    ip_conflict = (Attendance.query
                   .filter_by(session_id=sess.id, ip_address=ip)
                   .filter(Attendance.is_manual == False)
                   .first())
    if ip_conflict:
        log_suspicious('IP_DEVICE_REUSE',
                       f'IP {ip} already used by student_id={ip_conflict.student_id} '
                       f'for session={sess.id}. Attempted by student_id={current_user.id}',
                       user_id=current_user.id, ip=ip)
        return jsonify({'success': False,
                        'message': 'Another student already marked attendance from this device. '
                                   'Each device can only be used once per session.'})

    # ── Geolocation ──
    if lat is None or lon is None:
        return jsonify({'success': False, 'message': 'Location required. Enable GPS and try again.'})

    try:
        lat, lon = float(lat), float(lon)
    except (ValueError, TypeError):
        return jsonify({'success': False, 'message': 'Invalid location data.'})

    dist = haversine(lat, lon, CAMPUS_LAT, CAMPUS_LON)
    if dist > ALLOWED_RADIUS:
        log_suspicious('OUTSIDE_CAMPUS',
                       f'Distance: {dist:.1f}m, lat={lat}, lon={lon}',
                       user_id=current_user.id, ip=ip)
        return jsonify({'success': False,
                        'message': f'You are {dist:.0f}m from campus. Must be within {ALLOWED_RADIUS}m.'})

    # ── Record attendance ──
    rec = Attendance(
        student_id=current_user.id,
        session_id=sess.id,
        ip_address=ip,
        latitude=str(lat),
        longitude=str(lon),
        is_manual=False
    )
    db.session.add(rec)
    db.session.commit()

    return jsonify({
        'success': True,
        'message': f'Attendance marked for {sess.subject.name.title()}!'
    })


# ─────────────────────────────────────────────
# ROUTES — ADMIN
# ─────────────────────────────────────────────

@app.route('/admin/dashboard')
@login_required
def admin_dashboard():
    if current_user.role != 'admin':
        return redirect(url_for('student_dashboard'))

    # Summary cards
    total_students = User.query.filter_by(role='student', is_active=True).count()
    total_sessions = ClassSession.query.count()
    total_att      = Attendance.query.count()
    active_sessions = ClassSession.query.filter_by(is_active=True)\
                      .filter(ClassSession.expires_at > datetime.utcnow()).count()

    # Suspicious logs today
    today = datetime.utcnow().date()
    suspicious_today = SuspiciousLog.query.filter(
        func.date(SuspiciousLog.timestamp) == today
    ).count()

    # Recent sessions (last 8)
    recent = (ClassSession.query
              .order_by(ClassSession.created_at.desc())
              .limit(8).all())

    # Chart data — attendance last 7 days
    chart_data = []
    for i in range(6, -1, -1):
        day = datetime.utcnow().date() - timedelta(days=i)
        cnt = Attendance.query.filter(func.date(Attendance.timestamp) == day).count()
        chart_data.append({'day': day.strftime('%a'), 'count': cnt})

    return render_template('admin_dashboard.html',
                           total_students=total_students,
                           total_sessions=total_sessions,
                           total_att=total_att,
                           active_sessions=active_sessions,
                           suspicious_today=suspicious_today,
                           recent=recent,
                           chart_data=json.dumps(chart_data))


@app.route('/admin/start_class', methods=['GET', 'POST'])
@login_required
def start_class():
    if current_user.role != 'admin':
        return redirect(url_for('student_dashboard'))

    subjects = Subject.query.order_by(Subject.name).all()

    if request.method == 'POST':
        subject_name = request.form.get('subject_name', '').strip().lower()
        year         = request.form.get('year', '').strip()
        branch       = request.form.get('branch', '').strip().upper()
        duration     = request.form.get('duration', '').strip()

        if not all([subject_name, year, branch, duration]):
            flash('All fields are required.', 'error')
            return redirect(url_for('start_class'))

        try:
            duration = int(duration)
            assert 5 <= duration <= 300
        except (ValueError, AssertionError):
            flash('Duration must be between 5 and 300 minutes.', 'error')
            return redirect(url_for('start_class'))

        # Prevent duplicate active session for same batch+subject today
        subj = get_or_create_subject(subject_name, year, branch)

        conflict = (ClassSession.query
                    .filter_by(subject_id=subj.id, year=year, branch=branch, is_active=True)
                    .filter(ClassSession.expires_at > datetime.utcnow())
                    .first())
        if conflict:
            flash('An active session already exists for this batch & subject.', 'error')
            return redirect(url_for('start_class'))

        token = secrets.token_hex(24)
        expires = datetime.utcnow() + timedelta(minutes=duration)

        sess = ClassSession(
            subject_id=subj.id,
            created_by_id=current_user.id,
            year=year, branch=branch,
            duration=duration,
            qr_token=token,
            token_generated_at=datetime.utcnow(),
            expires_at=expires,
            is_active=True,
        )
        db.session.add(sess)
        db.session.commit()

        return redirect(url_for('session_live', session_id=sess.id))

    return render_template('start_class.html', subjects=subjects)


@app.route('/admin/session/<int:session_id>/live')
@login_required
def session_live(session_id):
    if current_user.role != 'admin':
        return redirect(url_for('student_dashboard'))

    sess = ClassSession.query.get_or_404(session_id)
    return render_template('session_live.html', sess=sess,
                           qr_rotate=QR_ROTATE_SECONDS)


@app.route('/api/session/<int:session_id>/status')
@login_required
def session_status(session_id):
    """Polling endpoint for live QR & session status."""
    sess = ClassSession.query.get_or_404(session_id)

    rotate_qr_if_needed(sess)

    # Auto-close if expired
    if sess.is_expired() and sess.is_active:
        sess.is_active = False
        db.session.commit()

    qr_data = f'{sess.id}:{sess.qr_token}'
    attend_count = sess.attendances.count()

    # Attendees list for live display
    att_records = (db.session.query(Attendance, User)
                   .join(User, Attendance.student_id == User.id)
                   .filter(Attendance.session_id == sess.id)
                   .order_by(Attendance.timestamp)
                   .all())

    attendances = [{
        'name': u.name,
        'pin':  u.pin,
        'time': a.timestamp.strftime('%H:%M:%S'),
        'is_manual': a.is_manual
    } for a, u in att_records]

    return jsonify({
        'session_id': sess.id,
        'is_active':  sess.is_active,
        'qr_data':    qr_data,
        'qr_seconds_remaining':   sess.qr_seconds_remaining(),
        'session_seconds_remaining': sess.seconds_remaining(),
        'attend_count': attend_count,
        'token':      sess.qr_token,
        'attendances': attendances,
    })


@app.route('/api/session/<int:session_id>/stop', methods=['POST'])
@login_required
def stop_session(session_id):
    if current_user.role != 'admin':
        return jsonify({'error': 'Forbidden'}), 403
    sess = ClassSession.query.get_or_404(session_id)
    sess.is_active = False
    sess.expires_at = datetime.utcnow()
    db.session.commit()
    return jsonify({'success': True})


@app.route('/admin/students')
@login_required
def student_info():
    if current_user.role != 'admin':
        return redirect(url_for('student_dashboard'))

    year   = request.args.get('year', '')
    branch = request.args.get('branch', '').upper()
    search = request.args.get('search', '').strip()

    q = User.query.filter_by(role='student')
    if year:
        q = q.filter(User.year == year)
    if branch:
        q = q.filter(func.upper(User.branch) == branch)
    if search:
        q = q.filter(or_(User.name.ilike(f'%{search}%'),
                         User.pin.ilike(f'%{search}%')))

    students = q.order_by(User.name).all()

    # Attach quick stats
    enriched = []
    for s in students:
        sy = (s.year   or '').strip()
        sb = (s.branch or '').strip().upper()
        # Strict: only sessions for this student's exact year + branch
        total = (ClassSession.query
                 .filter(ClassSession.year == sy,
                         func.upper(ClassSession.branch) == sb)
                 .count())
        # Only attendance linked to sessions of this batch
        att = (Attendance.query
               .join(ClassSession, Attendance.session_id == ClassSession.id)
               .filter(Attendance.student_id == s.id,
                       ClassSession.year == sy,
                       func.upper(ClassSession.branch) == sb)
               .count())
        pct = round(att / total * 100, 1) if total else 0
        enriched.append({'user': s, 'total': total, 'attended': att, 'pct': pct})

    return render_template('student_info.html', students=enriched,
                           year=year, branch=branch, search=search)


@app.route('/admin/student/<int:uid>/delete', methods=['POST'])
@login_required
def delete_student(uid):
    if current_user.role != 'admin':
        return jsonify({'error': 'Forbidden'}), 403
    user = User.query.get_or_404(uid)
    if user.role == 'admin':
        return jsonify({'error': 'Cannot delete admin'}), 400
    # Cascade delete attendance
    Attendance.query.filter_by(student_id=uid).delete()
    SuspiciousLog.query.filter_by(user_id=uid).delete()
    db.session.delete(user)
    db.session.commit()
    flash(f'Student {user.name} deleted.', 'success')
    return redirect(url_for('student_info'))


@app.route('/admin/student/<int:uid>/toggle_suspend', methods=['POST'])
@login_required
def toggle_suspend(uid):
    if current_user.role != 'admin':
        return jsonify({'error': 'Forbidden'}), 403
    user = User.query.get_or_404(uid)
    user.is_suspended = not user.is_suspended
    db.session.commit()
    status = 'suspended' if user.is_suspended else 'unsuspended'
    flash(f'Student {user.name} {status}.', 'success')
    return redirect(url_for('student_info'))


@app.route('/admin/attendance', methods=['GET', 'POST'])
@login_required
def attendance_dashboard():
    if current_user.role != 'admin':
        return redirect(url_for('student_dashboard'))

    year       = request.args.get('year', '')
    branch     = request.args.get('branch', '').upper()
    subject_id = request.args.get('subject_id', '')
    date_str   = request.args.get('date', '')

    q = (db.session.query(Attendance, User, ClassSession, Subject)
         .join(User,         Attendance.student_id  == User.id)
         .join(ClassSession, Attendance.session_id  == ClassSession.id)
         .join(Subject,      ClassSession.subject_id == Subject.id))

    if year:
        q = q.filter(ClassSession.year == year)
    if branch:
        q = q.filter(func.upper(ClassSession.branch) == branch)
    if subject_id:
        q = q.filter(ClassSession.subject_id == int(subject_id))
    if date_str:
        try:
            d = datetime.strptime(date_str, '%Y-%m-%d').date()
            q = q.filter(func.date(Attendance.timestamp) == d)
        except ValueError:
            pass

    records = q.order_by(Attendance.timestamp.desc()).all()

    # Summaries
    unique_students = len({r[1].id for r in records})
    subjects_list   = Subject.query.order_by(Subject.name).all()

    return render_template('attendance_dashboard.html',
                           records=records,
                           unique_students=unique_students,
                           subjects=subjects_list,
                           year=year, branch=branch,
                           subject_id=subject_id, date_str=date_str)


@app.route('/admin/recent_class', methods=['GET', 'POST'])
@login_required
def recent_class():
    if current_user.role != 'admin':
        return redirect(url_for('student_dashboard'))

    # Optionally filter by year/branch
    year   = request.args.get('year', '')
    branch = request.args.get('branch', '').upper()

    q = ClassSession.query
    if year:
        q = q.filter(ClassSession.year == year)
    if branch:
        q = q.filter(func.upper(ClassSession.branch) == branch)

    recent_session = q.order_by(ClassSession.created_at.desc()).first()

    if request.method == 'POST':
        pin = request.form.get('pin', '').strip()
        sid = int(request.form.get('session_id', 0))
        target_session = ClassSession.query.get_or_404(sid)
        student = User.query.filter_by(pin=pin, role='student').first()

        if not student:
            flash('Student not found with that PIN.', 'error')
            return redirect(url_for('recent_class', year=year, branch=branch))

        if Attendance.query.filter_by(student_id=student.id,
                                      session_id=target_session.id).first():
            flash('Attendance already marked for this student.', 'warning')
            return redirect(url_for('recent_class', year=year, branch=branch))

        rec = Attendance(
            student_id=student.id,
            session_id=target_session.id,
            ip_address='Manual Entry',
            latitude='Manual', longitude='Manual',
            is_manual=True
        )
        db.session.add(rec)
        db.session.commit()
        flash(f'Attendance added for {student.name} ({student.pin}).', 'success')
        return redirect(url_for('recent_class', year=year, branch=branch))

    attendance_list = []
    if recent_session:
        attendance_list = (db.session.query(Attendance, User)
                           .join(User, Attendance.student_id == User.id)
                           .filter(Attendance.session_id == recent_session.id)
                           .order_by(Attendance.timestamp)
                           .all())

    # All sessions for the selector
    all_sessions = ClassSession.query.order_by(ClassSession.created_at.desc()).limit(20).all()

    return render_template('recent_class.html',
                           recent_session=recent_session,
                           attendance_list=attendance_list,
                           all_sessions=all_sessions,
                           year=year, branch=branch)


@app.route('/admin/suspicious')
@login_required
def suspicious_panel():
    if current_user.role != 'admin':
        return redirect(url_for('student_dashboard'))

    logs = (SuspiciousLog.query
            .order_by(SuspiciousLog.timestamp.desc())
            .limit(200).all())

    suspended = User.query.filter_by(is_suspended=True).all()

    return render_template('suspicious_panel.html',
                           logs=logs, suspended=suspended)


@app.route('/admin/add_student', methods=['POST'])
@login_required
def admin_add_student():
    if current_user.role != 'admin':
        return jsonify({'error': 'Forbidden'}), 403

    pin    = request.form.get('pin', '').strip()
    name   = request.form.get('name', '').strip()
    pw     = request.form.get('password', '').strip()
    year   = request.form.get('year', '').strip()
    branch = request.form.get('branch', '').strip().upper()

    if not all([pin, name, pw, year, branch]):
        flash('All fields required.', 'error')
        return redirect(url_for('student_info'))

    if User.query.filter_by(pin=pin).first():
        flash('PIN already exists.', 'error')
        return redirect(url_for('student_info'))

    user = User(pin=pin, name=name,
                password=generate_password_hash(pw),
                year=year, branch=branch, role='student')
    db.session.add(user)
    db.session.commit()
    flash(f'Student {name} added successfully.', 'success')
    return redirect(url_for('student_info'))


# ─────────────────────────────────────────────
# EXPORT
# ─────────────────────────────────────────────

@app.route('/admin/export/csv')
@login_required
def export_csv():
    if current_user.role != 'admin':
        return redirect(url_for('student_dashboard'))

    records = (db.session.query(Attendance, User, ClassSession, Subject)
               .join(User,         Attendance.student_id  == User.id)
               .join(ClassSession, Attendance.session_id  == ClassSession.id)
               .join(Subject,      ClassSession.subject_id == Subject.id)
               .order_by(Attendance.timestamp.desc()).all())

    si = io.StringIO()
    writer = csv.writer(si)
    writer.writerow(['Student Name', 'PIN', 'Year', 'Branch', 'Subject',
                     'Session Date', 'Timestamp', 'IP Address', 'Manual'])
    for att, user, sess, subj in records:
        writer.writerow([
            user.name, user.pin, sess.year, sess.branch,
            subj.name.title(), sess.created_at.strftime('%Y-%m-%d'),
            att.timestamp.strftime('%Y-%m-%d %H:%M:%S'),
            att.ip_address or '', 'Yes' if att.is_manual else 'No'
        ])

    output = make_response(si.getvalue())
    output.headers['Content-Disposition'] = 'attachment; filename=attendance_export.csv'
    output.headers['Content-type'] = 'text/csv'
    return output


# ─────────────────────────────────────────────
# API — STATS
# ─────────────────────────────────────────────

@app.route('/api/admin/stats')
@login_required
def api_admin_stats():
    if current_user.role != 'admin':
        return jsonify({'error': 'Forbidden'}), 403

    year   = request.args.get('year', '')
    branch = request.args.get('branch', '').upper()

    q_students = User.query.filter_by(role='student')
    q_sessions = ClassSession.query
    q_att      = Attendance.query.join(ClassSession, Attendance.session_id == ClassSession.id)

    if year:
        q_students = q_students.filter(User.year == year)
        q_sessions = q_sessions.filter(ClassSession.year == year)
        q_att      = q_att.filter(ClassSession.year == year)
    if branch:
        q_students = q_students.filter(func.upper(User.branch) == branch)
        q_sessions = q_sessions.filter(func.upper(ClassSession.branch) == branch)
        q_att      = q_att.filter(func.upper(ClassSession.branch) == branch)

    return jsonify({
        'total_students': q_students.count(),
        'total_sessions': q_sessions.count(),
        'total_att':      q_att.count(),
        'active_sessions': ClassSession.query.filter_by(is_active=True)
                           .filter(ClassSession.expires_at > datetime.utcnow()).count(),
    })


@app.route('/api/student/stats')
@login_required
def api_student_stats():
    if current_user.role != 'student':
        return jsonify({'error': 'Forbidden'}), 403
    return jsonify(student_stats(current_user))


# ─────────────────────────────────────────────
# RUN
# ─────────────────────────────────────────────

if __name__ == '__main__':
    with app.app_context():
        db.create_all()

        # Seed admin
        if not User.query.filter_by(pin='admin').first():
            admin = User(
                pin='admin', name='Administrator',
                password=generate_password_hash('admin123'),
                role='admin', year=None, branch=None
            )
            db.session.add(admin)
            db.session.commit()
            print('[ATTENDR] Default admin created — PIN: admin / Pass: admin123')

    app.run(host='0.0.0.0', port=5000, debug=False)
