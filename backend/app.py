from flask import Flask, jsonify, request
from flask_cors import CORS
from flask_jwt_extended import (
    JWTManager, create_access_token,
    jwt_required, get_jwt_identity, get_jwt
)
from werkzeug.security import generate_password_hash, check_password_hash
from db_config import get_connection
from risk_analyzer import analyze_risk
from functools import wraps
import datetime
import smtplib
import os
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

app = Flask(__name__)
app.config['JWT_SECRET_KEY'] = os.environ.get('JWT_SECRET_KEY')
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = datetime.timedelta(hours=8)
CORS(app)
jwt = JWTManager(app)

# ─── RBAC DECORATORS ────────────────────────────────────────────

def principal_required(fn):
    @wraps(fn)
    @jwt_required()
    def wrapper(*args, **kwargs):
        if get_jwt().get('role') != 'principal':
            return jsonify({'error': 'Principals only'}), 403
        return fn(*args, **kwargs)
    return wrapper

def teacher_required(fn):
    @wraps(fn)
    @jwt_required()
    def wrapper(*args, **kwargs):
        if get_jwt().get('role') not in ['teacher', 'principal']:
            return jsonify({'error': 'Teachers or Principal only'}), 403
        return fn(*args, **kwargs)
    return wrapper

def student_required(fn):
    @wraps(fn)
    @jwt_required()
    def wrapper(*args, **kwargs):
        if get_jwt().get('role') != 'student':
            return jsonify({'error': 'Students only'}), 403
        return fn(*args, **kwargs)
    return wrapper

# ─── AUTH ROUTES ─────────────────────────────────────────────────

@app.route('/api/v1/auth/login', methods=['POST'])
def login():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    conn = get_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute(
                "SELECT * FROM users WHERE username=%s", (username,)
            )
            user = cursor.fetchone()
            if not user:
                return jsonify({'error': 'User not found', 'username_tried': username}), 401
            hash_check = check_password_hash(user['password_hash'], password)
            if not hash_check:
                return jsonify({'error': 'Wrong password', 'hash_start': user['password_hash'][:30]}), 401
            if not user['is_approved']:
                return jsonify({'error': 'Account pending approval'}), 403
            token = create_access_token(
                identity=str(user['id']),
                additional_claims={'role': user['role']}
            )
            return jsonify({
                'token': token,
                'role': user['role'],
                'user_id': user['id']
            })
    finally:
        conn.close()

@app.route('/api/v1/auth/register-teacher', methods=['POST'])
def register_teacher():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    name = data.get('name')
    email = data.get('email')
    specialization = data.get('specialization', '')

    if not all([username, password, name, email]):
        return jsonify({'error': 'All fields are required'}), 400

    hashed = generate_password_hash(password)
    conn = get_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute(
                "SELECT id FROM users WHERE username=%s", (username,)
            )
            if cursor.fetchone():
                return jsonify({'error': 'Username already exists'}), 409
            cursor.execute(
                """INSERT INTO users (username, password_hash, role, is_approved)
                   VALUES (%s, %s, 'teacher', 0)""",
                (username, hashed)
            )
            user_id = cursor.lastrowid
            cursor.execute(
                """INSERT INTO teachers
                   (user_id, name, email, subject_specialization)
                   VALUES (%s, %s, %s, %s)""",
                (user_id, name, email, specialization)
            )
        conn.commit()
        return jsonify({
            'message': 'Registration successful. '
                       'Wait for Principal approval before login.'
        }), 201
    finally:
        conn.close()

# ─── PRINCIPAL ROUTES ────────────────────────────────────────────

@app.route('/api/v1/principal/pending-teachers',
           methods=['GET'])
@principal_required
def get_pending_teachers():
    conn = get_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute("""
                SELECT t.id, u.id as user_id,
                       u.username, u.is_approved,
                       t.name, t.email,
                       t.subject_specialization
                FROM users u
                JOIN teachers t ON u.id = t.user_id
                WHERE u.role='teacher'
                AND u.is_approved=0
                ORDER BY t.name
            """)
            return jsonify({'pending': cursor.fetchall()})
    finally:
        conn.close()

@app.route('/api/v1/principal/approve-teacher/<int:user_id>',
           methods=['POST'])
@principal_required
def approve_teacher(user_id):
    conn = get_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute(
                """UPDATE users SET is_approved=1
                   WHERE id=%s AND role='teacher'""",
                (user_id,)
            )
            if cursor.rowcount == 0:
                return jsonify({
                    'error': 'Teacher not found'
                }), 404
        conn.commit()
        return jsonify({
            'message': 'Teacher approved successfully'
        })
    finally:
        conn.close()

@app.route('/api/v1/principal/all-students', methods=['GET'])
@principal_required
def get_all_students():
    conn = get_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute("""
                SELECT s.id, s.name, s.class_section,
                       s.roll_number,
                       COALESCE(
                         ROUND(
                           SUM(a.status='Present') /
                           COUNT(a.id) * 100, 2
                         ), 0
                       ) as attendance_pct
                FROM students s
                LEFT JOIN attendance a ON s.id = a.student_id
                GROUP BY s.id
            """)
            return jsonify({'students': cursor.fetchall()})
    finally:
        conn.close()

@app.route('/api/v1/principal/all-teachers',
           methods=['GET'])
@principal_required
def get_all_teachers():
    conn = get_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute("""
                SELECT t.id, u.id as user_id,
                       u.username, u.is_approved,
                       t.name, t.email,
                       t.subject_specialization
                FROM users u
                JOIN teachers t ON u.id = t.user_id
                WHERE u.role='teacher'
                ORDER BY t.name
            """)
            return jsonify({'teachers': cursor.fetchall()})
    finally:
        conn.close()

# ─── ATTENDANCE ROUTES ───────────────────────────────────────────

@app.route('/api/v1/attendance/<int:student_id>', methods=['GET'])
@jwt_required()
def get_attendance(student_id):
    conn = get_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute(
                """SELECT date, status FROM attendance
                   WHERE student_id=%s ORDER BY date DESC""",
                (student_id,)
            )
            records = cursor.fetchall()
            total = len(records)
            present = sum(
                1 for r in records if r['status'] == 'Present'
            )
            percentage = round(
                (present / total * 100), 2
            ) if total > 0 else 0
            return jsonify({
                'records': records,
                'percentage': percentage,
                'total': total,
                'present': present,
                'absent': total - present
            })
    finally:
        conn.close()

@app.route('/api/v1/attendance', methods=['POST'])
@teacher_required
def post_attendance():
    data = request.get_json()
    records = data.get('records', [])
    conn = get_connection()
    try:
        with conn.cursor() as cursor:
            for r in records:
                cursor.execute(
                    """INSERT INTO attendance
                       (student_id, date, status, marked_by)
                       VALUES (%s, %s, %s, %s)""",
                    (r['student_id'], r['date'],
                     r['status'], r.get('marked_by'))
                )
        conn.commit()
        return jsonify({
            'message': f"{len(records)} records saved"
        })
    finally:
        conn.close()

# ─── MARKS ROUTES ────────────────────────────────────────────────
@app.route('/api/v1/marks/<int:student_id>', methods=['GET'])
@jwt_required()
def get_marks(student_id):
    conn = get_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute("""
                SELECT m.id, m.exam_name, m.marks_obtained,
                       m.max_marks, s.subject_name
                FROM marks m
                JOIN subjects s ON m.subject_id = s.id
                WHERE m.student_id=%s
                ORDER BY m.id DESC
            """, (student_id,))
            return jsonify({'marks': cursor.fetchall()})
    finally:
        conn.close()

@app.route('/api/v1/marks', methods=['POST'])
@teacher_required
def post_marks():
    data = request.get_json()
    conn = get_connection()
    try:
        with conn.cursor() as cursor:
            # Validate class section match
            cursor.execute(
                "SELECT class_section FROM students WHERE id=%s",
                (data['student_id'],)
            )
            student = cursor.fetchone()
            cursor.execute(
                "SELECT class_section FROM subjects WHERE id=%s",
                (data['subject_id'],)
            )
            subject = cursor.fetchone()
            if not student or not subject:
                return jsonify({
                    'error': 'Student or subject not found'
                }), 404
            if student['class_section'] != subject['class_section']:
                return jsonify({
                    'error': 'Subject does not belong to student class'
                }), 400

            # Check if marks already exist for same
            # student + subject + exam
            cursor.execute("""
                SELECT id, marks_obtained, max_marks
                FROM marks
                WHERE student_id=%s
                AND subject_id=%s
                AND exam_name=%s
            """, (
                data['student_id'],
                data['subject_id'],
                data['exam_name']
            ))
            existing = cursor.fetchone()

            if existing:
                # Return existing marks info
                # so frontend can ask to update
                return jsonify({
                    'duplicate': True,
                    'existing_id': existing['id'],
                    'existing_marks': existing['marks_obtained'],
                    'existing_max': existing['max_marks'],
                    'message': f"Marks already exist for this "
                               f"subject and exam. "
                               f"Existing: {existing['marks_obtained']}"
                               f"/{existing['max_marks']}"
                }), 409

            # Insert new marks
            cursor.execute(
                """INSERT INTO marks
                   (student_id, subject_id, exam_name,
                    marks_obtained, max_marks)
                   VALUES (%s, %s, %s, %s, %s)""",
                (data['student_id'], data['subject_id'],
                 data['exam_name'], data['marks_obtained'],
                 data['max_marks'])
            )
        conn.commit()
        return jsonify({'message': 'Marks saved successfully'})
    finally:
        conn.close()

# ─── UPDATE MARKS ─────────────────────────────────────────────────
@app.route('/api/v1/marks/<int:mark_id>', methods=['PUT'])
@teacher_required
def update_marks(mark_id):
    data = request.get_json()
    conn = get_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute("""
                UPDATE marks
                SET marks_obtained=%s, max_marks=%s
                WHERE id=%s
            """, (
                data['marks_obtained'],
                data['max_marks'],
                mark_id
            ))
        conn.commit()
        return jsonify({'message': 'Marks updated successfully'})
    finally:
        conn.close()

# ─── DELETE MARKS ─────────────────────────────────────────────────
@app.route('/api/v1/marks/<int:mark_id>', methods=['DELETE'])
@teacher_required
def delete_marks(mark_id):
    conn = get_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute(
                "DELETE FROM marks WHERE id=%s",
                (mark_id,)
            )
        conn.commit()
        return jsonify({'message': 'Marks deleted successfully'})
    finally:
        conn.close()

# ─── REPORT ROUTE ────────────────────────────────────────────────

@app.route('/api/v1/report/<int:student_id>', methods=['GET'])
@jwt_required()
def get_report(student_id):
    conn = get_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute(
                "SELECT name, class_section FROM students WHERE id=%s",
                (student_id,)
            )
            student = cursor.fetchone()
            cursor.execute(
                "SELECT status FROM attendance WHERE student_id=%s",
                (student_id,)
            )
            att = cursor.fetchall()
            total = len(att)
            present = sum(
                1 for a in att if a['status'] == 'Present'
            )
            att_pct = round(
                (present / total * 100), 2
            ) if total > 0 else 0
            cursor.execute(
                """SELECT marks_obtained, max_marks
                   FROM marks WHERE student_id=%s""",
                (student_id,)
            )
            marks = cursor.fetchall()
            avg_marks = round(
                sum(
                    m['marks_obtained'] /
                    m['max_marks'] * 100 for m in marks
                ) / len(marks), 2
            ) if marks else 0

        report = {
            'student': student,
            'attendance_percentage': att_pct,
            'average_marks_percentage': avg_marks,
            'alert': att_pct < 75 or avg_marks < 40
        }
        return jsonify(report)
    finally:
        conn.close()

# ─── NOTIFY ROUTE ────────────────────────────────────────────────

def _send_notify(student_id, conn):
    with conn.cursor() as cursor:
        cursor.execute("""
            SELECT p.name, p.email, p.phone,
                   s.name as student_name,
                   s.class_section
            FROM students s
            JOIN parents p ON s.parent_id = p.id
            WHERE s.id=%s
        """, (student_id,))
        parent = cursor.fetchone()

    if parent and parent['email']:
        try:
            sender_email = os.environ.get('SENDER_EMAIL')
            sender_password = os.environ.get('SENDER_PASSWORD')

            msg = MIMEMultipart()
            msg['From'] = sender_email
            msg['To'] = parent['email']
            msg['Subject'] = (
                f"⚠️ Alert: {parent['student_name']} "
                f"Needs Your Attention"
            )

            body = f"""
Dear {parent['name']},

This is an automated alert from
Dr. Himasekhar Educational Institutions.

Your child {parent['student_name']}
(Class: {parent['class_section']})
requires your attention regarding
academic performance or attendance.

Please contact the class teacher
or visit the school for more details.

Regards,
Dr. Himasekhar Educational Institutions
Vijayawada, Andhra Pradesh
            """

            msg.attach(MIMEText(body, 'plain'))

            server = smtplib.SMTP(
                'smtp.gmail.com', 587
            )
            server.starttls()
            server.login(
                sender_email, sender_password
            )
            server.send_message(msg)
            server.quit()

            print(
                f"✅ Email sent to {parent['email']}"
            )
        except Exception as e:
            print(f"❌ Email failed: {e}")

@app.route('/api/v1/notify', methods=['POST'])
@teacher_required
def notify_parent():
    student_id = request.get_json().get('student_id')
    conn = get_connection()
    try:
        _send_notify(student_id, conn)
        return jsonify({'message': 'Mock notification sent'})
    finally:
        conn.close()

# ─── AI RISK ROUTE ───────────────────────────────────────────────

@app.route('/api/v1/predict-risk/<int:student_id>',
           methods=['POST'])
@jwt_required()
def predict_risk(student_id):
    conn = get_connection()
    try:
        with conn.cursor() as cursor:
            # Get attendance
            cursor.execute(
                "SELECT status FROM attendance WHERE student_id=%s",
                (student_id,)
            )
            att = cursor.fetchall()
            total = len(att)
            present = sum(
                1 for a in att if a['status'] == 'Present'
            )
            att_pct = round(
                (present / total * 100), 2
            ) if total > 0 else 0

            # Get marks
            cursor.execute(
                """SELECT marks_obtained, max_marks
                   FROM marks WHERE student_id=%s
                   ORDER BY id DESC LIMIT 5""",
                (student_id,)
            )
            marks = cursor.fetchall()
            scores = [
                m['marks_obtained'] /
                m['max_marks'] * 100 for m in marks
            ]
            avg_marks = round(
                sum(scores) / len(scores), 2
            ) if scores else 0
            trend = round(
                scores[0] - scores[-1], 2
            ) if len(scores) >= 2 else 0

            # Call risk analyzer
            risk_level, confidence = analyze_risk(
                att_pct, avg_marks, marks_trend=trend
            )

            # Store in risk_flags with correct columns
            cursor.execute(
                """INSERT INTO risk_flags
                   (student_id, risk_level,
                    confidence_score)
                   VALUES (%s, %s, %s)""",
                (student_id, risk_level, confidence)
            )
        conn.commit()

        return jsonify({
            'student_id': student_id,
            'risk_level': risk_level,
            'confidence': confidence,
            'attendance_pct': att_pct,
            'avg_marks': avg_marks
        })
    finally:
        conn.close()

# ─── WELLNESS ROUTE ──────────────────────────────────────────────

@app.route('/api/v1/wellness/log', methods=['POST'])
@jwt_required()
def log_wellness():
    data = request.get_json()
    conn = get_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute(
                """INSERT INTO wellness_logs
                   (student_id, resource_type)
                   VALUES (%s, %s)""",
                (data['student_id'], data['resource_type'])
            )
        conn.commit()
        return jsonify({'message': 'Wellness access logged'})
    finally:
        conn.close()

# ─── GET SUBJECTS BY STUDENT ─────────────────────────────────────
@app.route('/api/v1/subjects/student/<int:student_id>',
           methods=['GET'])
@jwt_required()
def get_subjects_by_student(student_id):
    conn = get_connection()
    try:
        with conn.cursor() as cursor:
            # Get student class section
            cursor.execute(
                "SELECT class_section FROM students WHERE id=%s",
                (student_id,)
            )
            student = cursor.fetchone()
            if not student:
                return jsonify(
                    {'error': 'Student not found'}
                ), 404

            class_section = student['class_section']

            # Get class number from section
            # e.g. "10-A" → 10, "4-B" → 4
            try:
                class_num = int(
                    class_section.split('-')[0]
                )
            except:
                class_num = 6

            # Define subjects based on class
            if class_num <= 5:
                correct_subjects = [
                    'Mathematics',
                    'English',
                    'Telugu',
                    'Science',
                    'Hindi',
                    'Social'
                ]
            else:
                correct_subjects = [
                    'Mathematics',
                    'English',
                    'Telugu',
                    'Physical Science',
                    'Natural Science',
                    'Social',
                    'Hindi'
                ]

            # Delete wrong subjects for this class
            cursor.execute(
                "DELETE FROM subjects WHERE class_section=%s",
                (class_section,)
            )

            # Insert correct subjects
            for subject in correct_subjects:
                cursor.execute(
                    """INSERT INTO subjects
                       (subject_name, class_section)
                       VALUES (%s, %s)""",
                    (subject, class_section)
                )

        conn.commit()

        # Now fetch the freshly inserted subjects
        with conn.cursor() as cursor:
            cursor.execute(
                """SELECT id, subject_name
                   FROM subjects
                   WHERE class_section=%s
                   ORDER BY id""",
                (class_section,)
            )
            subjects = cursor.fetchall()

        return jsonify({'subjects': subjects})
    finally:
        conn.close()

# ─── TEACHER ADD STUDENT ─────────────────────────────────────────
@app.route('/api/v1/teacher/add-student', methods=['POST'])
@teacher_required
def add_student():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    name = data.get('name')
    class_section = data.get('class_section')
    roll_number = data.get('roll_number', '')
    parent_name = data.get('parent_name', '')
    parent_email = data.get('parent_email', '')
    parent_phone = data.get('parent_phone', '')

    if not all([username, password, name, class_section]):
        return jsonify({'error': 'Required fields missing'}), 400

    # Determine subjects based on class number
    try:
        class_num = int(class_section.split('-')[0])
    except:
        class_num = 6

    if class_num <= 5:
        subjects = [
        'Mathematics',
        'English',
        'Telugu',
        'Science',
        'Hindi',
        'Social'
    ]
    else:
        subjects = [
        'Mathematics',
        'English',
        'Telugu',
        'Physical Science',
        'Natural Science',
        'Social',
        'Hindi'
    ]

    hashed = generate_password_hash(password)
    conn = get_connection()
    try:
        with conn.cursor() as cursor:
            # Check username exists
            cursor.execute(
                "SELECT id FROM users WHERE username=%s",
                (username,)
            )
            if cursor.fetchone():
                return jsonify({
                    'error': 'Username already exists'
                }), 409

            # Create user
            cursor.execute(
                """INSERT INTO users
                   (username, password_hash, role, is_approved)
                   VALUES (%s, %s, 'student', 1)""",
                (username, hashed)
            )
            user_id = cursor.lastrowid

            # Create parent if provided
            parent_id = None
            if parent_name and parent_email:
                cursor.execute(
                    """INSERT INTO parents
                       (name, email, phone)
                       VALUES (%s, %s, %s)""",
                    (parent_name, parent_email, parent_phone)
                )
                parent_id = cursor.lastrowid

            # Create student
            cursor.execute(
                """INSERT INTO students
                   (user_id, parent_id, name,
                    class_section, roll_number)
                   VALUES (%s, %s, %s, %s, %s)""",
                (user_id, parent_id, name,
                 class_section, roll_number)
            )

            # Check and insert subjects for this class
            # if not already present
            for subject in subjects:
                cursor.execute(
                    """SELECT id FROM subjects
                       WHERE subject_name=%s
                       AND class_section=%s""",
                    (subject, class_section)
                )
                if not cursor.fetchone():
                    cursor.execute(
                        """INSERT INTO subjects
                           (subject_name, class_section)
                           VALUES (%s, %s)""",
                        (subject, class_section)
                    )

        conn.commit()
        return jsonify({
            'message': f'Student {name} added successfully '
                       f'with {len(subjects)} subjects'
        }), 201
    finally:
        conn.close()

# ─── TEACHER GET THEIR OWN CLASS STUDENTS ONLY ───────────────────
@app.route('/api/v1/teacher/all-students', methods=['GET'])
@teacher_required
def teacher_get_all_students():
    user_id = get_jwt_identity()
    conn = get_connection()
    try:
        with conn.cursor() as cursor:
            # Get teacher record from user_id
            cursor.execute(
                "SELECT id FROM teachers WHERE user_id=%s",
                (user_id,)
            )
            teacher = cursor.fetchone()

            if not teacher:
                return jsonify({'students': [], 'classes': []})

            teacher_id = teacher['id']

            # Get classes assigned to this teacher
            cursor.execute(
                """SELECT class_section
                   FROM teacher_classes
                   WHERE teacher_id=%s
                   ORDER BY class_section""",
                (teacher_id,)
            )
            classes = cursor.fetchall()
            class_sections = [c['class_section'] for c in classes]

            if not class_sections:
                # No classes assigned yet
                return jsonify({
                    'students': [],
                    'classes': [],
                    'message': 'No classes assigned yet. Contact principal.'
                })

            # Get students from assigned classes only
            placeholders = ','.join(
                ['%s'] * len(class_sections)
            )
            cursor.execute(f"""
                SELECT s.id, s.name,
                       s.class_section,
                       s.roll_number,
                       COALESCE(
                         ROUND(
                           SUM(CASE WHEN a.status='Present'
                               THEN 1 ELSE 0 END) /
                           NULLIF(COUNT(a.id), 0) * 100, 2
                         ), 0
                       ) as attendance_pct
                FROM students s
                LEFT JOIN attendance a
                ON s.id = a.student_id
                WHERE s.class_section IN ({placeholders})
                GROUP BY s.id
                ORDER BY s.name ASC
            """, class_sections)

            students = cursor.fetchall()
            return jsonify({
                'students': students,
                'classes': class_sections
            })
    finally:
        conn.close()

# ─── GET STUDENT ID FROM USER ID ─────────────────────────────────
@app.route('/api/v1/auth/me', methods=['GET'])
@jwt_required()
def get_me():
    user_id = get_jwt_identity()
    conn = get_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute(
                "SELECT * FROM users WHERE id=%s",
                (user_id,)
            )
            user = cursor.fetchone()
            if not user:
                return jsonify({'error': 'User not found'}), 404

            result = {
                'user_id': user['id'],
                'username': user['username'],
                'role': user['role']
            }

            if user['role'] == 'student':
                cursor.execute(
                    """SELECT s.id, s.name, s.class_section,
                       s.roll_number
                       FROM students s
                       WHERE s.user_id=%s""",
                    (user_id,)
                )
                student = cursor.fetchone()
                if student:
                    result['student_id'] = student['id']
                    result['name'] = student['name']
                    result['class_section'] = student['class_section']
                    result['roll_number'] = student['roll_number']

            elif user['role'] == 'teacher':
                cursor.execute(
                    """SELECT t.id, t.name, t.email,
                       t.subject_specialization
                       FROM teachers t
                       WHERE t.user_id=%s""",
                    (user_id,)
                )
                teacher = cursor.fetchone()
                if teacher:
                    result['teacher_id'] = teacher['id']
                    result['name'] = teacher['name']
                    result['email'] = teacher['email']

            elif user['role'] == 'principal':
                cursor.execute(
                    """SELECT p.id, p.name, p.email
                       FROM principals p
                       WHERE p.user_id=%s""",
                    (user_id,)
                )
                principal = cursor.fetchone()
                if principal:
                    result['name'] = principal['name']
                    result['email'] = principal['email']

            return jsonify(result)
    finally:
        conn.close()

# ─── CHANGE PASSWORD ──────────────────────────────────────────────
@app.route('/api/v1/auth/change-password', methods=['POST'])
@jwt_required()
def change_password():
    user_id = get_jwt_identity()
    data = request.get_json()
    current_password = data.get('current_password')
    new_password = data.get('new_password')
    confirm_password = data.get('confirm_password')

    if not all([current_password, new_password, confirm_password]):
        return jsonify({'error': 'All fields are required'}), 400

    if new_password != confirm_password:
        return jsonify({'error': 'New passwords do not match'}), 400

    if len(new_password) < 6:
        return jsonify({
            'error': 'Password must be at least 6 characters'
        }), 400

    conn = get_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute(
                "SELECT * FROM users WHERE id=%s",
                (user_id,)
            )
            user = cursor.fetchone()
            if not user:
                return jsonify({'error': 'User not found'}), 404

            if not check_password_hash(
                user['password_hash'], current_password
            ):
                return jsonify({
                    'error': 'Current password is incorrect'
                }), 401

            new_hash = generate_password_hash(new_password)
            cursor.execute(
                "UPDATE users SET password_hash=%s WHERE id=%s",
                (new_hash, user_id)
            )
        conn.commit()
        return jsonify({
            'message': 'Password changed successfully!'
        })
    finally:
        conn.close()

# ─── CHANGE USERNAME ──────────────────────────────────────────────
@app.route('/api/v1/auth/change-username', methods=['POST'])
@jwt_required()
def change_username():
    user_id = get_jwt_identity()
    data = request.get_json()
    new_username = data.get('new_username')
    current_password = data.get('current_password')

    if not all([new_username, current_password]):
        return jsonify({'error': 'All fields are required'}), 400

    if len(new_username) < 4:
        return jsonify({
            'error': 'Username must be at least 4 characters'
        }), 400

    conn = get_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute(
                "SELECT * FROM users WHERE id=%s",
                (user_id,)
            )
            user = cursor.fetchone()
            if not user:
                return jsonify({'error': 'User not found'}), 404

            if not check_password_hash(
                user['password_hash'], current_password
            ):
                return jsonify({
                    'error': 'Current password is incorrect'
                }), 401

            # Check if username already exists
            cursor.execute(
                "SELECT id FROM users WHERE username=%s AND id!=%s",
                (new_username, user_id)
            )
            if cursor.fetchone():
                return jsonify({
                    'error': 'Username already taken'
                }), 409

            cursor.execute(
                "UPDATE users SET username=%s WHERE id=%s",
                (new_username, user_id)
            )
        conn.commit()
        return jsonify({
            'message': 'Username changed successfully! '
                       'Please login again.'
        })
    finally:
        conn.close()

    # ─── DELETE TEACHER ───────────────────────────────────────────────
@app.route('/api/v1/principal/delete-teacher/<int:user_id>',
       methods=['DELETE'])
@principal_required
def delete_teacher(user_id):
    conn = get_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute(
                "SELECT id FROM users WHERE id=%s AND role='teacher'",
                (user_id,)
            )
            if not cursor.fetchone():
                return jsonify({'error': 'Teacher not found'}), 404
            cursor.execute(
                "DELETE FROM users WHERE id=%s",
                (user_id,)
            )
        conn.commit()
        return jsonify({'message': 'Teacher deleted successfully'})
    finally:
        conn.close()

    # ─── DELETE STUDENT ───────────────────────────────────────────────
@app.route('/api/v1/teacher/delete-student/<int:student_id>',
           methods=['DELETE'])
@teacher_required
def delete_student(student_id):
    conn = get_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute(
                "SELECT user_id FROM students WHERE id=%s",
                (student_id,)
            )
            student = cursor.fetchone()
            if not student:
                return jsonify({
                    'error': 'Student not found'
                }), 404
            cursor.execute(
                "DELETE FROM users WHERE id=%s",
                (student['user_id'],)
            )
        conn.commit()
        return jsonify({
            'message': 'Student deleted successfully'
        })
    finally:
        conn.close()

# ─── EDIT STUDENT ─────────────────────────────────────────────────
@app.route('/api/v1/teacher/edit-student/<int:student_id>',
           methods=['PUT'])
@teacher_required
def edit_student(student_id):
    data = request.get_json()
    conn = get_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute(
                """UPDATE students
                   SET name=%s,
                       class_section=%s,
                       roll_number=%s
                   WHERE id=%s""",
                (data.get('name'),
                 data.get('class_section'),
                 data.get('roll_number'),
                 student_id)
            )
        conn.commit()
        return jsonify({
            'message': 'Student updated successfully'
        })
    finally:
        conn.close()

# ─── GET TEACHER'S ASSIGNED CLASSES ──────────────────────────────
@app.route('/api/v1/teacher/my-classes', methods=['GET'])
@teacher_required
def get_teacher_classes():
    user_id = get_jwt_identity()
    conn = get_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute(
                "SELECT id FROM teachers WHERE user_id=%s",
                (user_id,)
            )
            teacher = cursor.fetchone()
            if not teacher:
                return jsonify({'classes': []})

            cursor.execute(
                """SELECT class_section
                   FROM teacher_classes
                   WHERE teacher_id=%s
                   ORDER BY class_section""",
                (teacher['id'],)
            )
            classes = cursor.fetchall()
            return jsonify({'classes': classes})
    finally:
        conn.close()

# ─── PRINCIPAL ASSIGN CLASS TO TEACHER ───────────────────────────
@app.route('/api/v1/principal/assign-class', methods=['POST'])
@principal_required
def assign_class_to_teacher():
    data = request.get_json()
    teacher_id = data.get('teacher_id')
    class_section = data.get('class_section')

    if not teacher_id or not class_section:
        return jsonify({'error': 'teacher_id and class_section required'}), 400

    conn = get_connection()
    try:
        with conn.cursor() as cursor:
            # Check if already assigned
            cursor.execute(
                """SELECT id FROM teacher_classes
                   WHERE teacher_id=%s AND class_section=%s""",
                (teacher_id, class_section)
            )
            if cursor.fetchone():
                return jsonify({
                    'error': 'Class already assigned to this teacher'
                }), 409

            cursor.execute(
                """INSERT INTO teacher_classes
                   (teacher_id, class_section)
                   VALUES (%s, %s)""",
                (teacher_id, class_section)
            )
        conn.commit()
        return jsonify({
            'message': f'Class {class_section} assigned successfully'
        })
    finally:
        conn.close()

# ─── PRINCIPAL REMOVE CLASS FROM TEACHER ─────────────────────────
@app.route('/api/v1/principal/remove-class', methods=['POST'])
@principal_required
def remove_class_from_teacher():
    data = request.get_json()
    teacher_id = data.get('teacher_id')
    class_section = data.get('class_section')

    conn = get_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute(
                """DELETE FROM teacher_classes
                   WHERE teacher_id=%s AND class_section=%s""",
                (teacher_id, class_section)
            )
        conn.commit()
        return jsonify({'message': 'Class removed successfully'})
    finally:
        conn.close()

# ─── PRINCIPAL GET TEACHER'S CLASSES ─────────────────────────────
@app.route('/api/v1/principal/teacher-classes/<int:teacher_id>',
           methods=['GET'])
@principal_required
def get_teacher_assigned_classes(teacher_id):
    conn = get_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute(
                """SELECT class_section
                   FROM teacher_classes
                   WHERE teacher_id=%s
                   ORDER BY class_section""",
                (teacher_id,)
            )
            return jsonify({'classes': cursor.fetchall()})
    finally:
        conn.close()

from risk_analyzer import analyze_risk

if __name__ == '__main__':
    app.run(debug=False)
