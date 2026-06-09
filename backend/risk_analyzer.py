import numpy as np

def analyze_student_metrics(attendance_pct, avg_marks, marks_trend=0.0):
    """
    Independently evaluates metrics. Cleans types to prevent string comparison bugs.
    """
    # ── CRITICAL TYPE SAFEGUARDS ──
    try:
        if isinstance(attendance_pct, str):
            attendance_pct = attendance_pct.replace('%', '')
        attendance_pct = float(attendance_pct)
    except (ValueError, TypeError):
        attendance_pct = 0.0

    try:
        if isinstance(avg_marks, str):
            avg_marks = avg_marks.replace('%', '')
        avg_marks = float(avg_marks)
    except (ValueError, TypeError):
        avg_marks = 0.0

    try:
        marks_trend = float(marks_trend)
    except (ValueError, TypeError):
        marks_trend = 0.0

    # 1. ── INDEPENDENT ATTENDANCE EVALUATION ──
    if attendance_pct < 60.0:
        attendance_level = 'HIGH'
        attendance_conf = round(90.0 + (60.0 - attendance_pct) * 0.16, 2)
    elif attendance_pct < 75.0:
        attendance_level = 'MEDIUM'
        attendance_conf = round(70.0 + (75.0 - attendance_pct) * 1.33, 2)
    else:
        attendance_level = 'LOW'
        attendance_conf = round(80.0 + (attendance_pct - 75.0) * 0.8, 2)

    # 2. ── INDEPENDENT ACADEMIC EVALUATION ──
    if avg_marks < 40.0:
        academic_level = 'HIGH'
        academic_conf = round(90.0 + (40.0 - avg_marks) * 0.25, 2)
    elif avg_marks < 50.0 and marks_trend <= -10.0:
        academic_level = 'HIGH'
        academic_conf = 85.0
    elif avg_marks < 60.0 or marks_trend < 0.0:
        academic_level = 'MEDIUM'
        academic_conf = 75.0 if avg_marks >= 60.0 else round(70.0 + (60.0 - avg_marks) * 1.25, 2)
    else:
        academic_level = 'LOW'
        academic_conf = round(80.0 + (avg_marks - 60.0) * 0.5, 2)

    return {
        "attendance": {"level": attendance_level, "percentage": min(max(attendance_conf, 0.0), 100.0)},
        "academic": {"level": academic_level, "percentage": min(max(academic_conf, 0.0), 100.0)}
    }