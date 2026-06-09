import numpy as np

def analyze_student_metrics(attendance_pct, avg_marks, marks_trend):
    """
    Separately and independently calculates risk levels and exact confidence percentages 
    for Attendance and Academic Performance.
    """
    # Force convert parameters to floats to prevent string comparison bugs
    try:
        attendance_pct = float(attendance_pct)
        avg_marks = float(avg_marks)
        marks_trend = float(marks_trend)
    except (ValueError, TypeError):
        attendance_pct = 0.0
        avg_marks = 0.0
        marks_trend = 0.0

    # 1. ── INDEPENDENT ATTENDANCE RISK ENGINE ──
    if attendance_pct < 60.0:
        attendance_level = 'HIGH'
        # Scale risk confidence based on how far below 60% they are
        attendance_conf = round(90.0 + (60.0 - attendance_pct) * 0.16, 2)
    elif attendance_pct < 75.0:
        attendance_level = 'MEDIUM'
        # Scale based on distance to the safe 75% baseline
        attendance_conf = round(70.0 + (75.0 - attendance_pct) * 1.33, 2)
    else:
        attendance_level = 'LOW'
        # Higher attendance means a higher confidence that they are safe (LOW risk)
        attendance_conf = round(80.0 + (attendance_pct - 75.0) * 0.8, 2)
        
    attendance_conf = min(max(attendance_conf, 0.0), 100.0)


    # 2. ── INDEPENDENT ACADEMIC RISK ENGINE ──
    if avg_marks < 40.0:
        academic_level = 'HIGH'
        # Lower marks mean a higher confidence that they are strictly at HIGH academic risk
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

    academic_conf = min(max(academic_conf, 0.0), 100.0)

    return {
        "attendance": {"level": attendance_level, "percentage": attendance_conf},
        "academic": {"level": academic_level, "percentage": academic_conf}
    }


def get_universal_guidance(risk_profiles, avg_marks, marks_trend):
    """
    Generates actionable blueprints for ALL students based on their 
    independent risk levels and scores.
    """
    try:
        avg_marks = float(avg_marks)
        marks_trend = float(marks_trend)
    except (ValueError, TypeError):
        pass

    tips = {
        "attendance_advice": "",
        "academic_blueprint": [],
        "performance_note": f"Your calculated terminal average is currently {avg_marks}%."
    }
    
    # Attendance Guidance Block
    att_tier = risk_profiles["attendance"]["level"]
    if att_tier == 'HIGH':
        tips["attendance_advice"] = "⚠️ Attendance Alert: You are below the mandatory threshold. Prioritize attending every single lecture this month to maintain regular status."
    elif att_tier == 'MEDIUM':
        tips["attendance_advice"] = "📈 Attendance Tip: Try to minimize minor absences over the next two weeks to comfortably clear the 75% institutional line."
    else:
        tips["attendance_advice"] = "✅ Attendance Status: Excellent consistency! Keep this pace up to ensure complete internal assessment marks."

    # Academic Guidance Block (Available to all ranges)
    acad_tier = risk_profiles["academic"]["level"]
    if acad_tier == 'HIGH':
        tips["academic_blueprint"] = [
            "🎯 Next Exam Focus: Target fundamental, high-weightage chapters first instead of chasing complex elective modules.",
            "📚 Action Step: Book a direct review session with your subject teacher this week to clarify foundational doubts.",
            "📝 Mock Strategy: Practice solving basic 2-mark and 5-mark conceptual problems to lock in passing safety margins."
        ]
    elif acad_tier == 'MEDIUM':
        tips["academic_blueprint"] = [
            "🎯 Next Exam Focus: Review your past 3 test scripts to flag precisely where points were dropped.",
            "📚 Action Step: Form a quick active-recall study group with peers to practice explaining difficult lecture notes out loud.",
            "📝 Mock Strategy: Solve complete intermediate practice worksheets under a timed clock to improve your speed."
        ]
    else:
        if avg_marks >= 90.0:
            tips["academic_blueprint"] = [
                "🎯 Next Exam Focus: Protect your top positioning by analyzing complex, edge-case application problems.",
                "📚 Action Step: Consider helping out or mentoring classmates during revision sessions to lock in absolute mastery.",
                "📝 Mock Strategy: Attempt previous years' hardest competitive paper sets to elevate conceptual boundaries."
            ]
        else:
            tips["academic_blueprint"] = [
                "🎯 Next Exam Focus: Transition your solid score from a B-grade to an A-grade by polishing documentation structures.",
                "📚 Action Step: Take regular optional mock assessments to expose minor formatting weaknesses before the final exam.",
                "📝 Mock Strategy: Focus on advanced application questions in your reference textbooks to convert standard knowledge into high marks."
            ]

    if marks_trend < 0.0:
        tips["academic_blueprint"].append(f"📉 Improvement Note: Your test trajectory dipped by {abs(marks_trend)}% recently. Ensure you treat the very next chapter test as an immediate turnaround opportunity.")
    elif marks_trend > 5.0:
        tips["academic_blueprint"].append(f"🚀 Progress Note: Fantastic trend upward! Your marks climbed by {marks_trend}%. Maintain this strategy for the upcoming term.")

    return tips