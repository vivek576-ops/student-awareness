import numpy as np

def analyze_student_metrics(attendance_pct, avg_marks, marks_trend):
    """
    Separately calculates individual risk levels and exact confidence percentages 
    for Attendance and Academic Performance.
    """
    
    # 1. ── ATTENDANCE RISK ENGINE ──
    if attendance_pct < 60:
        attendance_level = 'HIGH'
        # Scale risk confidence based on how far below the 60% failure threshold they are
        attendance_conf = round(90 + (60 - attendance_pct) * 0.16, 2)
    elif attendance_pct < 75:
        attendance_level = 'MEDIUM'
        # Scale based on distance to the safe 75% baseline
        attendance_conf = round(70 + (75 - attendance_pct) * 1.33, 2)
    else:
        attendance_level = 'LOW'
        attendance_conf = round(80 + (attendance_pct - 75) * 0.8, 2)
        
    # Keep percentages safe between 0% and 100%
    attendance_conf = min(max(attendance_conf, 0.0), 100.0)


    # 2. ── ACADEMIC PERFORMANCE RISK ENGINE ──
    # High Risk if marks are below passing threshold (40%) OR borderline (< 50%) and dropping fast
    if avg_marks < 40:
        academic_level = 'HIGH'
        academic_conf = round(90 + (40 - avg_marks) * 0.25, 2)
    elif avg_marks < 50 and marks_trend <= -10:
        academic_level = 'HIGH'
        academic_conf = 85.0
    # Medium Risk if marks are borderline under B-tier (60%) OR if performance is trending downward
    elif avg_marks < 60 or marks_trend < 0:
        academic_level = 'MEDIUM'
        academic_conf = 75.0 if avg_marks >= 60 else round(70 + (60 - avg_marks) * 1.25, 2)
    else:
        academic_level = 'LOW'
        academic_conf = round(80 + (avg_marks - 60) * 0.5, 2)

    academic_conf = min(max(academic_conf, 0.0), 100.0)

    return {
        "attendance": {"level": attendance_level, "percentage": attendance_conf},
        "academic": {"level": academic_level, "percentage": academic_conf}
    }


def get_universal_guidance(risk_profiles, avg_marks, marks_trend):
    """
    Generates actionable exam blueprints and time-management tips 
    for ALL students depending on their exact scores and tier positions.
    """
    tips = {
        "attendance_advice": "",
        "academic_blueprint": [],
        "performance_note": f"Your calculated terminal average is currently {avg_marks}%."
    }
    
    # --- UNIVERSAL ATTENDANCE GUIDANCE ---
    att_tier = risk_profiles["attendance"]["level"]
    if att_tier == 'HIGH':
        tips["attendance_advice"] = "⚠️ Attendance Alert: You are below the mandatory threshold. Prioritize attending every single lecture this month to maintain regular status."
    elif att_tier == 'MEDIUM':
        tips["attendance_advice"] = "📈 Attendance Tip: Try to minimize minor absences over the next two weeks to comfortably clear the 75% institutional line."
    else:
        tips["attendance_advice"] = "✅ Attendance Status: Excellent consistency! Keep this pace up to ensure complete internal assessment marks."

    # --- UNIVERSAL ACADEMIC BLUEPRINT (For all mark tiers) ---
    acad_tier = risk_profiles["academic"]["level"]
    
    if acad_tier == 'HIGH':
        tips["academic_blueprint"] = [
            "🎯 Next Exam Focus: Target fundamental, high-weightage chapters first instead of chasing complex elective modules.",
            "📚 Action Step: Book a direct review session with your subject teacher this week to clarify foundational doubts.",
            "📝 Mock Strategy: Practice solving basic 2-mark and 5-mark conceptual problems to lock in passing safety margins."
        ]
        
    elif acad_tier == 'MEDIUM':
        tips["academic_blueprint"] = [
            "🎯 Next Exam Focus: Review your past 3 test scripts to flag precisely where points were dropped (e.g., calculation errors vs. missing definitions).",
            "📚 Action Step: Form a quick active-recall study group with peers to practice explaining difficult lecture notes out loud.",
            "📝 Mock Strategy: Solve complete intermediate practice worksheets under a timed clock to improve your speed before exam day."
        ]
        
    else: # LOW RISK (Good students wanting to optimize further or protect their grade)
        if avg_marks >= 90:
            tips["academic_blueprint"] = [
                "🎯 Next Exam Focus: Protect your top positioning by analyzing complex, edge-case application problems that appear in final sections.",
                "📚 Action Step: Consider helping out or mentoring classmates during revision sessions; teaching others is the ultimate mastery technique.",
                "📝 Mock Strategy: Attempt previous years' hardest competitive paper sets to elevate conceptual boundaries."
            ]
        else: # Marks are between 60% and 80%+
            tips["academic_blueprint"] = [
                "🎯 Next Exam Focus: Transition your solid score from a B-grade to an A-grade by polishing documentation structures and diagram presentations.",
                "📚 Action Step: Take regular optional mock assessments to expose minor formatting or timing weaknesses before the final exam.",
                "📝 Mock Strategy: Focus on advanced application questions in your reference textbooks to convert standard knowledge into high marks."
            ]

    # --- ATTACH ADDITIONAL WARNING BASED ON RECENT DROPS ---
    if marks_trend < 0:
        tips["academic_blueprint"].append(f"📉 Improvement Note: Your test trajectory dipped by {abs(marks_trend)}% recently. Ensure you treat the very next chapter test as an immediate turnaround opportunity.")
    elif marks_trend > 5:
        tips["academic_blueprint"].append(f"🚀 Progress Note: Fantastic trend upward! Your marks climbed by {marks_trend}%. Maintain this strategy for the upcoming term.")

    return tips