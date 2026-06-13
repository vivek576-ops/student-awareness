import numpy as np

# ── Rule-based risk (Primary method) ────────────────────────────
def rule_based_risk(attendance_pct, avg_marks, marks_trend=0):
    """
    Clear threshold-based risk classification:
    HIGH   → attendance < 60% OR marks < 35%
    MEDIUM → attendance < 75% OR marks < 50%
    LOW    → attendance >= 75% AND marks >= 50%
    """
    # HIGH RISK conditions
    if attendance_pct < 60 or avg_marks < 35:
        return 'HIGH', 0.95

    # MEDIUM RISK conditions
    if attendance_pct < 75 or avg_marks < 50:
        return 'MEDIUM', 0.80

    # LOW RISK
    return 'LOW', 0.90


# ── Scikit-learn model ───────────────────────────────────────────
_sklearn_available = False
_model = None

try:
    from sklearn.tree import DecisionTreeClassifier
    from sklearn.preprocessing import LabelEncoder

    # Training data: [attendance%, avg_marks%, trend]
    X_train = np.array([
        # HIGH RISK - very low attendance and marks
        [20, 15, -10],
        [25, 20, -8],
        [30, 25, -12],
        [35, 30, -5],
        [40, 28, -8],
        [45, 32, -6],
        [50, 35, -10],
        [55, 20, -5],
        [30, 40, -8],
        [25, 35, -10],

        # HIGH RISK - very low attendance even if marks ok
        [40, 55, -5],
        [35, 60, -3],
        [45, 50, 0],

        # HIGH RISK - very low marks even if attendance ok
        [80, 20, -5],
        [75, 25, -8],
        [70, 30, -3],

        # MEDIUM RISK
        [60, 45, -3],
        [65, 48, -2],
        [70, 42, -1],
        [72, 55, -4],
        [68, 50, -2],
        [74, 45, 0],
        [65, 60, -3],
        [70, 52, -2],
        [60, 55, 0],
        [72, 48, -1],

        # MEDIUM RISK - attendance ok but marks medium
        [80, 42, -2],
        [85, 45, -1],
        [90, 48, 0],

        # MEDIUM RISK - marks ok but attendance medium
        [65, 70, 2],
        [68, 75, 1],
        [72, 80, 0],

        # LOW RISK - good attendance and marks
        [90, 85, 5],
        [88, 78, 3],
        [95, 90, 8],
        [85, 80, 4],
        [80, 75, 2],
        [92, 88, 6],
        [87, 82, 3],
        [75, 70, 1],
        [78, 72, 2],
        [80, 65, 0],
        [85, 70, 1],
        [90, 75, 3],
        [76, 68, 0],
        [82, 76, 2],
        [88, 84, 4],
    ])

    y_train = [
        # HIGH RISK
        'HIGH','HIGH','HIGH','HIGH','HIGH',
        'HIGH','HIGH','HIGH','HIGH','HIGH',
        'HIGH','HIGH','HIGH',
        'HIGH','HIGH','HIGH',
        # MEDIUM RISK
        'MEDIUM','MEDIUM','MEDIUM','MEDIUM','MEDIUM',
        'MEDIUM','MEDIUM','MEDIUM','MEDIUM','MEDIUM',
        'MEDIUM','MEDIUM','MEDIUM',
        'MEDIUM','MEDIUM','MEDIUM',
        # LOW RISK
        'LOW','LOW','LOW','LOW','LOW',
        'LOW','LOW','LOW','LOW','LOW',
        'LOW','LOW','LOW','LOW','LOW',
    ]

    _model = DecisionTreeClassifier(
        max_depth=5,
        min_samples_split=2,
        random_state=42
    )
    _model.fit(X_train, y_train)
    _sklearn_available = True

except ImportError:
    _sklearn_available = False


# ── Main entry point called by Flask ────────────────────────────
def analyze_risk(attendance_pct, avg_marks,
                 marks_trend=0):
    """
    Returns (risk_level: str, confidence: float)

    Priority:
    1. Rule-based check first (most reliable)
    2. ML model as secondary check
    3. If both disagree use stricter one
    """
    # Always run rule-based first
    rule_level, rule_conf = rule_based_risk(
        attendance_pct, avg_marks, marks_trend
    )

    if not _sklearn_available or _model is None:
        return rule_level, rule_conf

    # Also run ML model
    try:
        features = np.array([[
            attendance_pct, avg_marks, marks_trend
        ]])
        ml_level = _model.predict(features)[0]
        ml_conf = float(
            _model.predict_proba(features).max()
        )

        # Risk severity mapping
        severity = {'LOW': 0, 'MEDIUM': 1, 'HIGH': 2}

        # Use the STRICTER (higher risk) prediction
        # to protect students
        if severity.get(rule_level, 0) >= \
           severity.get(ml_level, 0):
            return rule_level, rule_conf
        else:
            return ml_level, round(ml_conf, 2)

    except Exception:
        return rule_level, rule_conf