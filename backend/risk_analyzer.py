import numpy as np

def rule_based_risk(attendance_pct, avg_marks,
                    marks_trend=0):
    """
    PRIMARY method - always runs first.
    HIGH   → attendance < 60% OR marks < 35%
    MEDIUM → attendance < 75% OR marks < 50%
    LOW    → attendance >= 75% AND marks >= 50%
    """
    if attendance_pct < 60 or avg_marks < 35:
        return 'HIGH', 0.95
    if attendance_pct < 75 or avg_marks < 50:
        return 'MEDIUM', 0.80
    return 'LOW', 0.90


_sklearn_available = False
_model = None

try:
    from sklearn.tree import DecisionTreeClassifier

    X_train = np.array([
        # HIGH RISK
        [0,  0,   0],
        [10, 10, -5],
        [20, 15, -10],
        [25, 20, -8],
        [30, 25, -12],
        [30, 33,  0],
        [35, 30, -5],
        [40, 28, -8],
        [45, 32, -6],
        [50, 34, -10],
        [55, 20, -5],
        [58, 40, -8],
        [40, 55, -5],
        [35, 60, -3],
        [80, 20, -5],
        [75, 25, -8],
        [70, 30, -3],
        [85, 15,  0],
        [90, 10,  0],

        # MEDIUM RISK
        [60, 45, -3],
        [65, 48, -2],
        [70, 42, -1],
        [72, 55, -4],
        [68, 50, -2],
        [74, 45,  0],
        [65, 60, -3],
        [70, 52, -2],
        [60, 55,  0],
        [72, 48, -1],
        [80, 42, -2],
        [85, 45, -1],
        [90, 48,  0],
        [65, 70,  2],
        [68, 75,  1],
        [72, 80,  0],
        [62, 65,  1],
        [74, 68,  0],

        # LOW RISK
        [75, 50,  0],
        [76, 55,  1],
        [78, 60,  1],
        [80, 65,  2],
        [82, 68,  2],
        [85, 70,  1],
        [85, 75,  3],
        [88, 78,  3],
        [90, 75,  3],
        [90, 80,  4],
        [90, 85,  5],
        [92, 88,  6],
        [95, 90,  8],
        [87, 82,  3],
        [80, 75,  2],
        [76, 68,  0],
    ])

    y_train = [
        # HIGH (19)
        'HIGH','HIGH','HIGH','HIGH','HIGH',
        'HIGH','HIGH','HIGH','HIGH','HIGH',
        'HIGH','HIGH','HIGH','HIGH','HIGH',
        'HIGH','HIGH','HIGH','HIGH',
        # MEDIUM (18)
        'MEDIUM','MEDIUM','MEDIUM','MEDIUM','MEDIUM',
        'MEDIUM','MEDIUM','MEDIUM','MEDIUM','MEDIUM',
        'MEDIUM','MEDIUM','MEDIUM','MEDIUM','MEDIUM',
        'MEDIUM','MEDIUM','MEDIUM',
        # LOW (16)
        'LOW','LOW','LOW','LOW','LOW',
        'LOW','LOW','LOW','LOW','LOW',
        'LOW','LOW','LOW','LOW','LOW',
        'LOW',
    ]

    _model = DecisionTreeClassifier(
        max_depth=6,
        min_samples_split=2,
        random_state=42
    )
    _model.fit(X_train, y_train)
    _sklearn_available = True

except ImportError:
    _sklearn_available = False


def analyze_risk(attendance_pct, avg_marks,
                 marks_trend=0):
    """
    Returns (risk_level: str, confidence: float)
    Rule-based is PRIMARY — always used.
    ML is secondary — only upgrades risk, never downgrades.
    """
    # Step 1: Rule-based (always)
    rule_level, rule_conf = rule_based_risk(
        attendance_pct, avg_marks, marks_trend
    )

    if not _sklearn_available or _model is None:
        return rule_level, rule_conf

    # Step 2: ML model
    try:
        features = np.array([[
            attendance_pct, avg_marks, marks_trend
        ]])
        ml_level = _model.predict(features)[0]
        ml_conf = float(
            _model.predict_proba(features).max()
        )

        severity = {'LOW': 0, 'MEDIUM': 1, 'HIGH': 2}

        # Use whichever is STRICTER
        if severity.get(rule_level, 0) >= \
           severity.get(ml_level, 0):
            return rule_level, rule_conf
        else:
            return ml_level, round(ml_conf, 2)

    except Exception:
        return rule_level, rule_conf