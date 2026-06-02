import numpy as np

def rule_based_risk(attendance_pct, avg_marks, marks_trend):
    score = 0
    if attendance_pct < 60: score += 3
    elif attendance_pct < 75: score += 2

    if avg_marks < 35: score += 3
    elif avg_marks < 50: score += 2

    if marks_trend < -10: score += 2
    elif marks_trend < 0: score += 1

    if score >= 6: return 'HIGH', 0.95
    elif score >= 3: return 'MEDIUM', 0.75
    else: return 'LOW', 0.90

try:
    from sklearn.tree import DecisionTreeClassifier

    X_train = np.array([
        [90, 85, 5], [88, 78, 2], [95, 90, 8],
        [70, 55, -5], [65, 48, -8], [72, 60, 0],
        [50, 30, -15], [45, 25, -20], [55, 35, -12],
        [80, 70, 3], [75, 65, -2], [60, 45, -6]
    ])
    y_train = [
        'LOW','LOW','LOW',
        'MEDIUM','MEDIUM','MEDIUM',
        'HIGH','HIGH','HIGH',
        'LOW','MEDIUM','MEDIUM'
    ]
    _model = DecisionTreeClassifier(max_depth=4, random_state=42)
    _model.fit(X_train, y_train)
    _sklearn_available = True
except ImportError:
    _sklearn_available = False

def analyze_risk(attendance_pct, avg_marks, marks_trend):
    if _sklearn_available:
        features = np.array([[attendance_pct, avg_marks, marks_trend]])
        label = _model.predict(features)[0]
        proba = _model.predict_proba(features).max()
        return label, round(float(proba), 2)
    else:
        return rule_based_risk(attendance_pct, avg_marks, marks_trend)