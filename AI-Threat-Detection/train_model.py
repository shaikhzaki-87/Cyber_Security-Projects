import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
from log_parser import parse_auth_log
from feature_engineering import build_features

pd.set_option("display.max_columns", None)
pd.set_option("display.width", 200)

FEATURE_COLS = ["hour", "is_failed", "time_since_last", "failed_count_1min", "distinct_users_by_ip"]

def detect_anomalies(df):
    X_full = df[FEATURE_COLS]

    # Train only on unique feature combinations — avoids duplicate bursts
    # being treated as a "dense normal cluster" by the model
    X_unique = X_full.drop_duplicates()

    scaler = StandardScaler()
    X_unique_scaled = scaler.fit_transform(X_unique)
    X_full_scaled = scaler.transform(X_full)

    model = IsolationForest(
        n_estimators=200,
        contamination=0.15,
        random_state=42
    )
    model.fit(X_unique_scaled)

    df["anomaly_flag"] = model.predict(X_full_scaled)
    df["anomaly_score"] = model.decision_function(X_full_scaled)

    return df


if __name__ == "__main__":
    df = parse_auth_log()
    df = build_features(df)
    df = detect_anomalies(df)

    df["verdict"] = df["anomaly_flag"].map({1: "Normal", -1: "ANOMALY"})

    print(df[["timestamp", "status", "user", "ip", "time_since_last", "failed_count_1min", "distinct_users_by_ip", "anomaly_score", "verdict"]])
    from report_generator import generate_report
    generate_report(df)
