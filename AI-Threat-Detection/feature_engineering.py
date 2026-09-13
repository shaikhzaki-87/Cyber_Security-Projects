import pandas as pd
from log_parser import parse_auth_log

pd.set_option("display.max_columns", None)
pd.set_option("display.width", 200)

def build_features(df):
    df = df.sort_values("timestamp").reset_index(drop=True)

    df["hour"] = df["timestamp"].dt.hour
    df["is_failed"] = (df["status"] == "Failed").astype(int)
    df["time_since_last"] = (
        df.groupby("ip")["timestamp"].diff().dt.total_seconds().fillna(9999)
    )

    failed_counts = []
    distinct_users = []

    for ip, group in df.groupby("ip"):
        group = group.sort_values("timestamp")
        seen_users = set()
        for _, row in group.iterrows():
            window_start = row["timestamp"] - pd.Timedelta(seconds=60)
            count = group[
                (group["timestamp"] >= window_start) &
                (group["timestamp"] <= row["timestamp"]) &
                (group["is_failed"] == 1)
            ].shape[0]
            failed_counts.append((row.name, count))

            seen_users.add(row["user"])
            distinct_users.append((row.name, len(seen_users)))

    fc_series = pd.Series(dict(failed_counts))
    du_series = pd.Series(dict(distinct_users))

    df["failed_count_1min"] = df.index.map(fc_series)
    df["distinct_users_by_ip"] = df.index.map(du_series)

    return df


if __name__ == "__main__":
    df = parse_auth_log()
    df = build_features(df)
    print(df[["timestamp", "status", "user", "ip", "hour", "time_since_last", "failed_count_1min", "distinct_users_by_ip"]])
