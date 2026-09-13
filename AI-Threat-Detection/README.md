# AI Threat Detection — ML-Based Log Anomaly Detector

A Python tool that applies unsupervised machine learning (Isolation Forest) to SSH authentication logs to detect anomalous login behavior — brute-force attempts, invalid users, and unusual access patterns — without relying on static, rule-based thresholds.

## How it works
1. Parses SSH auth logs (via journalctl export) into structured events
2. Engineers behavioral features: failed-login frequency in rolling windows, time between attempts, distinct usernames tried per IP, hour-of-day
3. Trains an Isolation Forest model on unique feature patterns to establish a "normal" baseline
4. Flags outlier events as anomalies with a severity score
5. Generates a color-coded HTML report summarizing findings

## Why Isolation Forest
Unlike rule-based detection (e.g. "flag if failed_count > 5"), Isolation Forest learns what "normal" looks like from the data itself and flags statistical outliers — making it adaptable to different environments without manually tuning thresholds for every scenario.

## Tech Stack
Python, scikit-learn, pandas, Jinja2

## Usage
```bash
sudo journalctl -u ssh --no-pager > auth_export.log
python3 train_model.py
```
Report generates as `anomaly_report.html`.

## Results (test run)
Out of 32 analyzed login events, the model correctly flagged a 7-attempt brute-force burst and an invalid-username attempt as anomalies, while correctly classifying 24 genuine logins as normal.

## Disclaimer
Tested only against self-owned lab systems for educational purposes.

Author:
Shaikh Zaki 
shaikhzakiii34@gmail.com
LinkedIn: 
https://www.linkedin.com/in/shaikh-zaki-55b493260/
