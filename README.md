# Network Intrusion Detection System (Mini IDS)

## Requirements

- Python 3.8+
- pip

## Quick Start

```bash
pip install -r requirements.txt
python app.py
```

Open browser: http://127.0.0.1:5000

Default login: `admin` / `admin123`

## Project Structure

```
mini_ids_project/
├── app.py                  # Flask application
├── train_model.py          # Train ML model
├── generate_dataset.py     # Generate sample dataset
├── requirements.txt
├── README.md
├── model/
│   └── ids_model.pkl       # Pre-trained Random Forest model
├── data/
│   └── network_traffic.csv # Sample dataset
├── database/
│   └── ids.db              # SQLite database (auto-created)
├── templates/
│   ├── base.html
│   ├── index.html
│   ├── dashboard.html
│   ├── analyze.html
│   ├── alerts.html
│   └── logs.html
└── static/
    ├── css/
    │   └── style.css
    └── js/
        └── main.js
```

## Features

- Real-time network traffic analysis
- ML-based intrusion detection (Random Forest)
- Alert management dashboard
- Traffic log viewer
- CSV upload for batch analysis
- SQLite-backed alert storage

## ML Model

- Algorithm: Random Forest Classifier
- Features: duration, protocol_type, service, flag, src_bytes, dst_bytes, land,
  wrong_fragment, urgent, hot, num_failed_logins, logged_in, num_compromised,
  root_shell, su_attempted, num_root, num_file_creations, num_shells,
  num_access_files, count, srv_count, serror_rate, rerror_rate, same_srv_rate,
  diff_srv_rate, dst_host_count, dst_host_srv_count, dst_host_same_srv_rate,
  dst_host_diff_srv_rate
- Classes: normal, DoS, Probe, R2L, U2R
