# AI Cybersecurity Analyzer

An AI-powered cybersecurity platform for **real-time network threat detection, anomaly analysis, alert management, and security monitoring*

The system combines **machine learning, rule-based detection, network packet analysis, FastAPI, MySQL, SQLAlchemy, and Scapy** to identify potentially malicious network activity and store security alerts for further analysis.

---

## 1. Project Overview

Modern networks generate large volumes of traffic that make manual security monitoring difficult. Traditional rule-based intrusion detection systems can identify known attack patterns but may struggle with previously unseen or abnormal behavior.

This project proposes a hybrid AI-based cybersecurity framework that combines:

* Machine Learning classification
* Isolation Forest anomaly detection
* Rule-based threat detection
* Real-time packet capture
* Network traffic feature extraction
* Security alert generation
* MySQL-based alert storage
* FastAPI REST APIs
* WebSocket-based real-time communication

The goal is to provide a practical security monitoring platform capable of detecting both **known threats and anomalous network behavior**.

## 2. Dataset – CICIDS2017

The machine-learning component of this project was developed and evaluated using the **CICIDS2017 (Canadian Institute for Cybersecurity Intrusion Detection System 2017)** dataset.

Official dataset source:

https://www.unb.ca/cic/datasets/ids-2017.html

CICIDS2017 contains realistic benign and malicious network traffic represented using network-flow features. The dataset includes multiple attack categories such as DoS, DDoS, PortScan, Brute Force, Web Attacks, Infiltration, Botnet, and benign traffic.

### Dataset Processing

The raw CICIDS2017 CSV files were cleaned and combined for the machine-learning experiments.

The processed dataset used during the experiments contained approximately:

- **Rows:** 2,522,362
- **Columns:** 79

The preprocessing pipeline included:

1. Loading CICIDS2017 CSV files
2. Combining the relevant traffic records
3. Cleaning missing and invalid values
4. Handling infinite values
5. Removing unnecessary fields
6. Preparing network-flow features
7. Encoding attack labels
8. Separating features and target labels
9. Creating training and testing datasets
10. Saving processed datasets for reproducible experiments

The raw CICIDS2017 dataset is not stored in this GitHub repository because of its large size. Researchers can obtain the original dataset from the official Canadian Institute for Cybersecurity website.

---

## 2. System Architecture

```text
                    Network Traffic
                           |
                           v
                  +------------------+
                  |  Scapy Capture   |
                  +------------------+
                           |
                           v
                  +------------------+
                  | Packet Parser    |
                  +------------------+
                           |
                           v
                  +------------------+
                  | Feature Extractor|
                  +------------------+
                           |
             +-------------+-------------+
             |                           |
             v                           v
      Rule-Based Detection        Machine Learning
             |                           |
             |                    +------+------+
             |                    |             |
             |                    v             v
             |               XGBoost      Isolation Forest
             |                    |             |
             +-------------+------+-------------+
                           |
                           v
                   Threat Decision
                           |
                           v
                   Security Alert
                           |
                           v
                    SQLAlchemy ORM
                           |
                           v
                    MySQL Database
                           |
             +-------------+-------------+
             |                           |
             v                           v
       FastAPI REST API             WebSocket
             |                           |
             +-------------+-------------+
                           |
                           v
                    Security Dashboard
```

---

## 3. Main Features

### AI-Based Threat Detection

The platform uses machine learning to classify network traffic and identify potentially malicious activity.

Current components include:

* XGBoost classification
* Isolation Forest anomaly detection
* Confidence scoring
* Predicted class
* Risk score
* Severity classification

### Rule-Based Detection

The system also contains deterministic security rules for detecting network threats.

Examples include:

* Port scanning
* SYN flooding
* Brute-force activity
* DDoS-related traffic
* Unauthorized access
* Malware-related patterns
* SQL injection
* Cross-site scripting
* Privilege escalation

### Real-Time Packet Analysis

Network packets can be captured using Scapy and processed through the detection pipeline.

```text
Packet
  ↓
Parser
  ↓
Features
  ↓
Rule Detection
  ↓
AI Detection
  ↓
Alert
```

### Security Alert Storage

Detected events are stored in MySQL using SQLAlchemy.

The database currently contains the:

```text
security_alerts
```

table.

Example fields include:

| Field           | Description                      |
| --------------- | -------------------------------- |
| id              | Unique alert identifier          |
| attack_type     | Detected attack or traffic class |
| confidence      | Model confidence                 |
| severity        | Threat severity                  |
| risk_score      | Calculated risk                  |
| predicted_class | ML predicted class               |
| source          | Detection source                 |
| created_at      | Alert creation timestamp         |

---

## 4. Technology Stack

### Backend

* Python
* FastAPI
* Uvicorn
* SQLAlchemy
* PyMySQL

### Machine Learning

* XGBoost
* Scikit-learn
* Isolation Forest
* Pandas
* NumPy

### Network Security

* Scapy
* Packet inspection
* Network feature extraction
* Rule-based IDS techniques

### Database

* MySQL 9.6
* SQLAlchemy ORM

### API / Communication

* REST API
* WebSocket

### Development

* Git
* GitHub
* PowerShell
* Python virtual environment

---

## 5. Project Structure

```text
AI-Cybersecurity-Analyzermodel/
│
├── .gitignore
├── requirements.txt
│
└── backend/
    │
    ├── app/
    │   ├── __init__.py
    │   │
    │   ├── ai/
    │   │   └── isolation_forest.py
    │   │
    │   ├── api/
    │   │   ├── alerts.py
    │   │   ├── auth.py
    │   │   ├── dashboard.py
    │   │   ├── threats.py
    │   │   ├── traffic.py
    │   │   └── websocket.py
    │   │
    │   ├── auth/
    │   │   ├── __init__.py
    │   │   └── password_hashing.py
    │   │
    │   ├── database/
    │   │   ├── __init__.py
    │   │   ├── crud.py
    │   │   ├── database.py
    │   │   ├── models.py
    │   │   └── schemas.py
    │   │
    │   ├── detection/
    │   │   ├── __init__.py
    │   │   └── anomaly_detector.py
    │   │
    │   ├── ml/
    │   │   ├── __init__.py
    │   │   ├── anomaly_model.py
    │   │   ├── isolation_forest.pkl
    │   │   └── train_model.py
    │   │
    │   ├── network/
    │   │   ├── brute_force_detector.py
    │   │   ├── ddos_detector.py
    │   │   ├── features.py
    │   │   ├── firewall.py
    │   │   ├── ids.py
    │   │   ├── logger.py
    │   │   ├── packet_capture.py
    │   │   ├── packet_parser.py
    │   │   ├── port_scan_detector.py
    │   │   ├── protocol_analyzer.py
    │   │   └── traffic_monitor.py
    │   │
    │   ├── models/
    │   │   ├── threat.py
    │   │   ├── traffic.py
    │   │   └── user.py
    │   │
    │   ├── services/
    │   │   ├── ai_service.py
    │   │   ├── alert_service.py
    │   │   └── packet_service.py
    │   │
    │   ├── ai_detect.py
    │   ├── feature_ext.py
    │   ├── main.py
    │   └── user_model.py
    │
    ├── init_db.py
    ├── requirements.txt
    ├── test_db.py
    │
    └── tests/
        ├── __init__.py
        ├── test_capture.py
        └── test_hash.py
```

---

## 6. Installation

### Clone the Repository

```bash
git clone https://github.com/kumud1001/AI-Cybersecurity-Analyzermodel.git
cd AI-Cybersecurity-Analyzermodel
```

### Create a Virtual Environment

Windows:

```powershell
python -m venv .venv
```

Activate it:

```powershell
.\.venv\Scripts\Activate.ps1
```

Alternatively, the project backend can use its dedicated environment:

```powershell
cd backend
.\.venv\Scripts\Activate.ps1
```

### Install Dependencies

```powershell
pip install -r requirements.txt
```

If using the backend requirements:

```powershell
pip install -r backend\requirements.txt
```

---

## 7. Database Configuration

The application uses MySQL.

Create a database:

```sql
CREATE DATABASE ai_cybersecurity;
```

The application configuration should be stored in a local `.env` file.

Example:

```text
DB_USER=root
DB_PASSWORD=YOUR_MYSQL_PASSWORD
DB_HOST=127.0.0.1
DB_PORT=3306
DB_NAME=ai_cybersecurity
```

### Security Notice

The `.env` file must **not** be committed to GitHub.

Never place real database passwords, API keys, or other credentials directly in source code.

---

## 8. Database Initialization

From the backend directory:

```powershell
cd backend
```

Run the database initialization script:

```powershell
python init_db.py
```

The application uses SQLAlchemy to communicate with MySQL.

---

## 9. Start the FastAPI Server

From:

```text
C:\ai-cybersecurity\backend
```

run:

```powershell
python -m uvicorn app.main:app --reload
```

The server should start at:

```text
http://127.0.0.1:8000
```

API documentation:

```text
http://127.0.0.1:8000/docs
```

Alternative documentation:

```text
http://127.0.0.1:8000/redoc
```

---

## 10. API

The FastAPI application provides endpoints for security monitoring and alert management.

The main API areas include:

```text
/alerts
/dashboard
/threats
/traffic
/auth
```

The exact available endpoints can be inspected through:

```text
http://127.0.0.1:8000/docs
```

FastAPI automatically generates interactive API documentation.

---

## 11. Machine Learning Pipeline

The machine learning pipeline processes network traffic features and produces a classification result.

```text
Network Packet
      ↓
Feature Extraction
      ↓
ML Feature Vector
      ↓
XGBoost Model
      ↓
Predicted Class
      ↓
Confidence
      ↓
Risk Score
      ↓
Severity
      ↓
Security Alert
```

Example benign prediction:

```json
{
    "attack_type": "BENIGN",
    "confidence": 0.9961,
    "severity": "LOW",
    "risk_score": 0.0,
    "predicted_class": 0,
    "source": "XGBoost"
}
```

## Experimental Results

Several machine-learning approaches were evaluated using the processed CICIDS2017 network-traffic data.

| Model | Accuracy |
|---|---:|
| Random Forest | 99.17% |
| XGBoost | 99.30% |
| Isolation Forest | 23.32% |
| Hybrid AI Approach | **99.91%** |

### Hybrid AI Performance

The final hybrid approach achieved:

| Metric | Result |
|---|---:|
| Accuracy | **99.91%** |
| Precision | **99.98%** |
| Recall | **99.92%** |
| F1-score | **99.95%** |

The results indicate that combining supervised classification, anomaly detection, and rule-based detection can provide a strong approach for cybersecurity threat identification.

The detailed experimental results are available in:

`thesis results.xlsx`

---

## 12. Anomaly Detection

Isolation Forest is used to identify network behavior that differs significantly from learned normal traffic patterns.

The trained model is stored as:

```text
backend/app/ml/isolation_forest.pkl
```

The anomaly detection process complements the supervised XGBoost classifier.

This creates a hybrid detection architecture:

```text
              Network Traffic
                     |
          +----------+----------+
          |                     |
          v                     v
       XGBoost             Isolation Forest
     Classification          Anomaly Detection
          |                     |
          +----------+----------+
                     |
                     v
              Threat Analysis
```

---

## 13. Rule-Based Detection

The rule engine provides deterministic detection for known traffic patterns.

### Port Scan

Tracks destination ports accessed by a source IP.

Example threshold:

```text
More than 15 unique ports
```

can trigger a port-scan alert.

### SYN Flood

Tracks SYN packets over a time window.

Example threshold:

```text
More than 100 SYN packets
within 10 seconds
```

can trigger a SYN flood alert.

### Alert Deduplication

The detection engine also prevents repeated alerts from overwhelming the monitoring system.

A duplicate alert from the same source and attack type is suppressed for a configured time period.

---

## 14. Real-Time Packet Monitoring

The detection engine can capture packets using Scapy.

The processing pipeline is:

```text
Scapy sniff()
      ↓
parse_packet()
      ↓
extract_features()
      ↓
rule_detection()
      ↓
ml_detection()
      ↓
Security Alert
```

The primary detection engine is:

```text
backend/app/detection/anomaly_detector.py
```

---

## 15. Example Detection Output

Example rule-based detection:

```text
RULE ALERT

{
    "type": "PORT_SCAN",
    "severity": "HIGH",
    "source": "192.168.0.17",
    "message": "Accessed 16 ports"
}
```

Example AI anomaly detection:

```text
AI ANOMALY ALERT

{
    "type": "AI_ANOMALY",
    "severity": "MEDIUM",
    "score": -0.92,
    "message": "Network traffic classified as anomalous"
}
```

---

## 16. Security Alert Database

Example MySQL query:

```sql
USE ai_cybersecurity;

SELECT *
FROM security_alerts
ORDER BY id DESC
LIMIT 10;
```

Example records:

```text
+-----+------------+------------+----------+------------+-----------------+---------+
| id  | attack_type| confidence | severity | risk_score | predicted_class | source  |
+-----+------------+------------+----------+------------+-----------------+---------+
| 115 | BENIGN     | 0.9961     | LOW      | 0          | 0               | XGBoost |
| 114 | BENIGN     | 0.9998     | LOW      | 0          | 0               | XGBoost |
+-----+------------+------------+----------+------------+-----------------+---------+
```

---

## 17. Testing

The project includes tests for network capture and password hashing.

Run:

```powershell
pytest
```

Individual tests can also be executed:

```powershell
pytest backend/tests/test_capture.py
```

```powershell
pytest backend/tests/test_hash.py
```

Database testing can be performed using:

```powershell
python backend/test_db.py
```

---

## 18. Research and Thesis Contribution

This project is designed as an implementation component for a Master's cybersecurity research project.

The main research contribution is the integration of multiple detection approaches into a single cybersecurity architecture.

### Hybrid Detection

The system combines:

1. Supervised machine learning
2. Unsupervised anomaly detection
3. Rule-based intrusion detection
4. Real-time packet analysis
5. Risk scoring
6. Alert persistence

This allows the research to evaluate the differences between traditional rule-based security and AI-based detection.

---

## 19. Proposed Experimental Evaluation

The system can be evaluated using the following metrics:

### Classification Metrics

* Accuracy
* Precision
* Recall
* F1-score
* Confusion matrix
* ROC-AUC

### Security Metrics

* False positive rate
* False negative rate
* Detection rate
* Attack detection latency
* Alert generation rate
* Risk-score distribution

### Operational Metrics

* Processing latency
* Packets processed per second
* Database insertion latency
* API response time
* Memory consumption
* CPU utilization

---

## 20. Attack Categories for Evaluation

The implementation can be evaluated against multiple security scenarios:

| Attack Category      | Detection Method |
| -------------------- | ---------------- |
| Port Scan            | Rule-based + ML  |
| SYN Flood            | Rule-based + ML  |
| DDoS                 | Rule-based + ML  |
| Brute Force          | Rule-based       |
| SQL Injection        | Rule-based       |
| XSS                  | Rule-based       |
| Malware Traffic      | Rule-based + ML  |
| Unauthorized Access  | Rule-based       |
| Privilege Escalation | Rule-based       |
| Unknown Anomaly      | Isolation Forest |

Testing should be performed only in an authorized laboratory or test environment.

---

## 21. Future Improvements

Future versions of the system can include:

* Explainable AI using SHAP
* Advanced feature engineering
* Model calibration
* Real-time dashboard visualization
* Automated incident response
* Threat intelligence integration
* CVE correlation
* MITRE ATT&CK mapping
* Federated learning
* Deep learning models
* LSTM-based sequence analysis
* Model drift detection
* Analyst feedback loops
* Automated report generation

---

## 22. Limitations

The current implementation has several limitations:

* Detection thresholds require further experimental calibration.
* Network datasets may not represent every real-world environment.
* Machine learning performance depends on training-data quality.
* Real-time packet capture may require administrator privileges on Windows.
* Isolation Forest detects statistical anomalies but does not inherently identify the exact attack type.
* Rule-based detection can produce false positives if thresholds are not calibrated.
* The current authentication implementation should be strengthened before production deployment.

---

## 23. Ethical and Legal Considerations

This project is intended for:

* Academic research
* Authorized security testing
* Laboratory experimentation
* Defensive cybersecurity research

Network traffic should only be captured and analyzed on systems and networks where the researcher has explicit authorization.

The platform should not be used to monitor, scan, or attack systems without permission.

---

## 24. Project Status

### Current Implementation

* [x] FastAPI backend
* [x] SQLAlchemy integration
* [x] MySQL integration
* [x] Security alert database
* [x] XGBoost classification
* [x] Isolation Forest model
* [x] Scapy packet processing
* [x] Network feature extraction
* [x] Rule-based detection
* [x] Port-scan detection
* [x] SYN-flood detection
* [x] Alert deduplication
* [x] REST API
* [x] WebSocket components
* [x] Git version control
* [x] GitHub repository

### Planned

* [ ] Complete end-to-end attack experiments
* [ ] Performance benchmarking
* [ ] Confusion matrix generation
* [ ] ROC-AUC evaluation
* [ ] False-positive analysis
* [ ] Explainable AI
* [ ] Final security dashboard
* [ ] Thesis experimental-results chapter

---

## 25. Author

**Kumud Singh**

Master's Research Project in Cybersecurity

AI-Based Cybersecurity Threat Detection and Analysis

---

## 26. Repository

GitHub:

https://github.com/kumud1001/AI-Cybersecurity-Analyzermodel

---

## 27. License

This project is intended primarily for academic and research purposes.

A formal open-source license can be added if the project is later released for public reuse.
