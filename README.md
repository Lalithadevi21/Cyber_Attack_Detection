# 🛡️ Cyber Attack Detection System



### 🚀 Live Demo
(https://static.streamlit.io/badges/streamlit_badge_black_white.svg)](https://cyberattackdetection-crrnv2f73qro723nqeamas.streamlit.app/)



## 📖 About

A Machine Learning-based **Network Intrusion Detection System (NIDS)** that classifies network traffic as **Normal** or **Attack** in real time.

Built using the **UNSW-NB15 dataset** with a **Voting Ensemble** of Random Forest, XGBoost, and Logistic Regression — achieving **98.89% accuracy**.

---

## ✨ Features

- 🔐 **User Authentication** — Register & Login system with hashed passwords
- 🔍 **Real-Time Prediction** — Enter network traffic features and predict instantly
- 🟢 **Normal Traffic Info** — Understand what safe traffic looks like
- 🔴 **Attack Traffic Info** — Learn how malicious traffic differs
- ⚔️ **Attack Types** — Detailed info on 9 attack categories
- 📊 **Business Insights** — Model metrics and real-world impact
- 🛡️ **Prevention Tips** — Cybersecurity best practices

---

## 🤖 Model Performance

| Model | Accuracy | F1-Score | ROC-AUC | MCC |
|-------|----------|----------|---------|-----|
| Random Forest | 98.72% | 98.73% | 0.9981 | 0.9710 |
| XGBoost | 98.41% | 98.42% | 0.9974 | 0.9648 |
| Logistic Regression | 93.15% | 93.17% | 0.9832 | 0.8516 |
| **Voting Ensemble ⭐** | **98.89%** | **98.90%** | **0.9985** | **0.9742** |

> ✅ Best Model: **Voting Ensemble** (RF + XGB + LR, soft voting, weights 3:3:1)

---

## ⚔️ Attack Categories Detected

| # | Attack | Description |
|---|--------|-------------|
| 1 | Fuzzers | Random input injection to crash systems |
| 2 | Analysis | Port scanning & information gathering |
| 3 | Backdoors | Hidden unauthorized access points |
| 4 | DoS | Flooding to make services unavailable |
| 5 | Exploits | Exploiting known software vulnerabilities |
| 6 | Generic | Cryptographic cipher attacks |
| 7 | Reconnaissance | Network mapping & probing |
| 8 | Shellcode | Remote shell via crafted packets |
| 9 | Worms | Self-replicating malware |

---

## 🗂️ Dataset

- **Name:** UNSW-NB15
- **Source:** University of New South Wales, Australia
- **Features:** 42 network traffic features
- **Classes:** Normal + 9 Attack types

---

## 🛠️ Tech Stack

- **Frontend:** Streamlit
- **ML Models:** Scikit-learn, XGBoost
- **Data Processing:** Pandas, NumPy
- **Auth:** SHA-256 password hashing
- **Deployment:** Streamlit Cloud

---

## 📁 Project Structure

```
cyber-attack-detection/
│
├── app.py               # Main Streamlit application
├── model.pkl            # Trained Voting Ensemble model
├── scaler.pkl           # Feature scaler
├── columns.pkl          # Feature column names
├── threshold.pkl        # Custom decision threshold
├── users.json           # User credentials (auto-created)
└── requirements.txt     # Python dependencies
```

---

## ⚙️ Run Locally

```bash
# 1. Clone the repository
git clone https://github.com/YOUR_USERNAME/cyber-attack-detection.git
cd cyber-attack-detection

# 2. Install dependencies
pip install -r requirements.txt

# 3. Run the app
streamlit run app.py
```

---

## 📦 Requirements

```
streamlit
numpy
pandas
scikit-learn
xgboost
pickle-mixin
```

---

## 👤 Author

**LALITHADEVI VITTANALA**


---

