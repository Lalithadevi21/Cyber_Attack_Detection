import streamlit as st
import numpy as np
import pandas as pd
import pickle
import json
import os
import hashlib

# ──────────────────────────────────────────
#  PAGE CONFIG
# ──────────────────────────────────────────
st.set_page_config(page_title="Cyber Attack Detection", page_icon="🛡️", layout="wide")

# ──────────────────────────────────────────
#  LOAD MODEL FILES
# ──────────────────────────────────────────
@st.cache_resource
def load_models():
    try:
        model = pickle.load(open("model.pkl","rb"))
        scaler = pickle.load(open("scaler.pkl","rb"))
        columns = pickle.load(open("columns.pkl","rb"))
        threshold = pickle.load(open("threshold.pkl","rb"))
        return model, scaler, columns, threshold
    except FileNotFoundError as e:
        st.error(f"Model files not found: {e}. Place model.pkl, scaler.pkl, columns.pkl, threshold.pkl in same folder.")
        st.stop()

model, scaler, columns, threshold = load_models()

# ──────────────────────────────────────────
#  USER AUTH
# ──────────────────────────────────────────
USER_FILE = "users.json"

@st.cache_data(ttl=60)
def load_users():
    if os.path.exists(USER_FILE):
        return json.load(open(USER_FILE))
    return {}

def save_users(users):
    json.dump(users, open(USER_FILE,"w"), indent=2)
    load_users.clear()

def hash_pw(p):
    return hashlib.sha256(p.encode()).hexdigest()

if "login" not in st.session_state:
    st.session_state.login = False
    st.session_state.user = ""

# ──────────────────────────────────────────
#  REAL SAMPLE DATA (from your dataset)
# ──────────────────────────────────────────
NORMAL_SAMPLE = {
    'dur': 291.22914019804193, 'proto': 2, 'service': 0, 'state': 4,
    'spkts': 50, 'dpkts': 73, 'sbytes': 36499, 'dbytes': 91977,
    'rate': 460.7152754868763, 'sttl': 135, 'dttl': 73,
    'sload': 7598.237648667272, 'dload': 2400.072737306146,
    'sloss': 7, 'dloss': 1, 'sinpkt': 2.086929620478052,
    'dinpkt': 4.371552660749871, 'sjit': 0.424737057720541,
    'djit': 0.8194244436955327, 'swin': 4028, 'stcpb': 490810,
    'dtcpb': 74729, 'dwin': 21206, 'tcprtt': 0.7399646690272111,
    'synack': 0.3337232081551088, 'ackdat': 0.8278228390218243,
    'smean': 298, 'dmean': 183, 'trans_depth': 7, 'response_body_len': 3442,
    'ct_srv_src': 84, 'ct_state_ttl': 12, 'ct_flw_http_mthd': 9,
    'is_ftp_login': 0, 'ct_ftp_cmd': 3, 'ct_srv_dst': 86,
    'ct_dst_ltm': 3, 'ct_src_ ltm': 96, 'ct_src_dport_ltm': 39,
    'ct_dst_sport_ltm': 89, 'ct_dst_src_ltm': 65, 'is_sm_ips_ports': 0,
    'attack_cat_Backdoors': 0, 'attack_cat_DoS': 0, 'attack_cat_Exploits': 0,
    'attack_cat_Fuzzers': 0, 'attack_cat_Generic': 0, 'attack_cat_Normal': 1,
    'attack_cat_Reconnaissance': 0, 'attack_cat_Shellcode': 0, 'attack_cat_Worms': 0,
}

ATTACK_SAMPLE = {
    'dur': 374.54011884736246, 'proto': 1, 'service': 0, 'state': 0,
    'spkts': 70, 'dpkts': 38, 'sbytes': 45337, 'dbytes': 84540,
    'rate': 154.79113600679096, 'sttl': 111, 'dttl': 138,
    'sload': 1042.9636125537256, 'dload': 2431.728674559306,
    'sloss': 5, 'dloss': 6, 'sinpkt': 5.005420558023951,
    'dinpkt': 4.0292768246140165, 'sjit': 0.2895942306627455,
    'djit': 0.5804247428151784, 'swin': 45954, 'stcpb': 346471,
    'dtcpb': 154451, 'dwin': 64449, 'tcprtt': 0.730420900080599,
    'synack': 0.5454322938865218, 'ackdat': 0.8856551135404577,
    'smean': 134, 'dmean': 359, 'trans_depth': 9, 'response_body_len': 3296,
    'ct_srv_src': 98, 'ct_state_ttl': 56, 'ct_flw_http_mthd': 8,
    'is_ftp_login': 1, 'ct_ftp_cmd': 0, 'ct_srv_dst': 71,
    'ct_dst_ltm': 94, 'ct_src_ ltm': 7, 'ct_src_dport_ltm': 95,
    'ct_dst_sport_ltm': 53, 'ct_dst_src_ltm': 74, 'is_sm_ips_ports': 1,
    'attack_cat_Backdoors': 0, 'attack_cat_DoS': 0, 'attack_cat_Exploits': 0,
    'attack_cat_Fuzzers': 0, 'attack_cat_Generic': 0, 'attack_cat_Normal': 0,
    'attack_cat_Reconnaissance': 0, 'attack_cat_Shellcode': 1, 'attack_cat_Worms': 0,
}

# ──────────────────────────────────────────
#  LOGIN PAGE
# ──────────────────────────────────────────
if not st.session_state.login:
    st.markdown("""<style>[data-testid="stSidebar"] {display: none;}</style>""", unsafe_allow_html=True)
    
    col1, col2, col3 = st.columns([1, 1.5, 1])
    with col2:
        st.markdown("""
        <div style='text-align:center; padding: 40px 0;'>
            <div style='font-size:80px;'>🛡️</div>
            <h1 style='color:#a78bfa; margin: 16px 0; font-size:32px;'>Cyber Attack Detection</h1>
            <p style='color:#94a3b8; font-size:14px;'>🔍 Identify Normal and Malicious Network Traffic</p>
        </div>
        """, unsafe_allow_html=True)

        tab1, tab2 = st.tabs(["🔐 Login","📝 Register"])

        with tab1:
            st.markdown("<div style='padding: 20px;'></div>", unsafe_allow_html=True)
            u = st.text_input("👤 Username", key="login_u")
            p = st.text_input("🔑 Password", type="password", key="login_p")
            
            st.markdown("<div style='padding: 10px;'></div>", unsafe_allow_html=True)
            if st.button("Login →", use_container_width=True, type="primary"):
                if not u or not p:
                    st.error("Please fill in all fields.")
                else:
                    users = load_users()
                    if u in users and users[u] == hash_pw(p):
                        st.session_state.login = True
                        st.session_state.user = u
                        st.rerun()
                    else:
                        st.error("Invalid username or password")

        with tab2:
            st.markdown("<div style='padding: 20px;'></div>", unsafe_allow_html=True)
            u = st.text_input("👤 New Username",  key="reg_u")
            p = st.text_input("🔑 New Password", type="password",  key="reg_p")
            
            st.markdown("<div style='padding: 10px;'></div>", unsafe_allow_html=True)
            if st.button("Register →", use_container_width=True, type="primary"):
                users = load_users()
                if not u or not p:
                    st.error("Please fill in all fields.")
                elif len(u) < 3:
                    st.error("Username must be at least 3 characters.")
                elif u in users:
                    st.error("Username already exists. Choose another.")
                elif len(p) < 6:
                    st.error("Password must be at least 6 characters.")
                else:
                    users[u] = hash_pw(p)
                    save_users(users)
                    st.success(f"✅ Account '{u}' created! Please login.")

# ──────────────────────────────────────────
#  MAIN APP (after login)
# ──────────────────────────────────────────
else:
    with st.sidebar:
        st.markdown("""
        <div style='text-align:center; padding-bottom:20px;'>
            <div style='font-size:32px;'>🛡️</div>
            <h3 style='color:#a78bfa; margin:8px 0 2px;'>WELCOME</h3>
            <p style='color:#6b7280; font-size:12px; margin:0;'></p>
            <p style='color:#94a3b8; font-size:11px; margin-top:8px;'>👤 {}</p>
        </div>
        """.format(st.session_state.user), unsafe_allow_html=True)
        
        st.markdown("---")
        
        st.markdown("<div style='font-size:13px; font-weight:700; color:#a78bfa; margin-bottom:16px;'>📍 NAVIGATION</div>", unsafe_allow_html=True)
        
        page = st.radio("", [
            "🔍 Prediction",
            "🟢 Normal Traffic",
            "🔴 Attack Traffic",
            "⚔️ Attack Types",
            "📊 Business Insights",
            "🛡️ Prevention"
        ], key="nav_page", label_visibility="collapsed")

        st.markdown("---")
        st.markdown("<div style='height:180px;'></div>", unsafe_allow_html=True)
        
        if st.button("🚪 Logout", use_container_width=True):
            st.session_state.login = False
            st.rerun()

    # ──────────────────────────────────────────
    #  PREDICTION PAGE
    # ──────────────────────────────────────────
    if page == "🔍 Prediction":
        st.title("🔍 Network Traffic Prediction")

        col1,col2,col3 = st.columns(3)

        if col1.button("🟢 Auto Fill Normal"):
            for k,v in NORMAL_SAMPLE.items():
                if k in columns:
                    st.session_state[k] = float(v)
            st.rerun()

        if col2.button("🔴 Auto Fill Attack"):
            for k,v in ATTACK_SAMPLE.items():
                if k in columns:
                    st.session_state[k] = float(v)
            st.rerun()

        if col3.button("🔄 Reset"):
            for c in columns:
                st.session_state[c] = 0.0
            st.rerun()

        st.markdown("---")

        groups = [
            ("🕐 Flow & Timing",        ["dur","rate","sttl","dttl"]),
            ("🔢 Protocol",             ["proto","service","state"]),
            ("📦 Packet & Bytes",       ["spkts","dpkts","sbytes","dbytes","sloss","dloss"]),
            ("📡 Load & Jitter",        ["sload","dload","sinpkt","dinpkt","sjit","djit"]),
            ("🔗 TCP",                  ["swin","stcpb","dtcpb","dwin","tcprtt","synack","ackdat"]),
            ("📏 Sizes",                ["smean","dmean","trans_depth","response_body_len"]),
            ("📊 Counters",             ["ct_srv_src","ct_state_ttl","ct_flw_http_mthd","ct_ftp_cmd",
                                         "ct_srv_dst","ct_dst_ltm","ct_src_ ltm","ct_src_dport_ltm",
                                         "ct_dst_sport_ltm","ct_dst_src_ltm"]),
            ("🔒 Flags",                ["is_ftp_login","is_sm_ips_ports"]),
        ]

        for title, feats in groups:
            valid = [f for f in feats if f in columns]
            if not valid:
                continue
            st.markdown(f"### {title}")
            cols_ui = st.columns(4)
            for i, feat in enumerate(valid):
                val = float(st.session_state.get(feat, 0.0))
                with cols_ui[i % 4]:
                    st.number_input(feat, value=val, key=feat, format="%.4f")

        dummy_cols = [c for c in columns if c.startswith("attack_cat_")]
        if dummy_cols:
            st.markdown("### 🏷️ Attack Category")
            st.caption("Auto Fill sets these automatically.")
            cols_ui = st.columns(4)
            for i, feat in enumerate(dummy_cols):
                val = float(st.session_state.get(feat, 0.0))
                label = feat.replace("attack_cat_","")
                with cols_ui[i % 4]:
                    st.number_input(label, value=val, key=feat, min_value=0.0, max_value=1.0, format="%.0f")

        st.markdown("---")

        if st.button("🚀 Predict", use_container_width=True, type="primary"):
            input_vals = [float(st.session_state.get(col, 0.0)) for col in columns]
            input_arr = np.array(input_vals).reshape(1, -1)
            scaled = scaler.transform(input_arr)
            prob_attack = float(model.predict_proba(scaled)[0][1])
            prob_normal = 1.0 - prob_attack

            if prob_attack >= threshold:
                st.error(f"🚨 ATTACK DETECTED ({prob_attack*100:.2f}%)")
                st.write("**Attack Probability:** " + f"{prob_attack*100:.2f}%")
                st.write("**Normal Probability:** " + f"{prob_normal*100:.2f}%")
                st.write("\nThis traffic shows abnormal packet behavior, unusual patterns, or suspicious activity.")
                st.write("It may indicate real-world cyber threats like:")
                st.write("- DDoS/DoS attacks (flooding)")
                st.write("- Intrusion attempts (reconnaissance, exploits)")
                st.write("- Malware activity (backdoors, worms, shellcode)")
                st.write("- Brute force attacks (repeated failed logins)")

            else:
                st.success(f"✅ NORMAL TRAFFIC ({prob_normal*100:.2f}%)")
                st.write("**Normal Probability:** " + f"{prob_normal*100:.2f}%")
                st.write("**Attack Probability:** " + f"{prob_attack*100:.2f}%")
                st.write("\nThis traffic follows stable and expected communication patterns.")
                st.write("It represents normal user activity such as:")
                st.write("- Web browsing (HTTP/HTTPS requests)")
                st.write("- Video streaming (Netflix, YouTube)")
                st.write("- Email communication (SMTP, IMAP)")
                st.write("- File transfers and downloads")
                st.write("- Messaging and chat applications")

            st.markdown("---")
            col1, col2 = st.columns(2)
            with col1:
                st.metric("Normal", f"{prob_normal*100:.2f}%")
                st.progress(prob_normal)
            with col2:
                st.metric("Attack", f"{prob_attack*100:.2f}%")
                st.progress(prob_attack)

    # ──────────────────────────────────────────
    #  NORMAL TRAFFIC PAGE
    # ──────────────────────────────────────────
    elif page == "🟢 Normal Traffic":
        st.title("🟢 Normal Traffic")

        col1, col2 = st.columns(2)
        with col1:
            st.subheader("What is Normal Traffic?")
            st.write("Normal traffic refers to safe and legitimate network communication.")
            st.write("Data flows in a proper request-response pattern without suspicious spikes or anomalies.")
            st.write("**Key Characteristics:**")
            st.write("- Stable flow duration and consistent packet rates")
            st.write("- Balanced source and destination byte exchange")
            st.write("- Complete TCP handshake (SYN → SYN-ACK → ACK)")
            st.write("- Low or zero packet loss")
            st.write("- Consistent connection patterns over time")

        with col2:
            st.subheader("Real-Life Examples")
            st.write("1. **Web Browsing** — Opening websites (Google, YouTube). Browser sends request, server responds.")
            st.write("2. **Email** — Sending/receiving emails via SMTP/IMAP protocols.")
            st.write("3. **Video Streaming** — Netflix or YouTube with stable, predictable data flow.")
            st.write("4. **File Transfer** — Downloading files with consistent speeds.")
            st.write("5. **Chat Apps** — WhatsApp, Teams messages with small, frequent packets.")

        st.markdown("---")
        st.subheader("Real Dataset Sample (Normal Row)")
        df_normal = pd.DataFrame([NORMAL_SAMPLE])
        st.dataframe(df_normal, use_container_width=True)

    # ──────────────────────────────────────────
    #  ATTACK TRAFFIC PAGE
    # ──────────────────────────────────────────
    elif page == "🔴 Attack Traffic":
        st.title("🔴 Attack Traffic")

        col1, col2 = st.columns(2)
        with col1:
            st.subheader("What is Attack Traffic?")
            st.write("Attack traffic is malicious or suspicious network activity.")
            st.write("It can damage systems, steal data, or make services unavailable.")
            st.write("**Key Characteristics:**")
            st.write("- Unusual flow duration or extreme packet rates")
            st.write("- Imbalanced or one-sided packet flow")
            st.write("- High packet loss or retransmissions")
            st.write("- Unusual TTL or TCP state mismatches")
            st.write("- Repeated connections to same IP/port")

        with col2:
            st.subheader("💡 Real-Time Example")
            st.write("**Scenario:** Exam results released → 10,000 students visit website at once (NORMAL).")
            st.write("\nBut if a **script refreshes 10,000 times/second**, it floods the server.")
            st.write("\nServer **cannot handle real students** → crashes. This is **DoS attack**.")
            st.write("\n**Attack signatures detected:**")
            st.write("- dur = 0 (instant flood, no real session)")
            st.write("- spkts = high, dpkts = 0 (no server response)")
            st.write("- sloss = 1 (packets dropped)")
            st.write("- rate = 0 (no real connection)")

        st.markdown("---")
        st.subheader("Real Dataset Sample (Shellcode Attack Row)")
        df_attack = pd.DataFrame([ATTACK_SAMPLE])
        st.dataframe(df_attack, use_container_width=True)

    # ──────────────────────────────────────────
    #  ATTACK TYPES PAGE
    # ──────────────────────────────────────────
    elif page == "⚔️ Attack Types":
        st.title("⚔️ Cyber Attack Types")
        st.write("The dataset contains 9 attack categories + Normal traffic (10 classes total).")

        attacks = [
            ("Fuzzers", "Sending random/invalid inputs to crash or expose vulnerabilities.",
             "Typing random symbols in login form to crash server.", "High spkts, random sbytes, short dur"),
            ("Analysis", "Port scanning, spam, HTML injection for information gathering.",
             "Using Nmap to scan all open ports before attacking.", "Many short connections, varying ports"),
            ("Backdoors", "Hidden access points that bypass authentication.",
             "Malware opening a secret login door for return access.", "is_ftp_login=1, long dur, unusual service"),
            ("DoS-Denial Of Service", "Flooding system with traffic to make it unavailable.",
             "Script refreshing website 10,000 times/second until crash.", "dur≈0, spkts high, dpkts=0, sloss=1"),
            ("Exploits", "Taking advantage of known software vulnerabilities.",
             "Using unpatched Windows bug to execute malicious code.", "Abnormal state, unusual sbytes"),
            ("Generic", "Attacks targeting encryption algorithms.",
             "Brute-forcing encrypted messages to find secret key.", "Specific protocol patterns"),
            ("Reconnaissance", "Scanning and probing to map target network.",
             "Attacker mapping all devices on company network.", "High ct_dst_ltm, ct_src_ltm"),
            ("Shellcode", "Malicious code placed in exploits to open remote shell.",
             "Crafted packet opens terminal on victim's computer.", "is_ftp_login=1, is_sm_ips_ports=1"),
            ("Worms", "Self-replicating malware spreading automatically.",
             "WannaCry infected 200,000 computers in 150 countries in 1 day.", "High ct_dst_src_ltm, spreading patterns"),
        ]

        for name, definition, example, signs in attacks:
            with st.expander(f"⚡ {name}"):
                st.write(f"**Definition:** {definition}")
                st.write(f"**Real Example:** {example}")
                st.write(f"**Key Feature Signs:** {signs}")

    # ──────────────────────────────────────────
    #  BUSINESS INSIGHTS PAGE
    # ──────────────────────────────────────────
    elif page == "📊 Business Insights":
        st.title("📊 Business Insights")

        col1, col2, col3, col4 = st.columns(4)
        col1.metric("Average Breach Cost", "$4.45M", "Per incident")
        col2.metric("Global Cybercrime", "$8 Trillion", "Annual cost")
        col3.metric("DoS Cost", "$20K–$40K/hr", "Revenue loss")
        col4.metric("Detection Time", "207 days", "Global average")

        st.markdown("---")

        st.subheader("Why Detection Systems Matter")
        st.write("1. **Prevent Financial Loss** — Early detection stops attacks before damage. Banks detecting DoS in seconds vs hours saves millions in downtime.")
        st.write("2. **Protect Customer Data** — One breach = GDPR fines up to 4% of annual revenue + reputation damage.")
        st.write("3. **Real-Time Response** — This ML model predicts attacks in milliseconds. Security teams get instant alerts instead of discovering breaches days later.")
        st.write("4. **Reduce Insurance Costs** — Proven cybersecurity can reduce cyber insurance premiums by 20–30%.")
        st.write("5. **Competitive Advantage** — Customers trust companies that protect data. ISO 27001, SOC 2 certifications require active threat detection.")
        st.write("6. **Compliance** — GDPR, HIPAA, PCI-DSS all require active monitoring. This system helps meet legal obligations.")

        st.markdown("---")
        st.subheader("Model Performance Metrics")
        perf_data = {
            "Model": ["Random Forest", "XGBoost", "Logistic Regression", "Voting Ensemble ⭐"],
            "Accuracy": ["98.72%", "98.41%", "93.15%", "98.89%"],
            "F1-Score": ["98.73%", "98.42%", "93.17%", "98.90%"],
            "ROC-AUC": ["0.9981", "0.9974", "0.9832", "0.9985"],
            "MCC": ["0.9710", "0.9648", "0.8516", "0.9742"],
        }
        st.dataframe(pd.DataFrame(perf_data), use_container_width=True, hide_index=True)
        st.success("Best Model: Voting Ensemble combines RF + XGB + LR with soft voting (weights 3:3:1) and tuned threshold.")

    # ──────────────────────────────────────────
    #  PREVENTION PAGE
    # ──────────────────────────────────────────
    elif page == "🛡️ Prevention":
        st.title("🛡️ Cyber Attacks Prevention")

        st.subheader("For Organizations")
        st.write("1. **Deploy IDS/IPS** — Install intrusion detection systems like this ML model to monitor network 24/7.")
        st.write("2. **Network Segmentation** — Divide network into zones; if one zone is hacked, others remain safe.")
        st.write("3. **Regular Updates** — Patch systems immediately to block known exploits.")
        st.write("4. **Access Control** — Use strong passwords, multi-factor authentication, role-based access.")
        st.write("5. **Employee Training** — Teach staff to recognize phishing, social engineering, suspicious emails.")
        st.write("6. **Backup Systems** — Regular backups protect against ransomware attacks.")
        st.write("7. **Incident Response Plan** — Have a documented plan for handling security breaches.")

        st.subheader("For Individuals")
        st.write("1. **Strong Passwords** — Use 12+ character passwords with mix of uppercase, lowercase, numbers, symbols.")
        st.write("2. **Two-Factor Authentication** — Enable 2FA on all important accounts (email, banking, social media).")
        st.write("3. **Avoid Public WiFi** — Don't access banking or sensitive data on public networks.")
        st.write("4. **Update Software** — Keep OS, browsers, antivirus updated to latest versions.")
        st.write("5. **Phishing Awareness** — Don't click suspicious links or download unknown files.")
        st.write("6. **VPN Usage** — Use VPN to encrypt internet traffic on public networks.")
        st.write("7. **Regular Backups** — Back up important files to external storage or cloud.")