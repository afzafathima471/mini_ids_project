from flask import Flask, render_template, request, jsonify, redirect, url_for, flash, session
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
import pandas as pd
import numpy as np
import joblib
import os
import json

# ── Bootstrap ─────────────────────────────────
BASE = os.path.dirname(os.path.abspath(__file__))

# Generate dataset & train model if not present
if not os.path.exists(os.path.join(BASE, 'data', 'network_traffic.csv')):
    import generate_dataset  # noqa

if not os.path.exists(os.path.join(BASE, 'model', 'ids_model.pkl')):
    import train_model  # noqa

# ── App setup ─────────────────────────────────
app = Flask(__name__)
app.secret_key = 'mini_ids_secret_2024'
os.makedirs(os.path.join(BASE, 'database'), exist_ok=True)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(BASE, 'database', 'ids.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

# ── Models ────────────────────────────────────
class Alert(db.Model):
    id            = db.Column(db.Integer, primary_key=True)
    timestamp     = db.Column(db.DateTime, default=datetime.utcnow)
    src_ip        = db.Column(db.String(20))
    dst_ip        = db.Column(db.String(20))
    protocol      = db.Column(db.String(10))
    attack_type   = db.Column(db.String(50))
    confidence    = db.Column(db.Float)
    severity      = db.Column(db.String(20))
    status        = db.Column(db.String(20), default='new')

class TrafficLog(db.Model):
    id            = db.Column(db.Integer, primary_key=True)
    timestamp     = db.Column(db.DateTime, default=datetime.utcnow)
    src_ip        = db.Column(db.String(20))
    dst_ip        = db.Column(db.String(20))
    protocol      = db.Column(db.String(10))
    service       = db.Column(db.String(20))
    src_bytes     = db.Column(db.Integer)
    dst_bytes     = db.Column(db.Integer)
    prediction    = db.Column(db.String(50))
    confidence    = db.Column(db.Float)

class User(db.Model):
    id            = db.Column(db.Integer, primary_key=True)
    username      = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    created_at    = db.Column(db.DateTime, default=datetime.utcnow)

with app.app_context():
    db.create_all()
    if not User.query.filter_by(username='admin').first():
        admin_user = User(
            username='admin',
            password_hash=generate_password_hash('admin123')
        )
        db.session.add(admin_user)
        db.session.commit()

# ── Load model ────────────────────────────────
bundle      = joblib.load(os.path.join(BASE, 'model', 'ids_model.pkl'))
clf         = bundle['model']
encoders    = bundle['encoders']
label_enc   = bundle['label_encoder']
FEATURES    = bundle['features']
CATEGORICAL = bundle['categorical']

SEVERITY_MAP = {'normal': 'info', 'DoS': 'critical', 'Probe': 'medium',
                'R2L': 'high', 'U2R': 'critical'}

def encode_input(data: dict) -> np.ndarray:
    row = {}
    for f in FEATURES:
        val = data.get(f, 0)
        if f in CATEGORICAL:
            le = encoders[f]
            if val in le.classes_:
                val = le.transform([val])[0]
            else:
                val = 0
        row[f] = val
    return np.array([list(row.values())])

def random_ip():
    import random
    return f"{random.randint(1,254)}.{random.randint(0,254)}.{random.randint(0,254)}.{random.randint(1,254)}"

# ── Routes ────────────────────────────────────
@app.before_request
def require_login():
    if request.endpoint in ('login', 'static'):
        return
    if 'user_id' not in session:
        return redirect(url_for('login'))

@app.route('/')
def index():
    total   = TrafficLog.query.count()
    alerts  = Alert.query.count()
    new_a   = Alert.query.filter_by(status='new').count()
    normal  = TrafficLog.query.filter_by(prediction='normal').count()
    attacks = total - normal
    recent  = Alert.query.order_by(Alert.timestamp.desc()).limit(5).all()
    return render_template('index.html',
        total=total, alerts=alerts, new_alerts=new_a,
        normal=normal, attacks=attacks, recent=recent)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if 'user_id' in session:
        return redirect(url_for('index'))
    error = None
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password_hash, password):
            session['user_id'] = user.id
            session['username'] = user.username
            flash('Logged in successfully.', 'success')
            return redirect(url_for('index'))
        error = 'Invalid username or password.'
        flash(error, 'danger')
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    flash('You have been logged out.', 'success')
    return redirect(url_for('login'))

@app.route('/dashboard')
def dashboard():
    # attack type distribution
    from sqlalchemy import func
    try:
        dist = db.session.query(Alert.attack_type, func.count(Alert.id))\
                         .group_by(Alert.attack_type).all()
        dist_labels = [str(d[0]) if d[0] else "Unknown" for d in dist]
        dist_values = [int(d[1]) if d[1] else 0 for d in dist]
    except Exception as e:
        print(f"Error fetching attack distribution: {e}")
        dist_labels = []
        dist_values = []

    # severity distribution
    try:
        sev = db.session.query(Alert.severity, func.count(Alert.id))\
                        .group_by(Alert.severity).all()
        sev_labels = [str(s[0]) if s[0] else "Unknown" for s in sev]
        sev_values = [int(s[1]) if s[1] else 0 for s in sev]
    except Exception as e:
        print(f"Error fetching severity: {e}")
        sev_labels = []
        sev_values = []

    # last 7 days traffic
    try:
        from sqlalchemy import cast, func as sql_func
        from datetime import datetime, timedelta
        daily_data = db.session.query(
            TrafficLog.timestamp,
            func.count(TrafficLog.id)
        ).filter(TrafficLog.timestamp.isnot(None))\
         .group_by(TrafficLog.timestamp)\
         .order_by(TrafficLog.timestamp.desc())\
         .limit(7).all()
        
        # Group by date and count
        from collections import defaultdict
        daily_dict = defaultdict(int)
        for ts, count in daily_data:
            if ts:
                date_str = ts.strftime('%Y-%m-%d')
                daily_dict[date_str] += count
        
        # Sort chronologically
        sorted_dates = sorted(daily_dict.keys())
        daily_labels = sorted_dates
        daily_values = [daily_dict[d] for d in sorted_dates]
    except Exception as e:
        print(f"Error fetching daily traffic: {e}")
        daily_labels = []
        daily_values = []

    try:
        total   = TrafficLog.query.count() or 0
        alerts  = Alert.query.count() or 0
        new_a   = Alert.query.filter_by(status='new').count() or 0
    except Exception as e:
        print(f"Error fetching stats: {e}")
        total, alerts, new_a = 0, 0, 0

    return render_template('dashboard.html',
        dist_labels=json.dumps(dist_labels),
        dist_values=json.dumps(dist_values),
        sev_labels=json.dumps(sev_labels),
        sev_values=json.dumps(sev_values),
        daily_labels=json.dumps(daily_labels),
        daily_values=json.dumps(daily_values),
        total=total, alerts=alerts, new_alerts=new_a)

@app.route('/analyze', methods=['GET', 'POST'])
def analyze():
    result = None
    if request.method == 'POST':
        if 'csv_file' in request.files and request.files['csv_file'].filename:
            f = request.files['csv_file']
            df = pd.read_csv(f)
            results = []
            for _, row in df.iterrows():
                data = row.to_dict()
                X   = encode_input(data)
                pred_idx  = clf.predict(X)[0]
                pred_prob = clf.predict_proba(X)[0]
                pred_label= label_enc.inverse_transform([pred_idx])[0]
                conf      = float(max(pred_prob))
                results.append({'label': pred_label, 'confidence': round(conf*100,2)})
                src = data.get('src_ip', random_ip())
                dst = data.get('dst_ip', random_ip())
                log = TrafficLog(
                    src_ip=src, dst_ip=dst,
                    protocol=str(data.get('protocol_type','tcp')),
                    service=str(data.get('service','http')),
                    src_bytes=int(data.get('src_bytes',0)),
                    dst_bytes=int(data.get('dst_bytes',0)),
                    prediction=pred_label, confidence=conf)
                db.session.add(log)
                if pred_label != 'normal':
                    alert = Alert(
                        src_ip=src, dst_ip=dst,
                        protocol=str(data.get('protocol_type','tcp')),
                        attack_type=pred_label, confidence=conf,
                        severity=SEVERITY_MAP.get(pred_label,'medium'))
                    db.session.add(alert)
            db.session.commit()
            result = {'type': 'batch', 'data': results}
            flash(f'Analyzed {len(results)} records.', 'success')
        else:
            data = {k: request.form.get(k, 0) for k in FEATURES}
            for k in ['duration','src_bytes','dst_bytes','land','wrong_fragment',
                      'urgent','hot','num_failed_logins','logged_in','num_compromised',
                      'root_shell','su_attempted','num_root','num_file_creations',
                      'num_shells','num_access_files','count','srv_count',
                      'dst_host_count','dst_host_srv_count']:
                try: data[k] = int(data[k])
                except: data[k] = 0
            for k in ['serror_rate','rerror_rate','same_srv_rate','diff_srv_rate',
                      'dst_host_same_srv_rate','dst_host_diff_srv_rate']:
                try: data[k] = float(data[k])
                except: data[k] = 0.0
            X         = encode_input(data)
            pred_idx  = clf.predict(X)[0]
            pred_prob = clf.predict_proba(X)[0]
            pred_label= label_enc.inverse_transform([pred_idx])[0]
            conf      = float(max(pred_prob))
            src = request.form.get('src_ip', random_ip())
            dst = request.form.get('dst_ip', random_ip())
            log = TrafficLog(
                src_ip=src, dst_ip=dst,
                protocol=str(data.get('protocol_type','tcp')),
                service=str(data.get('service','http')),
                src_bytes=int(data.get('src_bytes',0)),
                dst_bytes=int(data.get('dst_bytes',0)),
                prediction=pred_label, confidence=conf)
            db.session.add(log)
            if pred_label != 'normal':
                alert = Alert(
                    src_ip=src, dst_ip=dst,
                    protocol=str(data.get('protocol_type','tcp')),
                    attack_type=pred_label, confidence=conf,
                    severity=SEVERITY_MAP.get(pred_label,'medium'))
                db.session.add(alert)
            db.session.commit()
            result = {
                'type': 'single',
                'label': pred_label,
                'confidence': round(conf*100, 2),
                'severity': SEVERITY_MAP.get(pred_label, 'info'),
                'probabilities': {
                    label_enc.inverse_transform([i])[0]: round(float(p)*100,2)
                    for i, p in enumerate(pred_prob)
                }
            }
    return render_template('analyze.html', result=result)

@app.route('/alerts')
def alerts():
    page   = request.args.get('page', 1, type=int)
    status = request.args.get('status', 'all')
    q      = Alert.query.order_by(Alert.timestamp.desc())
    if status != 'all':
        q = q.filter_by(status=status)
    alerts_page = q.paginate(page=page, per_page=20)
    return render_template('alerts.html', alerts=alerts_page, current_status=status)

@app.route('/alerts/update/<int:alert_id>', methods=['POST'])
def update_alert(alert_id):
    alert = Alert.query.get_or_404(alert_id)
    alert.status = request.form.get('status', alert.status)
    db.session.commit()
    return redirect(url_for('alerts'))

@app.route('/logs')
def logs():
    page  = request.args.get('page', 1, type=int)
    items = TrafficLog.query.order_by(TrafficLog.timestamp.desc()).paginate(page=page, per_page=25)
    return render_template('logs.html', logs=items)

@app.route('/api/simulate', methods=['POST'])
def simulate():
    import random
    protocols = ['tcp','udp','icmp']
    services  = ['http','ftp','smtp','ssh','dns','telnet']
    flags     = ['SF','S0','REJ','RSTO']
    attack_types = ['normal','DoS','Probe','R2L','U2R']
    attack = random.choice(attack_types)
    if attack == 'normal':
        data = dict(duration=random.randint(0,300),protocol_type=random.choice(protocols),
            service=random.choice(services),flag='SF',
            src_bytes=random.randint(100,50000),dst_bytes=random.randint(100,50000),
            land=0,wrong_fragment=0,urgent=0,hot=random.randint(0,5),
            num_failed_logins=0,logged_in=1,num_compromised=0,root_shell=0,
            su_attempted=0,num_root=0,num_file_creations=0,num_shells=0,
            num_access_files=0,count=random.randint(1,50),srv_count=random.randint(1,50),
            serror_rate=round(random.uniform(0,0.1),2),rerror_rate=round(random.uniform(0,0.1),2),
            same_srv_rate=round(random.uniform(0.8,1),2),diff_srv_rate=round(random.uniform(0,0.2),2),
            dst_host_count=random.randint(100,255),dst_host_srv_count=random.randint(50,255),
            dst_host_same_srv_rate=round(random.uniform(0.7,1),2),dst_host_diff_srv_rate=round(random.uniform(0,0.3),2))
    elif attack == 'DoS':
        data = dict(duration=0,protocol_type='tcp',service='http',flag='S0',
            src_bytes=random.randint(0,500),dst_bytes=0,land=0,wrong_fragment=1,urgent=0,
            hot=0,num_failed_logins=0,logged_in=0,num_compromised=0,root_shell=0,
            su_attempted=0,num_root=0,num_file_creations=0,num_shells=0,num_access_files=0,
            count=500,srv_count=500,serror_rate=0.99,rerror_rate=0.0,
            same_srv_rate=1.0,diff_srv_rate=0.0,dst_host_count=255,dst_host_srv_count=255,
            dst_host_same_srv_rate=1.0,dst_host_diff_srv_rate=0.0)
    else:
        data = dict(duration=random.randint(0,10),protocol_type=random.choice(protocols),
            service=random.choice(services),flag=random.choice(flags),
            src_bytes=random.randint(0,2000),dst_bytes=random.randint(0,2000),
            land=0,wrong_fragment=0,urgent=0,hot=random.randint(0,3),
            num_failed_logins=random.randint(0,3),logged_in=0,num_compromised=0,
            root_shell=0,su_attempted=0,num_root=0,num_file_creations=0,num_shells=0,
            num_access_files=0,count=random.randint(50,512),srv_count=random.randint(1,50),
            serror_rate=round(random.uniform(0,0.5),2),rerror_rate=round(random.uniform(0,0.5),2),
            same_srv_rate=round(random.uniform(0,0.5),2),diff_srv_rate=round(random.uniform(0.5,1),2),
            dst_host_count=random.randint(150,255),dst_host_srv_count=random.randint(1,50),
            dst_host_same_srv_rate=round(random.uniform(0,0.3),2),dst_host_diff_srv_rate=round(random.uniform(0.5,1),2))
    src = random_ip(); dst = random_ip()
    X         = encode_input(data)
    pred_idx  = clf.predict(X)[0]
    pred_prob = clf.predict_proba(X)[0]
    pred_label= label_enc.inverse_transform([pred_idx])[0]
    conf      = float(max(pred_prob))
    log = TrafficLog(src_ip=src,dst_ip=dst,
        protocol=str(data.get('protocol_type','tcp')),
        service=str(data.get('service','http')),
        src_bytes=int(data.get('src_bytes',0)),
        dst_bytes=int(data.get('dst_bytes',0)),
        prediction=pred_label,confidence=conf)
    db.session.add(log)
    if pred_label != 'normal':
        alert = Alert(src_ip=src,dst_ip=dst,
            protocol=str(data.get('protocol_type','tcp')),
            attack_type=pred_label,confidence=conf,
            severity=SEVERITY_MAP.get(pred_label,'medium'))
        db.session.add(alert)
    db.session.commit()
    return jsonify({'prediction': pred_label,'confidence': round(conf*100,2),
                    'src_ip': src,'dst_ip': dst,'severity': SEVERITY_MAP.get(pred_label,'info')})

@app.route('/api/stats')
def api_stats():
    from sqlalchemy import func
    total   = TrafficLog.query.count()
    alerts  = Alert.query.count()
    normal  = TrafficLog.query.filter_by(prediction='normal').count()
    dist    = db.session.query(Alert.attack_type,func.count(Alert.id))\
                        .group_by(Alert.attack_type).all()
    return jsonify({'total': total,'alerts': alerts,'normal': normal,
                    'attacks': total-normal,
                    'distribution': {d[0]: d[1] for d in dist}})

if __name__ == '__main__':
    app.run(debug=True)
