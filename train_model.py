"""Train and save the Random Forest IDS model."""
import pandas as pd
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder
from sklearn.metrics import classification_report, accuracy_score
import joblib
import os

# Generate dataset if missing
if not os.path.exists('data/network_traffic.csv'):
    import generate_dataset  # noqa

df = pd.read_csv('data/network_traffic.csv')

CATEGORICAL = ['protocol_type', 'service', 'flag']
FEATURES = [
    'duration','protocol_type','service','flag','src_bytes','dst_bytes',
    'land','wrong_fragment','urgent','hot','num_failed_logins','logged_in',
    'num_compromised','root_shell','su_attempted','num_root',
    'num_file_creations','num_shells','num_access_files',
    'count','srv_count','serror_rate','rerror_rate','same_srv_rate',
    'diff_srv_rate','dst_host_count','dst_host_srv_count',
    'dst_host_same_srv_rate','dst_host_diff_srv_rate'
]

encoders = {}
for col in CATEGORICAL:
    le = LabelEncoder()
    df[col] = le.fit_transform(df[col])
    encoders[col] = le

label_enc = LabelEncoder()
df['label_enc'] = label_enc.fit_transform(df['label'])

X = df[FEATURES]
y = df['label_enc']

X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

clf = RandomForestClassifier(n_estimators=100, random_state=42, n_jobs=-1)
clf.fit(X_train, y_train)

y_pred = clf.predict(X_test)
print("Accuracy:", accuracy_score(y_test, y_pred))
print(classification_report(y_test, y_pred, target_names=label_enc.classes_))

os.makedirs('model', exist_ok=True)
joblib.dump({
    'model': clf,
    'encoders': encoders,
    'label_encoder': label_enc,
    'features': FEATURES,
    'categorical': CATEGORICAL
}, 'model/ids_model.pkl')
print("Model saved: model/ids_model.pkl")
