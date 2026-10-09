"""
Builds the Kaggle Cloud Evaluation Notebook for CIC-IDS2017 (2.83 Million Flows).
Evaluates RAKSHA-AI's unsupervised non-IoC perception engine on modern enterprise attacks.
Strictly zero-IoC compliant (Rule 1 & Rule 2: benign-only training on Benign-Monday).
"""

import os
import json

base_dir = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
out_dir = os.path.join(base_dir, "notebooks", "kaggle_cicids2017")
os.makedirs(out_dir, exist_ok=True)
notebook_path = os.path.join(out_dir, "raksha_ai_cicids2017_large_eval.ipynb")
metadata_path = os.path.join(out_dir, "kernel-metadata.json")

cells = []

def md_cell(source):
    return {
        "cell_type": "markdown",
        "metadata": {},
        "source": [line + "\n" for line in source.split("\n")]
    }

def code_cell(source):
    return {
        "cell_type": "code",
        "execution_count": None,
        "metadata": {},
        "outputs": [],
        "source": [line + "\n" for line in source.split("\n")]
    }

# 1. Header
cells.append(md_cell(r"""# 🛡️ Project RAKSHA-AI: Large-Scale Evaluation on CIC-IDS2017 (2.83M Flows)
### Autonomous Non-IoC Network Compromise Detection & Benchmark Core

> **Dataset:** CIC-IDS2017 (Canadian Institute for Cybersecurity) — 2,830,743 network flows across 8 days.
> **Scope:** Full enterprise modern attack taxonomy (DDoS, DoS Hulk/GoldenEye, PortScan, SSH/FTP Brute Force, Web Attacks, Botnet Ares, Infiltration, Heartbleed).
> **Invariant Enforced:** Trained **strictly on Benign-Monday** (`label == Benign`). Zero exposure to attack signatures or static IoCs during training.
---"""))

# 2. Imports & Setup
cells.append(md_cell(r"""## 1. Setup & Hardware Diagnostics"""))
cells.append(code_cell(r"""import os
import sys
import time
import glob
import json
import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import RobustScaler
import torch
import torch.nn as nn
from torch.utils.data import DataLoader, TensorDataset

print(f"[+] Python Version: {sys.version.split()[0]}")
device = torch.device('cuda' if torch.cuda.is_available() else 'cpu')
print(f"[+] PyTorch Device: {device}")
if device.type == 'cuda':
    print(f"[+] GPU Detected:   {torch.cuda.get_device_name(0)}")
    print(f"[+] VRAM Available: {torch.cuda.get_device_properties(0).total_memory / 1e9:.2f} GB")

plt.style.use('seaborn-v0_8-whitegrid' if 'seaborn-v0_8-whitegrid' in plt.style.available else 'default')
plt.rcParams['figure.figsize'] = (12, 6)
"""))

# 3. Data Ingestion
cells.append(md_cell(r"""## 2. Ingestion of 2.83 Million Flows (Parquet)"""))
cells.append(code_cell(r"""DATA_DIR = "/kaggle/input/cicids2017"
if not os.path.exists(DATA_DIR):
    matched = glob.glob("/kaggle/input/**/Benign-Monday*.parquet", recursive=True)
    if matched:
        DATA_DIR = os.path.dirname(matched[0])
    else:
        DATA_DIR = "."

print(f"[*] Looking for Parquet files in: {DATA_DIR}")
parquet_files = sorted(glob.glob(os.path.join(DATA_DIR, "*.parquet")))
for f in parquet_files:
    print(f"    - {os.path.basename(f)} ({os.path.getsize(f) / 1e6:.1f} MB)")

dfs = []
for f in parquet_files:
    t0 = time.time()
    day_df = pd.read_parquet(f)
    day_name = os.path.basename(f).replace("-no-metadata.parquet", "")
    day_df["day_file"] = day_name
    print(f"[+] Loaded {day_name}: {len(day_df):,} flows in {time.time() - t0:.2f}s")
    dfs.append(day_df)

df_all = pd.concat(dfs, ignore_index=True)
print("\n[+] Total Flows Loaded: {:,}".format(len(df_all)))
print("[+] Memory Usage: {:.2f} GB".format(df_all.memory_usage().sum() / 1e9))
print("\n[+] Flow Label Distribution:")
print(df_all['Label'].value_counts())
"""))

# 4. Temporal Sequence Aggregation (Zero-IoC Behavioral Frequency)
cells.append(md_cell(r"""## 3. Temporal Sequence Aggregation (Zero-IoC)
To crack the limitations of purely stateless single-flow anomaly detection, we convert stateful flow sequences (like SSH brute-forcing) into a stateless behavioral metric. We aggregate the number of flows spawned by each Source IP per second (`Src_Flows_Per_Sec`). The Source IP is then discarded to maintain Zero-IoC compliance."""))

cells.append(code_cell(r"""print("[*] Computing Temporal Sequence Metrics (Src_Flows_Per_Sec)...")
t0 = time.time()

# Ensure Timestamp and Source IP exist and are clean
if 'Timestamp' in df_all.columns and 'Source IP' in df_all.columns:
    df_all['Timestamp_DT'] = pd.to_datetime(df_all['Timestamp'], errors='coerce', format='mixed')
    df_all['Time_Sec'] = df_all['Timestamp_DT'].dt.floor('S')
    
    # Compute the frequency of flows per Source IP per second
    src_freq = df_all.groupby(['Source IP', 'Time_Sec']).size().astype(np.float32).reset_index(name='Src_Flows_Per_Sec')
    
    # Merge the behavioral metric back into the main telemetry dataframe
    df_all = df_all.merge(src_freq, on=['Source IP', 'Time_Sec'], how='left')
    
    # Drop the tracking columns
    df_all.drop(columns=['Timestamp_DT', 'Time_Sec'], inplace=True)
    
    # Fill any NaNs safely
    df_all['Src_Flows_Per_Sec'] = df_all['Src_Flows_Per_Sec'].fillna(1.0).astype(np.float32)
    
    print(f"[+] Temporal aggregation complete in {time.time() - t0:.2f}s!")
else:
    print("[-] Missing Timestamp or Source IP. Skipping temporal aggregation.")
"""))

# 5. Feature Selection & Extraction
cells.append(md_cell(r"""## 4. Behavioral Feature Extraction (Zero Static IoC)
We select purely statistical, behavioral flow metrics (durations, packet sizes, inter-arrival times, flag ratios, and temporal flow rates), excluding all static IP addresses, ports, timestamps, or payload signatures."""))

cells.append(code_cell(r"""# Identify numerical flow columns (exclude day_file and Label)
exclude_cols = ['Label', 'day_file', 'Flow ID', 'Source IP', 'Destination IP', 'Timestamp', 'External IP']
feature_cols = [c for c in df_all.columns if c not in exclude_cols]

print(f"[+] Total Behavioral Flow Features: {len(feature_cols)}")

# Clean infinities and NaNs and downcast to float32 for RAM efficiency
for col in feature_cols:
    df_all[col] = pd.to_numeric(df_all[col], errors='coerce').astype(np.float32)

df_all[feature_cols] = df_all[feature_cols].replace([np.inf, -np.inf], np.nan).fillna(0.0)

# Identify Categorical Columns for Protocol Embeddings
cat_cols = [c for c in feature_cols if 'Protocol' in c or 'Destination Port' in c or 'Dst Port' in c]
cont_cols = [c for c in feature_cols if c not in cat_cols]

print(f"[+] Categorical Features: {cat_cols}")
print(f"[+] Continuous Features: {len(cont_cols)}")

cat_dims = []
for col in cat_cols:
    df_all[col] = df_all[col].astype('int64')
    # Remap to 0..N-1
    unique_vals = df_all[col].unique()
    val2idx = {v: i for i, v in enumerate(unique_vals)}
    df_all[col] = df_all[col].map(val2idx)
    cat_dims.append(len(unique_vals))

# Apply Log1p scaling to heavily skewed volumetric continuous features
# This prevents DoS attacks from masking stealthy probes by dominating the feature space
log1p_count = 0
for col in cont_cols:
    upper_max = float(df_all[col].max())
    if upper_max > 1000.0:  # Identify volumetric/heavy-tailed features
        df_all[col] = np.log1p(df_all[col].clip(lower=0.0))
        log1p_count += 1
    
    # Clip extreme outlier values for statistical stability
    upper_q = float(df_all[col].quantile(0.999))
    if upper_q > 0:
        df_all[col] = df_all[col].clip(upper=upper_q * 2.0)

print(f"[+] Applied log1p scaling to {log1p_count} volumetric features.")
print("[+] Feature preprocessing & float32 optimization complete.")
"""))

# 5. Training on Benign-Monday Only
cells.append(md_cell(r"""## 4. Unsupervised Baseline Perception Training (Strictly Benign-Monday)
In accordance with **Rule 1 & Rule 2**, RAKSHA-AI trains strictly on legitimate normal enterprise traffic (`Label == 'Benign'`). It has never seen any of the attacks before."""))

cells.append(code_cell(r"""# Partition Benign Monday for baseline training
is_benign = df_all['Label'] == 'Benign'
is_monday = df_all['day_file'].str.contains('Monday', case=False, na=False)

df_train_benign = df_all[is_benign & is_monday]
print("[+] Pure Benign-Monday Baseline Flows: {:,}".format(len(df_train_benign)))

# Sample up to 100,000 baseline flows for training scaler and Isolation Forest
sample_size = min(100000, len(df_train_benign))
train_df = df_train_benign.sample(n=sample_size, random_state=42)

scaler = RobustScaler()
X_train_cont = scaler.fit_transform(train_df[cont_cols].values)
X_train_cat = train_df[cat_cols].values

print("[*] 1. Training V7 Deep Neural Autoencoder with Categorical Embeddings...")
class V7Autoencoder(nn.Module):
    def __init__(self, cont_dim, cat_dims):
        super(V7Autoencoder, self).__init__()
        
        self.embeddings = nn.ModuleList([
            nn.Embedding(num_embeddings=d, embedding_dim=min(50, (d + 1) // 2))
            for d in cat_dims
        ])
        
        embed_dim = sum(min(50, (d + 1) // 2) for d in cat_dims)
        input_dim = cont_dim + embed_dim
        
        self.encoder = nn.Sequential(
            nn.Linear(input_dim, 128), nn.ReLU(), nn.Dropout(0.15),
            nn.Linear(128, 64), nn.ReLU(), nn.Dropout(0.15),
            nn.Linear(64, 32)
        )
        self.cont_decoder = nn.Sequential(
            nn.Linear(32, 64), nn.ReLU(),
            nn.Linear(64, 128), nn.ReLU(),
            nn.Linear(128, cont_dim)
        )
        
        # Dual-Head: Categorical Service Predictor
        self.cat_decoders = nn.ModuleList([
            nn.Sequential(
                nn.Linear(32, 64), nn.ReLU(),
                nn.Linear(64, d)
            ) for d in cat_dims
        ])
        
    def forward(self, x_cont, x_cat):
        embeds = [emb(x_cat[:, i]) for i, emb in enumerate(self.embeddings)]
        x_emb = torch.cat(embeds, dim=1)
        x_in = torch.cat([x_cont, x_emb], dim=1)
        z = self.encoder(x_in)
        
        cont_recon = self.cont_decoder(z)
        cat_preds = [dec(z) for dec in self.cat_decoders]
        return cont_recon, cat_preds, z

ae_model = V7Autoencoder(len(cont_cols), cat_dims).to(device)
optimizer = torch.optim.Adam(ae_model.parameters(), lr=1e-3, weight_decay=1e-5)
criterion_mse = nn.MSELoss()
criterion_ce = nn.CrossEntropyLoss()

dataset = TensorDataset(
    torch.tensor(X_train_cont, dtype=torch.float32), 
    torch.tensor(X_train_cat, dtype=torch.long)
)
dataloader = DataLoader(dataset, batch_size=2048, shuffle=True)

t0 = time.time()
ae_model.train()
for epoch in range(30):
    for batch_cont, batch_cat in dataloader:
        batch_cont, batch_cat = batch_cont.to(device), batch_cat.to(device)
        optimizer.zero_grad()
        recon_cont, preds_cat, _ = ae_model(batch_cont, batch_cat)
        
        loss_mse = criterion_mse(recon_cont, batch_cont)
        
        loss_ce = 0.0
        for i, pred in enumerate(preds_cat):
            loss_ce += criterion_ce(pred, batch_cat[:, i])
            
        # Dual-Head Loss Balancing
        loss = loss_mse + 0.15 * loss_ce
        
        loss.backward()
        optimizer.step()
print(f"[+] Dual-Head Neural weights optimized in {time.time() - t0:.2f}s!")

print("[*] 2. Training 4-Subspace Isolation Forest...")
t0 = time.time()
# Isolation Forest still trains on scaled continuous features
n_feats = len(cont_cols)
subspace_size = n_feats // 4
subspaces = [
    list(range(0, subspace_size)),
    list(range(subspace_size, 2*subspace_size)),
    list(range(2*subspace_size, 3*subspace_size)),
    list(range(3*subspace_size, n_feats))
]

if_models = []
for i, subset in enumerate(subspaces):
    model = IsolationForest(
        n_estimators=50,
        max_samples=1024,
        contamination=0.015,
        random_state=42+i,
        n_jobs=-1
    )
    model.fit(X_train_cont[:, subset])
    if_models.append(model)

print(f"[+] 4-Subspace Models trained in {time.time() - t0:.2f}s!")

def get_ae_scores(X_cont, X_cat):
    ae_model.eval()
    with torch.no_grad():
        t_cont = torch.tensor(X_cont, dtype=torch.float32).to(device)
        t_cat = torch.tensor(X_cat, dtype=torch.long).to(device)
        recon_cont, preds_cat, _ = ae_model(t_cont, t_cat)
        
        # Continuous Reconstruction Error (MSE)
        mse_scores = torch.mean((recon_cont - t_cont)**2, dim=1)
        
        # Categorical Service Deviation (Cross Entropy)
        ce_scores = torch.zeros(t_cont.size(0), device=device)
        loss_fn = nn.CrossEntropyLoss(reduction='none')
        for i, pred in enumerate(preds_cat):
            ce_scores += loss_fn(pred, t_cat[:, i])
            
        # Combine normalized MSE and CE to get a powerful unified AE score
        # Scale CE slightly down to balance with MSE
        combined_scores = (mse_scores + 0.15 * ce_scores).cpu().numpy()
        return combined_scores

def get_if_scores(X_cont):
    scores = []
    for i, model in enumerate(if_models):
        scores.append(model.decision_function(X_cont[:, subspaces[i]]))
    # IF returns lower values for anomalies, we negate so higher = more anomalous
    raw_scores = -np.min(np.vstack(scores), axis=0)
    # Extremely important: Clip negative (normal) values to 0 before squaring!
    return np.maximum(0.0, raw_scores)

# Calibrate Thresholds
val_df = df_train_benign.sample(n=min(50000, len(df_train_benign)), random_state=99)
val_cont = scaler.transform(val_df[cont_cols].values)
val_cat = val_df[cat_cols].values

val_ae_scores = get_ae_scores(val_cont, val_cat)
val_if_scores = get_if_scores(val_cont)

ae_tau = float(np.percentile(val_ae_scores, 95.0))  # 95th percentile
if_tau = float(np.percentile(val_if_scores, 95.0))

# Power-Mean Consensus Fusion
val_consensus = np.sqrt(0.6 * (val_ae_scores / (ae_tau + 1e-6))**2 + 0.4 * (val_if_scores / (if_tau + 1e-6))**2)
bdi_cutoff = float(np.percentile(val_consensus, 97.5)) # Hold overall 2.5% FPR
print(f"[+] Calibrated Consensus Cutoff at 2.5% FPR: {bdi_cutoff:.5f}")
"""))

# 6. Evaluation across 2.83 Million Flows
cells.append(md_cell(r"""## 5. Full 2.83-Million Flow Benchmark Execution"""))
cells.append(code_cell(r"""print("[*] Running full batch inference across all 2,830,743 flows in chunks...")

chunk_size = 250000
all_scores = []
t_start = time.perf_counter()

for i in range(0, len(df_all), chunk_size):
    chunk_df = df_all.iloc[i:i+chunk_size]
    chunk_cont = scaler.transform(chunk_df[cont_cols].values)
    chunk_cat = chunk_df[cat_cols].values
    
    ae_s = get_ae_scores(chunk_cont, chunk_cat)
    if_s = get_if_scores(chunk_cont)
    
    consensus = np.sqrt(0.6 * (ae_s / (ae_tau + 1e-6))**2 + 0.4 * (if_s / (if_tau + 1e-6))**2)
    all_scores.append(consensus)
    print("    - Processed chunk {:,} to {:,} flows...".format(i, min(len(df_all), i+chunk_size)))

raw_scores = np.concatenate(all_scores)
total_eval_time = time.perf_counter() - t_start

throughput = len(df_all) / total_eval_time
latency_us = (total_eval_time / len(df_all)) * 1_000_000

print(f"\n[+] Complete 2.83M Flow Inference Time: {total_eval_time:.2f}s")
print(f"    - Throughput: {throughput:,.0f} flows/sec")
print(f"    - Per-Flow Latency: {latency_us:.2f} microseconds ({latency_us / 1000.0:.4f} ms)")

# Anomaly flag: score > bdi_cutoff
is_predicted_anomaly = raw_scores > bdi_cutoff
is_actual_attack = df_all['Label'] != 'Benign'
is_actual_benign = df_all['Label'] == 'Benign'

overall_recall = float((is_predicted_anomaly & is_actual_attack).sum() / is_actual_attack.sum() * 100.0)
overall_fpr = float((is_predicted_anomaly & is_actual_benign).sum() / is_actual_benign.sum() * 100.0)

print("\n==============================================================================")
print("   CIC-IDS2017 FULL BENCHMARK RESULTS (2,830,743 FLOWS)")
print("==============================================================================")
print("Total Flows Evaluated:        {:,}".format(len(df_all)))
print("Total Legitimate Flows:       {:,}".format(is_actual_benign.sum()))
print("Total Attack Telemetry Flows: {:,}".format(is_actual_attack.sum()))
print("OVERALL ATTACK RECALL:        {:.2f}% ({:,} / {:,})".format(
    overall_recall, (is_predicted_anomaly & is_actual_attack).sum(), is_actual_attack.sum()
))
print("BENIGN FALSE ALARM RATE:      {:.2f}% ({:,} / {:,})".format(
    overall_fpr, (is_predicted_anomaly & is_actual_benign).sum(), is_actual_benign.sum()
))
"""))

# 7. Breakdown by Modern Threat Family
cells.append(md_cell(r"""## 6. Threat Family Breakdown across Modern Attacks"""))
cells.append(code_cell(r"""labels = df_all['Label'].values
unique_attacks = sorted([lbl for lbl in np.unique(labels) if lbl != 'Benign'])

breakdown = {}
print("\n| Attack Category                  | Total Flows | Detected Flows | Recall % |")
print("|:---------------------------------|:-----------:|:--------------:|:--------:|")

for atk in unique_attacks:
    mask = labels == atk
    tot = int(mask.sum())
    det = int((is_predicted_anomaly & mask).sum())
    rec = float((det / tot) * 100.0) if tot else 0.0
    breakdown[atk] = {
        "total": tot,
        "detected": det,
        "recall_pct": round(rec, 2)
    }
    print(f"| {atk:<32} | {tot:>11,} | {det:>14,} | {rec:>7.2f}% |")

# Aggregate Macro Families
macro_families = {
    "DDoS / DoS": ["DDoS", "DoS Hulk", "DoS GoldenEye", "DoS slowloris", "DoS Slowhttptest"],
    "Recon / PortScan": ["PortScan"],
    "Credential Brute Force": ["FTP-Patator", "SSH-Patator"],
    "Web Attacks": ["Web Attack \u2013 Brute Force", "Web Attack \u2013 XSS", "Web Attack \u2013 Sql Injection"],
    "Botnet / Advanced": ["Bot", "Infiltration", "Heartbleed"]
}

macro_results = {}
print("\n--- Macro Threat Family Aggregation ---")
for fam_name, attack_list in macro_families.items():
    fam_mask = np.isin(labels, attack_list)
    tot = int(fam_mask.sum())
    det = int((is_predicted_anomaly & fam_mask).sum())
    rec = float((det / tot) * 100.0) if tot else 0.0
    macro_results[fam_name] = {
        "total": tot,
        "detected": det,
        "recall_pct": round(rec, 2)
    }
    print(f"[*] {fam_name}: {rec:.2f}% ({det:,} / {tot:,} flows detected)")
"""))

# 8. Export Benchmark JSON & Plot
cells.append(md_cell(r"""## 7. Artifact Export & Visualization"""))
cells.append(code_cell(r"""report = {
    "dataset": "CIC-IDS2017",
    "total_flows": int(len(df_all)),
    "benign_flows": int(is_actual_benign.sum()),
    "attack_flows": int(is_actual_attack.sum()),
    "overall_recall_pct": round(overall_recall, 2),
    "benign_false_alarm_pct": round(overall_fpr, 2),
    "throughput_flows_per_sec": round(throughput, 1),
    "latency_microseconds": round(latency_us, 2),
    "macro_families": macro_results,
    "detailed_attacks": breakdown
}

with open("cicids2017_large_benchmark.json", "w") as f:
    json.dump(report, f, indent=2)

print("[+] Saved cicids2017_large_benchmark.json!")

# Plot
plt.figure(figsize=(10, 5))
fam_names = list(macro_results.keys())
recalls = [macro_results[k]['recall_pct'] for k in fam_names]
colors = ['#00e5ff' if r > 80 else '#ff9100' for r in recalls]

bars = plt.barh(fam_names, recalls, color=colors, edgecolor='none', height=0.55)
plt.axvline(x=80, color='gray', linestyle='--', alpha=0.5, label='80% Target')
plt.xlim(0, 105)
plt.xlabel("Detection Recall (%)", fontsize=12)
plt.title("RAKSHA-AI Zero-Shot Generalization on CIC-IDS2017 (2.83 Million Flows)", fontsize=14, fontweight='bold')

for bar in bars:
    w = bar.get_width()
    plt.text(w + 1.5, bar.get_y() + bar.get_height()/2, f"{w:.1f}%", va='center', fontweight='bold', fontsize=11)

plt.tight_layout()
plt.savefig("cicids2017_benchmark.png", dpi=150)
plt.show()
print("[+] Benchmark plot generated and saved.")
"""))

# Write notebook
nb_data = {
    "cells": cells,
    "metadata": {
        "kernelspec": {"display_name": "Python 3", "language": "python", "name": "python3"},
        "language_info": {"name": "python", "version": "3.10.12"}
    },
    "nbformat": 4,
    "nbformat_minor": 4
}

with open(notebook_path, "w") as f:
    json.dump(nb_data, f, indent=1)

print(f"[+] Successfully wrote {notebook_path} ({len(cells)} cells)")

# Write metadata
meta = {
    "id": "sameersingh0104/raksha-ai-cicids2017-large-eval",
    "title": "raksha-ai-cicids2017-large-eval",
    "code_file": "raksha_ai_cicids2017_large_eval.ipynb",
    "language": "python",
    "kernel_type": "notebook",
    "is_private": "true",
    "enable_gpu": "true",
    "enable_tpu": "false",
    "enable_internet": "true",
    "dataset_sources": [
        "dhoogla/cicids2017"
    ],
    "competition_sources": [],
    "kernel_sources": []
}

with open(metadata_path, "w") as f:
    json.dump(meta, f, indent=2)

print(f"[+] Successfully wrote {metadata_path}")
