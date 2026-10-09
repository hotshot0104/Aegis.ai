import re

with open("notebooks/kaggle/build_cicids2017_notebook.py", "r") as f:
    content = f.read()

# Replace Training block
old_train = r"""# Partition Benign Monday for baseline training.*?(?=\ncells\.append\(md_cell\(r\"\"\"## 5\. Full)"""
new_train = r"""# Partition Benign Monday for baseline training
is_benign = df_all['Label'] == 'Benign'
is_monday = df_all['day_file'].str.contains('Monday', case=False, na=False)

df_train_benign = df_all[is_benign & is_monday]
print("[+] Pure Benign-Monday Baseline Flows: {:,}".format(len(df_train_benign)))

# Sample up to 100,000 baseline flows for training scaler and Isolation Forest
sample_size = min(100000, len(df_train_benign))
train_samples = df_train_benign[feature_cols].sample(n=sample_size, random_state=42).values

scaler = RobustScaler()
X_train_scaled = scaler.fit_transform(train_samples)

print("[*] 1. Training V7 Deep Neural Autoencoder (Benign-Monday Only)...")
class V7Autoencoder(nn.Module):
    def __init__(self, input_dim):
        super(V7Autoencoder, self).__init__()
        self.encoder = nn.Sequential(
            nn.Linear(input_dim, 64), nn.ReLU(), nn.Dropout(0.15),
            nn.Linear(64, 32), nn.ReLU(),
            nn.Linear(32, 16)
        )
        self.decoder = nn.Sequential(
            nn.Linear(16, 32), nn.ReLU(),
            nn.Linear(32, 64), nn.ReLU(),
            nn.Linear(64, input_dim)
        )
        
    def forward(self, x):
        z = self.encoder(x)
        return self.decoder(z), z

input_dim = X_train_scaled.shape[1]
ae_model = V7Autoencoder(input_dim).to(device)
optimizer = torch.optim.Adam(ae_model.parameters(), lr=1e-3, weight_decay=1e-5)
criterion = nn.MSELoss()

X_train_tensor = torch.tensor(X_train_scaled, dtype=torch.float32)
dataset = TensorDataset(X_train_tensor, X_train_tensor)
dataloader = DataLoader(dataset, batch_size=2048, shuffle=True)

t0 = time.time()
ae_model.train()
for epoch in range(25):
    for batch_x, _ in dataloader:
        batch_x = batch_x.to(device)
        optimizer.zero_grad()
        recon, _ = ae_model(batch_x)
        loss = criterion(recon, batch_x)
        loss.backward()
        optimizer.step()
print(f"[+] Neural weights optimized in {time.time() - t0:.2f}s!")

print("[*] 2. Training 4-Subspace Isolation Forest...")
t0 = time.time()
n_feats = X_train_scaled.shape[1]
subspace_size = n_feats // 4
subspaces = [
    list(range(0, subspace_size)),
    list(range(subspace_size, 2*subspace_size)),
    list(range(2*subspace_size, 3*subspace_size)),
    list(range(3*subspace_size, n_feats))
]

if_models = []
for i, subset in enumerate(subspaces):
    model = IsolationForest(n_estimators=50, max_samples=1024, contamination=0.015, random_state=42+i, n_jobs=-1)
    model.fit(X_train_scaled[:, subset])
    if_models.append(model)
print(f"[+] 4-Subspace IF Models trained in {time.time() - t0:.2f}s!")

def get_ae_scores(X):
    ae_model.eval()
    with torch.no_grad():
        X_t = torch.tensor(X, dtype=torch.float32).to(device)
        recon, _ = ae_model(X_t)
        return torch.mean((recon - X_t)**2, dim=1).cpu().numpy()

def get_if_scores(X):
    scores = []
    for i, model in enumerate(if_models):
        scores.append(model.decision_function(X[:, subspaces[i]]))
    # IF returns lower values for anomalies, we negate so higher = more anomalous
    return -np.min(np.vstack(scores), axis=0)

# Calibrate Thresholds
val_samples = df_train_benign[feature_cols].sample(n=min(50000, len(df_train_benign)), random_state=99).values
val_scaled = scaler.transform(val_samples)

val_ae_scores = get_ae_scores(val_scaled)
val_if_scores = get_if_scores(val_scaled)

ae_tau = float(np.percentile(val_ae_scores, 95.0))  # 95th percentile
if_tau = float(np.percentile(val_if_scores, 95.0))

# Power-Mean Consensus Fusion
val_consensus = np.sqrt(0.6 * (val_ae_scores / (ae_tau + 1e-6))**2 + 0.4 * (val_if_scores / (if_tau + 1e-6))**2)
bdi_cutoff = float(np.percentile(val_consensus, 97.5)) # Hold overall 2.5% FPR
print(f"[+] Calibrated Consensus Cutoff at 2.5% FPR: {bdi_cutoff:.5f}")
\"\"\"))
"""

content = re.sub(old_train, new_train, content, flags=re.DOTALL)

# Replace inference block
old_infer = r"""for i in range\(0, len\(df_all\), chunk_size\):.*?is_predicted_anomaly = raw_scores < bdi_cutoff"""
new_infer = r"""for i in range(0, len(df_all), chunk_size):
    chunk = df_all[feature_cols].iloc[i:i+chunk_size].values
    chunk_scaled = scaler.transform(chunk)
    
    ae_s = get_ae_scores(chunk_scaled)
    if_s = get_if_scores(chunk_scaled)
    
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
is_predicted_anomaly = raw_scores > bdi_cutoff"""

content = re.sub(old_infer, new_infer, content, flags=re.DOTALL)

with open("notebooks/kaggle/build_cicids2017_notebook.py", "w") as f:
    f.write(content)

print("Notebook generated script patched.")
