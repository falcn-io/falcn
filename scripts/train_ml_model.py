import numpy as np
import pandas as pd
from sklearn.neural_network import MLPClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report
from skl2onnx import convert_sklearn
from skl2onnx.common.data_types import FloatTensorType
import onnx
import os
import math

def generate_synthetic_data(n_samples=5000):
    # Features:
    # 0: Log(DownloadCount + 1)
    # 1: MaintainerCount
    # 2: AgeInDays
    # 3: DaysSinceLastUpdate
    # 4: VulnerabilityCount
    # 5: MalwareCount
    # 6: VerifiedFlagCount
    
    np.random.seed(42)
    
    # Generate BENIGN data (Class 0)
    n_benign = int(n_samples * 0.9) # 90% benign
    
    # 0: Downloads - Log1p - Benign usually high
    f0_benign = np.random.normal(12.0, 3.0, n_benign) # Mean ~160k downloads
    f0_benign = np.clip(f0_benign, 0, 25)

    # 1: Maintainers - Usually 1-5
    f1_benign = np.random.poisson(2, n_benign) + 1
    
    # 2: Age - Usually old (> 1 year = 365 days)
    f2_benign = np.random.exponential(1000, n_benign) + 30 # Min 30 days
    
    # 3: SinceUpdate - Usually recent (< 1 year)
    f3_benign = np.random.exponential(180, n_benign)
    
    # 4: Vulns - Few
    f4_benign = np.random.poisson(0.5, n_benign)
    
    # 5: Malware - None
    f5_benign = np.zeros(n_benign)
    
    # 6: Flags - None
    f6_benign = np.zeros(n_benign)
    
    X_benign = np.column_stack([f0_benign, f1_benign, f2_benign, f3_benign, f4_benign, f5_benign, f6_benign])
    y_benign = np.zeros(n_benign)

    # Generate MALICIOUS data (Class 1)
    n_mal = n_samples - n_benign
    
    # 0: Downloads - Low
    f0_mal = np.random.normal(4.0, 2.0, n_mal) # Mean ~50 downloads
    f0_mal = np.clip(f0_mal, 0, 10)
    
    # 1: Maintainers - Usually 0 or 1
    f1_mal = np.random.choice([0, 1], n_mal, p=[0.3, 0.7])
    
    # 2: Age - Very new (< 7 days) OR very old (abandoned/hijacked)
    # Split 80% new, 20% hijacked
    n_new = int(n_mal * 0.8)
    n_hijacked = n_mal - n_new
    
    f2_new = np.random.exponential(10, n_new) # Mean 10 days
    f2_hijacked = np.random.normal(2000, 500, n_hijacked) # > 5 years
    f2_mal = np.concatenate([f2_new, f2_hijacked])
    
    # 3: SinceUpdate - Recent for new, Recent for hijacked (pushed malware)
    f3_mal = np.random.exponential(5, n_mal)
    
    # 4: Vulns - Often used as vector, but maybe not reported yet.
    f4_mal = np.random.poisson(0.2, n_mal)
    
    # 5: Malware - Some might be reported
    f5_mal = np.random.choice([0, 1], n_mal, p=[0.9, 0.1]) # 10% already detected
    
    # 6: Flags - Some alerted
    f6_mal = np.random.choice([0, 1], n_mal, p=[0.95, 0.05])
    
    X_mal = np.column_stack([f0_mal, f1_mal, f2_mal, f3_mal, f4_mal, f5_mal, f6_mal])
    y_mal = np.ones(n_mal)
    
    # Combine
    X = np.vstack([X_benign, X_mal])
    y = np.hstack([y_benign, y_mal])
    
    # Add strong signal: If malware or flag is present, ALWAYS malicious (override)
    for i in range(len(y)):
        if X[i, 5] > 0 or X[i, 6] > 0:
            y[i] = 1.0
            
    return X.astype(np.float32), y.astype(np.int64)

def main():
    print("Generating synthetic data...")
    X, y = generate_synthetic_data(10000)
    
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
    
    print(f"Training MLPClassifier on {len(X_train)} samples...")
    # Simple MLP: Input(7) -> Hidden(16) -> Output(2)
    # Use 'relu' activation and 'adam' solver
    clf = MLPClassifier(hidden_layer_sizes=(16,), activation='relu', solver='adam', max_iter=500, random_state=42)
    clf.fit(X_train, y_train)
    
    print("Evaluating model...")
    y_pred = clf.predict(X_test)
    print(classification_report(y_test, y_pred))
    
    # Export to ONNX
    print("Exporting to ONNX...")
    # The input type must match the feature vector (float, [1, 7])
    # onnx-go might prefer fixed batch size
    initial_type = [('float_input', FloatTensorType([1, 7]))]
    # target_opset 12 is widely supported
    onx = convert_sklearn(clf, initial_types=initial_type, target_opset=12)
    
    output_dir = "resources/models"
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)
        
    output_path = os.path.join(output_dir, "reputation_model.onnx")
    with open(output_path, "wb") as f:
        f.write(onx.SerializeToString())
        
    print(f"Model saved to {output_path}")

if __name__ == "__main__":
    main()
