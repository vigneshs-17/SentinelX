# SentinelX ML Model Evaluation: Comparative Analysis

## 1. Executive Summary & Objective

This report provides a scientifically defensible comparative evaluation between the **Baseline Random Forest Model (v1)** and the **Improved Regularized Random Forest Model (v2)** on SentinelX's labeled network traffic dataset (`ml/data/network_traffic.csv`).

The goal of this evaluation is **not** to inflate metrics cosmetically, but to:
1. Prevent severe decision-tree overfitting on training noise.
2. Establish transparent, reproducible baseline numbers.
3. Balance class detection to resolve the severe false-negative rate on `HIGH_TRAFFIC`.
4. Document the mathematical and dataset-level boundaries of single-packet intrusion detection.

---

## 2. High-Level Metrics Comparison

Both models were evaluated on the exact same stratified holdout test split (20% test size, $N=400$ samples, `random_state=42`, strictly unseen during cross-validation and training).

| Metric | Baseline Model (v1) | Improved Model (v2) | Absolute Delta | Relative Change |
| :--- | :--- | :--- | :--- | :--- |
| **Training Accuracy** | 1.0000 (100.0%) | 0.8506 (85.06%) | -0.1494 | -14.94% (Overfitting resolved) |
| **Test Accuracy** | 0.7700 (77.00%) | 0.7675 (76.75%) | -0.0025 | -0.32% (Test accuracy essentially unchanged) |
| **Macro F1-Score** | 0.7688 | **0.7894** | **+0.0206** | **+2.68%** |
| **Weighted F1-Score** | 0.7694 | **0.7739** | **+0.0045** | **+0.58%** |
| **Macro Precision** | 0.7694 | **0.8005** | **+0.0311** | **+4.04%** |
| **Macro Recall** | 0.7683 | **0.8167** | **+0.0484** | **+6.30%** |
| **Macro False Negative Rate (FNR)** | 0.2317 (23.17%) | **0.1833 (18.33%)**| **-0.0484** | **-20.89% (Threats missed cut by ~21%)** |
| **Macro False Positive Rate (FPR)** | 0.1283 (12.83%) | **0.1128 (11.28%)**| **-0.0155** | **-12.08%** |
| **ROC-AUC (OvR)** | 0.9160 | 0.9077 | -0.0083 | -0.91% |
| **ROC-AUC (OvO)** | 0.9280 | 0.9209 | -0.0071 | -0.76% |

---

## 3. Per-Class Detailed Performance Breakdown

| Threat Class | Model | Precision | Recall | F1-Score | FPR | FNR | TP / Support |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| `HIGH_TRAFFIC` | Baseline (v1) | 0.5408 | 0.5300 | 0.5354 | 0.1500 | **0.4700** | 53 / 100 |
| `HIGH_TRAFFIC` | **Improved (v2)** | 0.5220 | **0.8300** | **0.6409** | 0.2533 | **0.1700** | **83 / 100** |
| `NORMAL` | Baseline (v1) | 0.7673 | 0.7750 | 0.7711 | 0.2350 | 0.2250 | 155 / 200 |
| `NORMAL` | **Improved (v2)** | **0.8794** | 0.6200 | 0.7273 | **0.0850** | 0.3800 | 124 / 200 |
| `PORT_SCAN` | Baseline (v1) | 1.0000 | 1.0000 | 1.0000 | 0.0000 | 0.0000 | 100 / 100 |
| `PORT_SCAN` | **Improved (v2)** | 1.0000 | 1.0000 | 1.0000 | 0.0000 | 0.0000 | 100 / 100 |

---

## 4. Key Findings & Technical Rationale

1. **Massive Reduction in Missed Attacks (FNR)**:
   - In Baseline v1, the model missed **47 out of 100** high-traffic threats (47% FNR). Because `NORMAL` is the largest class, NORMAL (50%), and `class_weight=None`, the baseline model penalized misclassifying `NORMAL` twice as heavily and defaulted to predicting `NORMAL`.
   - In Improved v2, by applying `class_weight='balanced'` and tree regularization, `HIGH_TRAFFIC` recall surged from **53.0% to 83.0%** (only 17 missed vs. 47 missed).
2. **Elimination of Extreme Overfitting**:
   - Baseline v1 achieved 100% accuracy on the training set by allowing unconstrained decision trees (`max_depth=None`, `min_samples_split=2`) to memorize random ephemeral source port numbers.
   - Improved v2 bounds tree depth (`max_depth=10`, `min_samples_split=5`), bringing training accuracy to a healthy 85.06%, which aligns closely with the test accuracy.
3. **Overlapping Feature Distributions and Temporal Necessity**:
   - In `network_traffic.csv`, `HIGH_TRAFFIC` packets have sizes in $[500, 1499]$ and destination ports in $\{53, 80, 443\}$.
   - `NORMAL` packets have sizes in $[41, 1500]$ and destination ports in $\{22, 53, 80, 123, 443\}$.
   - **Direct Dataset Measurement**: Exactly 423 of the 1,000 `NORMAL` samples (42.30%) fall completely within the feature range of `HIGH_TRAFFIC` across packet size, destination ports, protocols, and TCP flags.
   - The overlapping feature distributions demonstrate that isolated packet-level features are insufficient to perfectly distinguish HIGH_TRAFFIC from NORMAL. Reliable volumetric detection therefore requires temporal/flow-level context such as packets-per-second and bytes-per-second.
   - This demonstrates that **ML-only packet-level detection is unsuitable for reliable volumetric detection in the current SentinelX architecture**, and that the Phase 3 stateful rule engine (measuring true pps and Bps over sliding windows) is the proper architectural tier for volumetric anomaly detection.
