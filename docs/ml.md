# ForensiTrace Machine Learning & Anomaly Detection Specification (v1.0)

**Contract Status:** FROZEN  
**Owners:** AKASH (Model & Engine), PURVA (Data & API), DAKSH (Baselines & Scenarios), CHETNA (Dashboard)

---

## 1. Overview & Hybrid Philosophy

ForensiTrace implements a hybrid architecture combining declarative, explainable correlation rules with a sequence-based machine learning anomaly detector.

- **Rules Provide Explainability:** Declarative rules (R1 through R7 in `rules.yaml`) establish explicit causal chains, linking evidence across USB, File System, and Windows Event Logs. Every assertion is backed by concrete event IDs and raw records.
- **Machine Learning Provides Contextual Anomaly Detection:** A lightweight LSTM autoencoder trained exclusively on normal baseline workstation activity evaluates sequences of events. It scores how atypical a pattern is based on reconstruction error.
- **Independent Coexistence:** The ML score **never replaces** rule confidence. Both scores are preserved and exposed side-by-side in the API, the React dashboard, and the formal forensic report.
- **Terminology Rule:** The anomaly score represents normalized sequence reconstruction error between `0.0` and `1.0`. It is never described as a "percentage of risk" or "probability of attack."

---

## 2. Feature Vector & Sliding Window Contract

### 2.1 Dynamic Input Vector Size
The feature vector dimension $D$ is **dynamically derived** from the canonical actions in `docs/schema.md` plus 3 continuous/contextual indicators:
$$\text{Vector Dimension } D = |\text{Actions}| + 3$$

Hardcoding the vector size is strictly prohibited. The feature extractor reads the schema at initialization.

### 2.2 Feature Definitions

| Index / Slice | Feature Description | Encoding / Formula |
| :--- | :--- | :--- |
| `0` to `|Actions|-1` | **Action One-Hot Vector** | One binary flag ($0$ or $1$) for each canonical action (`DEVICE_ARRIVED`, `DEVICE_REMOVED`, `FILE_CREATED`, `FILE_MODIFIED`, `FILE_DELETED`, `FILE_MOVED`, `PROCESS_STARTED`, `LOG_CLEARED`, `USER_LOGON`, `HEARTBEAT`). |
| `|Actions|` | **Time Delta to Previous Event** | $\log(1.0 + \Delta t)$, where $\Delta t$ is the elapsed seconds since the preceding event in the sequence. For the first event, $\Delta t = 0$. |
| `|Actions| + 1` | **Executable File Flag** | $1$ if the target entity path ends in an executable/script extension (`.exe`, `.bat`, `.ps1`, `.cmd`, `.vbs`, `.dll`, `.scr`, `.msi`), otherwise $0$. |
| `|Actions| + 2` | **Removable Drive Flag** | $1$ if the entity path resides on a drive letter other than the system root (`C:`), e.g., `E:\`, `D:\`, or indicates a removable storage device, otherwise $0$. |

### 2.3 Sliding Window
- **Window Size ($N$):** $10$ consecutive chronological events.
- **Step Size:** 1 event (sliding window over the host event stream).
- **Minimum Sequence:** Sequences shorter than 3 events are padded with neutral zero-vectors.

---

## 3. Model Architecture (PyTorch LSTM Autoencoder)

The anomaly detector is implemented in PyTorch (`engine/ml/model.py`) and packaged for low-footprint execution:

1. **Encoder:**
   - Input shape: $(B, N, D)$ where $B$ is batch size, $N = 10$, $D = |\text{Actions}| + 3$.
   - Layer: Single-layer or 2-layer LSTM with hidden dimension $H = 32$.
   - Latent representation: Hidden state $h_N \in \mathbb{R}^{B \times H}$.
2. **Decoder:**
   - Layer: LSTM initialized with latent vector, unrolling $N$ steps to reconstruct $(B, N, D)$.
   - Linear projection: Fully connected layer mapping from hidden dimension back to $D$.
3. **Loss Function:**
   - Mean Squared Error (MSE) between input sequence $X$ and reconstructed sequence $\hat{X}$:
     $$\text{MSE}(X, \hat{X}) = \frac{1}{N \cdot D} \sum_{i=1}^{N} \sum_{j=1}^{D} (X_{i,j} - \hat{X}_{i,j})^2$$
4. **Hardware Execution:**
   - Default: CPU execution (guarantees portability across student and evaluation laptops).
   - Optional: GPU execution via CUDA if available, with automatic CPU fallback.

---

## 4. Score Normalization, Combined Index & Threat Levels

### 4.1 Score Normalization
Raw reconstruction errors vary by model parameters. Errors are normalized into the interval $[0.0, 1.0]$ using a validation-derived threshold:
- $\tau$ (**Threshold**): The 99th percentile of reconstruction error on the held-out **validation set** of normal workstation activity.
- Normalization mapping:
  $$\text{score}(e) = \begin{cases} 
  0.5 \times \frac{e}{\tau} & \text{if } e < \tau \\ 
  0.5 + 0.5 \times \min\left(1.0, \frac{e - \tau}{\tau}\right) & \text{if } e \ge \tau 
  \end{cases}$$
- This guarantees that normal baseline activity scores below $0.50$, an error matching threshold $\tau$ scores exactly $0.50$, and an error $\ge 2\tau$ scores $1.00$.

### 4.2 Activity ML Anomaly Score
For an activity $A$ comprising evidence events $E_A = \{e_1, e_2, \dots, e_k\}$:
$$\text{ml\_anomaly\_score}(A) = \max_{W \cap E_A \neq \emptyset} \text{score}(W)$$
The activity inherits the maximum anomaly score of any 10-event sliding window that encompasses its constituent events.

### 4.3 Combined Risk Index & Threat Levels
Every activity preserves its rule confidence and ML anomaly score as distinct fields:
- **Rule Confidence ($C_{\text{rule}}$):** $[0.0, 1.0]$ derived from rule criteria and timing tightness in `rules.yaml`.
- **ML Anomaly Score ($S_{\text{ml}}$):** $[0.0, 1.0]$ derived from LSTM autoencoder sequence reconstruction error.
- **Combined Risk Index ($R$):**
  $$R = 0.5 \cdot C_{\text{rule}} + 0.5 \cdot S_{\text{ml}}$$
  *(Note: If ML score is unavailable or disabled, $R = C_{\text{rule}}$).*

### 4.4 Categorical Threat Levels

| Threat Level | Combined Risk Index ($R$) | Forensic Meaning |
| :--- | :--- | :--- |
| **`CRITICAL`** | $R \ge 0.80$ | High rule confidence combined with high statistical sequence anomaly (e.g. USB staging followed by immediate process execution and log wipe). |
| **`HIGH`** | $0.65 \le R < 0.80$ | Strong correlation or significant anomaly indicating suspicious host staging. |
| **`MEDIUM`** | $0.45 \le R < 0.65$ | Moderate anomaly or isolated staging behavior requiring analyst verification. |
| **`LOW`** | $R < 0.45$ | Low confidence or routine activity matching broad heuristic boundaries. |

### 4.5 ML-Aware Narrative Line
The activity narrative concludes with an explainable Anomaly Assessment sentence:
> *"Anomaly Assessment: Sequence exhibited an ML anomaly score of 0.88 (threshold 0.50), driven by atypical transition from removable storage write to process execution within a 10-event window."*

No percentage-of-risk or probabilistic assertions are permitted.

---

## 5. Dataset Management & Session-Based Splits

### 5.1 Baseline Collection
Normal baseline data is captured through the ForensiTrace endpoint agent during routine workstation usage:
- Standard software development and terminal compilation.
- Web browsing and document authoring.
- Ordinary benign USB operations (mounting flash drives, reading presentation files) so that USB presence alone does not trigger false positives.

### 5.2 Strict Session-Based Splitting
To prevent data leakage, splitting is strictly performed by **recording session**, never by random event:
- **Train Set:** Baseline recording sessions 1 to $k_{\text{train}}$. Used exclusively for fitting LSTM weights.
- **Validation Set:** Baseline recording sessions $k_{\text{val}}$. Used strictly to calculate the reconstruction threshold $\tau$ (99th percentile).
- **Test Set:** Held-out normal sessions + Attack Scenarios (A, A', B, C) + Noise Session. Never observed during training or threshold tuning.

---

## 6. Schema & API Additions

### 6.1 Database Schema Additions
The `activities` table is extended with two optional columns:
```sql
ALTER TABLE activities ADD COLUMN ml_anomaly_score REAL;
ALTER TABLE activities ADD COLUMN threat_level TEXT;
```

### 6.2 REST Endpoints
- `GET /api/v1/activities` & `GET /api/v1/activities/{id}`: Returns `ml_anomaly_score` and `threat_level`.
- `GET /api/v1/timeline`: Merged chronological stream of activities and raw events.
- `GET /api/v1/report/{activity_id}` & `GET /api/v1/activities/{activity_id}/export`: Streams 3-page formal PDF investigation report.
