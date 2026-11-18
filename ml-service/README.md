# CipherGuard AI — ML Service

Internal Python/FastAPI microservice for **static PE malware threat assessment**.

This service is the Member 1 ML module. It does not implement the React frontend, Node.js/Express API gateway, PostgreSQL/Prisma layer, encryption, or authentication. The Node.js backend calls this service on the internal network.

**Current status: production-ready inference pipeline.**
- EMBER 2018 Random Forest trained and evaluated (94.05% accuracy).
- Real PE feature extraction via lief 0.14 + pefile validation.
- `/internal/analyze` endpoint is fully implemented.
- 207 tests passing (0 failures).

---

## Purpose

- Validate uploaded PE files using `pefile` structural checks.
- Extract EMBER 2018 `feature_version=2` static features (2,381-D float32 vector) from PE bytes using lief 0.14, without executing the file.
- Classify samples with an **offline-trained** scikit-learn Random Forest.
- Load the Joblib model artifact **once at FastAPI startup** (never reloaded per-request).
- Return `verdict`, `probability` (P(malicious)), `risk_score` (0–100), and the top 5 contributing features with human-readable descriptions.

---

## Requirements

- Python **3.12** (3.12+ compatible; 3.12 preferred).
- The official **EMBER 2018** dataset is required for offline training only, not for running inference.

---

## Local setup

```bash
cd ml-service
cp .env.example .env
```

### Virtual environment

```bash
python3.12 -m venv .venv
source .venv/bin/activate        # macOS / Linux
# .venv\Scripts\activate         # Windows
```

### Install dependencies

```bash
pip install --upgrade pip
pip install -r requirements.txt
```

---

## EMBER 2018 dataset setup

Training uses the official **EMBER 2018** static PE feature dataset. Do not substitute another malware corpus and do not commit the dataset to Git.

### 1. Where to place the dataset

Extract the official EMBER 2018 release into:

```
ml-service/data/ember2018/
```

Expected layout (JSONL raw features):

```
ml-service/data/ember2018/
├── train_features_0.jsonl   # 100,000 samples each
├── train_features_1.jsonl
├── train_features_2.jsonl
├── train_features_3.jsonl
├── train_features_4.jsonl
├── train_features_5.jsonl
└── test_features.jsonl      # 200,000 samples
```

Unlabeled samples (label=-1) are automatically excluded. Dataset files are gitignored.

Obtain EMBER 2018 from the [elastic/ember](https://github.com/elastic/ember) upstream project.

### 2. Inspect the dataset

```bash
python scripts/inspect_ember.py
```

Reports train/test counts, feature dimensionality, benign/malicious counts, and missing values.

### 3. Train the Random Forest (offline)

```bash
python scripts/train_ember_rf.py
```

This is a **one-time offline process**, not part of the FastAPI request path. The script:

1. Loads labeled training data (unlabeled rows excluded).
2. Fits `RandomForestClassifier` with `n_estimators=100, random_state=42, n_jobs=-1, max_features="sqrt"`.
3. Evaluates accuracy, precision, recall, F1, FPR, ROC-AUC, and confusion matrix on the held-out test set.
4. Writes `models/ember_rf.joblib` and `models/ember_rf_metadata.json` only if training succeeds.

Achieved evaluation metrics (on 200,000 supervised EMBER 2018 test samples):

| Metric | Value |
|---|---|
| Accuracy | 94.05% |
| Precision | 93.17% |
| Recall | 95.06% |
| F1-score | 94.11% |
| ROC-AUC | 98.56% |
| False positive rate | 6.97% |

### 4. Model artifacts

| Artifact | Path | Git |
|---|---|---|
| Trained model | `models/ember_rf.joblib` (~107 MiB) | gitignored |
| Metrics / metadata | `models/ember_rf_metadata.json` | gitignored |

Restart uvicorn after training so workers reload the artifact.

---

## Start the service

```bash
uvicorn app.main:app --reload --host 127.0.0.1 --port 8000
```

The Joblib artifact is loaded **once** during the FastAPI lifespan hook. If the artifact is missing, the service starts but `/internal/analyze` returns `503 model_not_ready`. Use `/health` to check readiness before sending analyze requests.

---

## API Contract

### `GET /health`

Liveness and readiness probe. The Node.js backend should poll this to confirm the model is loaded before sending analyze requests.

**Response `200 OK`:**
```json
{
  "status": "ok",
  "model_ready": true
}
```

`model_ready` is `false` if the Joblib artifact is missing, corrupt, has wrong dimensions, or failed validation at startup.

```bash
curl http://127.0.0.1:8000/health
```

---

### `POST /internal/analyze`

**Request:** `multipart/form-data`, field name: **`file`**

The uploaded file is read into memory, validated structurally via `pefile`, then feature-extracted via lief 0.14, then classified by the Random Forest. The file is **never written to disk** and **never executed**.

```bash
curl -X POST http://127.0.0.1:8000/internal/analyze \
  -F "file=@/path/to/sample.exe"
```

**Successful response `200 OK`:**
```json
{
  "verdict": "benign",
  "probability": 0.02,
  "risk_score": 2,
  "top_features": [
    {
      "feature": "datadirectories_13",
      "importance": 0.00734,
      "description": "Influential model feature (datadirectories): PE data directory sizes and virtual addresses. Note: importance reflects global RF training signal, not a per-file causal explanation."
    }
  ]
}
```

**Field semantics:**

| Field | Type | Semantics |
|---|---|---|
| `verdict` | `"benign"` \| `"malicious"` | Binary classification from Random Forest majority vote |
| `probability` | float [0.0, 1.0] | P(malicious \| static features) from `predict_proba()` |
| `risk_score` | int [0, 100] | `round(probability * 100)` |
| `top_features` | list, max 5 entries | Global RF feature importances scaled by feature magnitude |
| `top_features[].feature` | string | EMBER feature name (e.g. `histogram_42`, `imports_128`) |
| `top_features[].importance` | float [0.0, 1.0] | Relative contribution score |
| `top_features[].description` | string | Human-readable group explanation |

**Error responses** (all use `{"error": "...", "detail": "..."}`):

| Status | `error` code | Condition |
|---|---|---|
| `400` | `malformed_pe` | Empty file, non-PE, missing MZ magic, invalid PE headers |
| `413` | `file_too_large` | Upload exceeds `ML_MAX_FILE_SIZE_BYTES` (default 50 MiB) |
| `422` | `invalid_request` | Missing `file` field or wrong multipart encoding |
| `503` | `model_not_ready` | Model artifact not loaded or failed validation |

No stack traces, filesystem paths, or raw file bytes are ever included in error responses.

---

## Node.js Integration Notes

The Node.js backend should:

1. **Check `/health`** on startup and confirm `model_ready === true` before routing traffic.
2. **POST to `/internal/analyze`** using `multipart/form-data` with field name `file`.
3. **Expect `{"error": ..., "detail": ...}`** for all non-200 responses — consistent schema across all error codes.
4. **Handle `503`** gracefully if the service is still loading (e.g., on cold restart).
5. **Set a reasonable timeout** — extraction + inference typically takes 30–60 ms; allow 5–10 seconds for cold start with model loading (~0.24 s).

Example using Node.js `form-data`:
```js
const FormData = require('form-data');
const axios = require('axios');

const form = new FormData();
form.append('file', fileBuffer, { filename: 'sample.exe', contentType: 'application/octet-stream' });

const response = await axios.post('http://127.0.0.1:8000/internal/analyze', form, {
  headers: form.getHeaders(),
  timeout: 10000,
});
// response.data: { verdict, probability, risk_score, top_features }
```

---

## Run tests

```bash
cd ml-service
source .venv/bin/activate
pytest
```

All 207 tests pass in ~6 seconds. Tests are organized by concern:

| File | Tests | Covers |
|---|---|---|
| `test_health.py` | 3 | Health endpoint and model_ready field |
| `test_analyze_errors.py` | 3 | Malformed input rejection |
| `test_inference.py` | ~60 | Extractor (rejection + valid PE), loader, predictor, endpoint |
| `test_prompt7_parity.py` | ~70 | Vectorizer parity, schema invariants, malformed rejection, real PE extraction |
| `test_prompt8_integration.py` | ~40 | Full API contract: request format, response schema, error codes, security |
| `test_schemas.py` | 4 | Pydantic schema validation |
| `test_train_rf.py` | 8 | RF training, joblib roundtrip, missing dataset |
| `test_ember_loader.py` | multiple | EMBER JSONL loading and vectorization |

Tests use a legally usable benign PE fixture (`windows-kill.exe` from the nodemon npm package). No malware is downloaded or executed.

---

## Configuration

All settings use the `ML_` prefix and can be set via `.env` or environment variables.

| Variable | Meaning | Default |
|---|---|---|
| `ML_ENVIRONMENT` | `development`, `test`, `production` | `development` |
| `ML_MODEL_PATH` | Path to Joblib RF artifact | `models/ember_rf.joblib` |
| `ML_EMBER_DATA_DIR` | Path to extracted EMBER 2018 dataset | `data/ember2018` |
| `ML_MAX_FILE_SIZE_BYTES` | Maximum upload size in bytes | `52428800` (50 MiB) |
| `ML_HOST` | Bind host for local uvicorn | `127.0.0.1` |
| `ML_PORT` | Bind port for local uvicorn | `8000` |

---

## Feature extraction compatibility notes

**lief version:** Training used lief `0.9.0`. Inference uses lief `0.14.1`. All API differences are compensated:

| API change | Impact | Resolution |
|---|---|---|
| `DataDirectory.type` string format | None (positional indexing used) | Documented only |
| `exported_functions` returns objects (lief ≥ 0.10) | Handled | `LIEF_EXPORT_OBJECT` flag |
| `has_signatures` renamed (lief ≥ 0.11) | Handled | `LIEF_HAS_SIGNATURE` flag |
| Exception-based → result-based parse failure | Handled | Returns `None` on failure |

**Inherent limitation:** lief 0.14 may parse some PE header fields (section sizes, timestamps) differently than lief 0.9.0 used during training. This introduces a small distributional shift in the PE-group features (general, header, section, imports, exports, datadirectories) at inference time. Eliminating this would require re-extracting the full EMBER 2018 corpus with lief 0.14 and retraining. The effect is expected to be minimal given the model's 94.05% accuracy on the official EMBER test set.

**Vectorizer parity:** The `vectorize_raw_features()` function was verified to produce **bit-for-bit identical** output to the official `elastic/ember process_raw_features()` on 20 real EMBER JSONL records (max absolute diff = 0.00 across all 2,381 features).

---

## Project layout

```
ml-service/
├── app/
│   ├── main.py                  # FastAPI app, lifespan, endpoints, exception handlers
│   ├── config.py                # Settings (pydantic-settings, ML_ prefix)
│   ├── schemas.py               # AnalyzeResponse, HealthResponse, ErrorResponse, TopFeature
│   ├── data/
│   │   ├── ember_loader.py      # EMBER JSONL loading and vectorization
│   │   ├── ember_feature_schema.py  # Feature groups, dims, names (2381-D)
│   │   └── ember_vectorizer.py  # process_raw_features (exact EMBER parity)
│   ├── training/
│   │   ├── trainer.py           # RandomForestClassifier fit + evaluate
│   │   ├── rf_config.py         # RandomForestConfig dataclass
│   │   ├── metrics.py           # Evaluation metric computation
│   │   └── artifact.py          # Joblib serialization
│   ├── model/
│   │   └── model_loader.py      # load_model(): validates n_features==2381, classes=={0,1}
│   ├── features/
│   │   └── pe_extractor.py      # PE validation (pefile) + lief extraction → raw dict
│   └── inference/
│       └── predictor.py         # predict(): RF inference → AnalyzeResponse
├── data/ember2018/              # Place official dataset here (gitignored)
├── models/                      # Joblib artifact output (gitignored)
├── scripts/
│   ├── inspect_ember.py
│   └── train_ember_rf.py
├── tests/
├── requirements.txt
└── .env.example
```

---

## Offline training vs. FastAPI inference

| Stage | Entry point | What happens |
|---|---|---|
| **Training** | `python scripts/train_ember_rf.py` | Load EMBER JSONL → fit RF → evaluate test set → write Joblib |
| **Inference** | `uvicorn app.main:app` | Load Joblib once at startup → `/internal/analyze` serves requests |

Training never happens inside FastAPI. The RF is never retrained on user uploads.
