# CipherGuard AI ML Service — Backend Integration Contract

**Document scope:** This document is for the Node.js backend team.
It describes the exact HTTP contract for calling the CipherGuard AI ML Service.

> **Security boundary:** `/internal/analyze` is an internal service endpoint.
> It must NOT be exposed directly to the public internet.
> The Node.js API gateway is the only authorized caller.
> See [Network topology](#network-topology) below.

---

## Service overview

| Property | Value |
|---|---|
| Protocol | HTTP/1.1 (plain, internal network only) |
| Local development base URL | `http://127.0.0.1:8000` |
| Docker network base URL | `http://ml-service:8000` (when both services are on the same Docker network) |
| Framework | FastAPI / uvicorn |
| Authentication | None (trust the internal network; add a shared secret header if needed) |

---

## Endpoints

### `GET /health`

**Purpose:** Liveness and readiness probe.
Call this on startup and in health-check loops before routing traffic to `/internal/analyze`.

**Request:** No body, no parameters.

**Response `200 OK`:**
```json
{
  "status": "ok",
  "model_ready": true
}
```

| Field | Type | Meaning |
|---|---|---|
| `status` | `"ok"` | Service process is alive |
| `model_ready` | `boolean` | `true` when the RF artifact is loaded and validated |

`model_ready` is `false` if the Joblib artifact is missing, corrupt, has wrong dimensions, or failed startup validation. Do **not** send analyze requests when `model_ready` is `false`; they will return `503`.

**Example (curl):**
```bash
curl http://127.0.0.1:8000/health
```

---

### `POST /internal/analyze`

**Purpose:** Classify a Windows PE file as benign or malicious.

**Request format:** `multipart/form-data`

| Parameter | Type | Required | Description |
|---|---|---|---|
| `file` | binary file upload | ✅ Yes | The PE file to analyze. Field name must be exactly `file`. |

The uploaded file is read into memory, validated structurally via `pefile`, then feature-extracted (lief 0.14 static analysis — the file is **never executed**), then classified by the offline-trained Random Forest.

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

**Response field semantics:**

| Field | Type | Semantics |
|---|---|---|
| `verdict` | `"benign"` \| `"malicious"` | Binary classification from Random Forest majority vote across 100 trees |
| `probability` | `float` [0.0 – 1.0] | **P(malicious \| static PE features)** — the class-1 probability from `predict_proba()`. This is the model's calibrated confidence that the file is malicious given its static features. |
| `risk_score` | `integer` [0 – 100] | `round(probability × 100)`. Use this for display to end users. |
| `top_features` | `array`, max 5 items | Top contributing EMBER feature groups with descriptions. |
| `top_features[].feature` | `string` | EMBER feature name (`histogram_N`, `imports_N`, etc.) |
| `top_features[].importance` | `float` [0.0 – 1.0] | Relative contribution score (global RF importance, not per-file causal) |
| `top_features[].description` | `string` | Human-readable explanation of the feature group |

**Example (curl):**
```bash
curl -X POST http://127.0.0.1:8000/internal/analyze \
     -F "file=@/path/to/sample.exe"
```

**Example (Node.js `form-data` + `axios`):**
```js
const FormData = require('form-data');
const axios   = require('axios');
const fs      = require('fs');

async function analyzePE(fileBuffer, filename) {
  const form = new FormData();
  form.append('file', fileBuffer, {
    filename:    filename,
    contentType: 'application/octet-stream',
  });

  const response = await axios.post(
    'http://127.0.0.1:8000/internal/analyze',
    form,
    {
      headers:        form.getHeaders(),
      timeout:        15000,           // 15 s — allows for cold-start model load
      maxContentLength: 60 * 1024 * 1024,  // 60 MiB receive buffer
    }
  );

  // response.data: { verdict, probability, risk_score, top_features }
  return response.data;
}
```

**Example (Node.js built-in `fetch` — Node 18+):**
```js
async function analyzePE(fileBuffer, filename) {
  const formData = new FormData();
  const blob = new Blob([fileBuffer], { type: 'application/octet-stream' });
  formData.append('file', blob, filename);

  const response = await fetch('http://127.0.0.1:8000/internal/analyze', {
    method:  'POST',
    body:    formData,
    signal:  AbortSignal.timeout(15000),
  });

  if (!response.ok) {
    const error = await response.json();
    throw Object.assign(new Error(error.detail), { code: error.error, status: response.status });
  }

  return response.json(); // { verdict, probability, risk_score, top_features }
}
```

---

## Error response schema

All non-200 responses use the **same error envelope**:

```json
{
  "error": "<error_code>",
  "detail": "<human-readable message>"
}
```

| HTTP status | `error` code | When |
|---|---|---|
| `400` | `malformed_pe` | Empty file, non-PE, missing MZ magic, invalid PE headers, truncated |
| `413` | `file_too_large` | Upload exceeds `ML_MAX_FILE_SIZE_BYTES` (default 50 MiB) |
| `422` | `invalid_request` | Missing `file` field, wrong field name, or malformed multipart |
| `503` | `model_not_ready` | Model artifact not loaded or failed validation at startup |

Error responses do **not** contain stack traces, filesystem paths, or raw file bytes.

---

## Timeout and retry guidance

| Scenario | Recommended timeout |
|---|---|
| Normal inference (warm service) | 5 s |
| Cold start (model loading) | 30–60 s |
| Health check | 2 s |

**Retry strategy:**
- `400`, `413`, `422`: **Do not retry** — these are client errors. Return them to the frontend.
- `503`: **Retry with exponential backoff** (e.g., 1 s → 2 s → 4 s, max 3 attempts). The service may be loading its model.
- Network timeouts: Retry once. Log if it fails twice.

---

## Network topology

### Local development

Both the ML service and the Node.js backend run on the host machine.

```
Browser → Node.js backend (localhost:3000)
              ↓  (internal HTTP, not exposed to browser)
         ML service (127.0.0.1:8000)
```

The ML service binds to `127.0.0.1` by default and is **not reachable** from outside the host. The Node.js backend calls it on the loopback interface.

### Docker Compose (when backend is containerised)

```yaml
# docker-compose.yml (illustrative — backend team owns this file)
services:
  ml-service:
    build: ./ml-service
    volumes:
      - ./ml-service/models:/app/models:ro   # supply model artifact
    networks:
      - internal
    # Do NOT publish ports to host in production
    # ports: ["8000:8000"]  ← only for local debug

  backend:
    build: ./backend
    environment:
      ML_SERVICE_URL: http://ml-service:8000
    networks:
      - internal
      - public          # backend faces the internet; ML service does not

networks:
  internal:             # ml-service is isolated on this network
    driver: bridge
  public:
    driver: bridge
```

The ML service container should **not** have its port published to the host in production. Only the Node.js backend should be able to reach it.

### Environment variable for the Node.js backend

```bash
ML_SERVICE_URL=http://127.0.0.1:8000    # local dev
ML_SERVICE_URL=http://ml-service:8000   # Docker Compose
```

---

## Model artifact

The Random Forest artifact (`models/ember_rf.joblib`, ~107 MiB) is **not committed to Git** and **not baked into the Docker image**. It must be supplied:

- **Local dev:** Place it at `ml-service/models/ember_rf.joblib` before starting the service.
- **Docker:** Mount it as a read-only bind volume (see above).
- **Production:** Store it in a private artifact registry or object storage and pull it at deployment time.

The service reports `model_ready: false` in `/health` if the artifact is missing. It will not fabricate predictions.

---

## Quick-start checklist for the backend team

- [ ] Place `ml-service/models/ember_rf.joblib` (provided separately, ~107 MiB)
- [ ] `cd ml-service && cp .env.example .env`
- [ ] `python3.12 -m venv .venv && source .venv/bin/activate`
- [ ] `pip install -r requirements.txt`
- [ ] `uvicorn app.main:app --host 127.0.0.1 --port 8000`
- [ ] `curl http://127.0.0.1:8000/health` → confirm `"model_ready": true`
- [ ] Run `pytest` → confirm 207 tests pass
- [ ] Point Node.js backend `ML_SERVICE_URL` to `http://127.0.0.1:8000`

---

## Known limitations

1. **lief version drift:** The RF was trained with lief 0.9.0; inference runs with lief 0.14.1.
   All API differences are compensated, but field-level parse differences may cause a small distributional shift in PE-group features for unusual PE structures.

2. **Static analysis only:** The service performs no dynamic analysis, sandboxing, or signature lookup.
   The verdict is based solely on static structural features of the PE file.

3. **`top_features` are global, not per-file:** The `importance` values reflect the Random Forest's global training signal, not a causal explanation for this specific file.

4. **Upload size limit:** 50 MiB by default (`ML_MAX_FILE_SIZE_BYTES`). Legitimate PE files are typically under 50 MiB; adjust if needed.
