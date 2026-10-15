from __future__ import annotations

import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI, File, Request, UploadFile
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse

from app.config import get_settings
from app.features.pe_extractor import MalformedPEError, extract_ember_features
from app.inference.predictor import ModelNotReadyError, predict
from app.model.model_loader import LoadedModel, load_model
from app.schemas import AnalyzeResponse, ErrorResponse, HealthResponse

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class FileTooLargeError(ValueError):
    """Raised when the uploaded file exceeds ML_MAX_FILE_SIZE_BYTES."""

    def __init__(self, size: int, limit: int) -> None:
        super().__init__(
            f"Upload size {size:,} bytes exceeds the maximum allowed {limit:,} bytes."
        )
        self.size = size
        self.limit = limit


@asynccontextmanager
async def lifespan(app: FastAPI):
    settings = get_settings()
    app.state.loaded_model = load_model(settings.resolved_model_path)
    logger.info(
        "ML service started (environment=%s, model_ready=%s)",
        settings.environment,
        app.state.loaded_model.ready,
    )
    yield
    app.state.loaded_model = LoadedModel(ready=False)


app = FastAPI(
    title="CipherGuard AI ML Service",
    description="Internal static PE malware assessment service (EMBER 2018 + Random Forest).",
    version="0.1.0",
    lifespan=lifespan,
)


def get_loaded_model(request: Request) -> LoadedModel:
    return request.app.state.loaded_model


@app.exception_handler(MalformedPEError)
async def malformed_pe_handler(_request: Request, exc: MalformedPEError) -> JSONResponse:
    # Detail is sanitised in pe_extractor — no raw bytes or file paths.
    payload = ErrorResponse(error="malformed_pe", detail=str(exc))
    return JSONResponse(status_code=400, content=payload.model_dump())


@app.exception_handler(FileTooLargeError)
async def file_too_large_handler(_request: Request, exc: FileTooLargeError) -> JSONResponse:
    payload = ErrorResponse(
        error="file_too_large",
        detail=f"Upload size {exc.size:,} bytes exceeds the {exc.limit:,}-byte limit.",
    )
    return JSONResponse(status_code=413, content=payload.model_dump())


@app.exception_handler(ModelNotReadyError)
async def model_not_ready_handler(_request: Request, exc: ModelNotReadyError) -> JSONResponse:
    payload = ErrorResponse(
        error="model_not_ready",
        detail="The ML model is not available. Contact the administrator.",
    )
    return JSONResponse(status_code=503, content=payload.model_dump())


@app.exception_handler(NotImplementedError)
async def not_implemented_handler(_request: Request, exc: NotImplementedError) -> JSONResponse:
    payload = ErrorResponse(error="not_implemented", detail=str(exc))
    return JSONResponse(status_code=501, content=payload.model_dump())


@app.exception_handler(RequestValidationError)
async def validation_handler(_request: Request, exc: RequestValidationError) -> JSONResponse:
    payload = ErrorResponse(error="invalid_request", detail=str(exc.errors()))
    return JSONResponse(status_code=422, content=payload.model_dump())


@app.get("/health", response_model=HealthResponse)
async def health(request: Request) -> HealthResponse:
    """Liveness + readiness probe.

    Returns {"status": "ok", "model_ready": true/false} so callers can
    distinguish a cold-start (model still loading or artifact missing) from
    a fully operational service without making a speculative analyze request.
    """
    loaded: LoadedModel = request.app.state.loaded_model
    return HealthResponse(status="ok", model_ready=loaded.ready)


@app.post(
    "/internal/analyze",
    response_model=AnalyzeResponse,
    responses={
        400: {"model": ErrorResponse},
        413: {"model": ErrorResponse},
        422: {"model": ErrorResponse},
        501: {"model": ErrorResponse},
        503: {"model": ErrorResponse},
    },
)
async def analyze(request: Request, file: UploadFile = File(...)) -> AnalyzeResponse:
    """Internal inference endpoint. Called by the Node.js backend, not the browser.

    Request:  multipart/form-data  field name: ``file``
    Response: AnalyzeResponse JSON (see app/schemas.py)

    Uploaded bytes are read into memory and never written to disk or executed.
    """
    settings = get_settings()

    # Read in one shot — UploadFile is already spooled to memory by python-multipart.
    # No temp file is created; bytes are discarded after this request scope.
    raw = await file.read()

    if len(raw) > settings.max_file_size_bytes:
        raise FileTooLargeError(size=len(raw), limit=settings.max_file_size_bytes)

    features = extract_ember_features(raw)
    return predict(features, get_loaded_model(request))
