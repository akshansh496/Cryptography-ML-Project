from fastapi import status


def test_analyze_rejects_malformed_pe(client) -> None:
    response = client.post(
        "/internal/analyze",
        files={"file": ("not_a_pe.txt", b"this is not a portable executable", "application/octet-stream")},
    )
    assert response.status_code == status.HTTP_400_BAD_REQUEST
    body = response.json()
    assert body["error"] == "malformed_pe"
    assert "detail" in body


def test_analyze_rejects_empty_upload(client) -> None:
    response = client.post(
        "/internal/analyze",
        files={"file": ("empty.exe", b"", "application/octet-stream")},
    )
    assert response.status_code == status.HTTP_400_BAD_REQUEST
    assert response.json()["error"] == "malformed_pe"


def test_analyze_rejects_mz_garbage(client) -> None:
    """Prompt 7: MZ+garbage must be rejected with 400 malformed_pe.

    pefile structural validation now runs before any feature extraction.
    MZ+zeros and MZ+garbage fail pefile validation (invalid e_lfanew / NT
    headers) and are returned as 400 Bad Request — they are never scored.
    These inputs never appeared in EMBER 2018 training data (all 800k records
    had vsize>0, meaning lief 0.9 successfully parsed them). They are
    out-of-distribution and producing a score for them would be misleading.
    """
    for bad_body in [
        b"\x00" * 64,               # zeros — invalid e_lfanew / NT sig
        b"\xff" * 500,              # all-ones — invalid NT headers
        b"\xde\xad\xbe\xef" * 200,  # garbage — invalid e_lfanew
    ]:
        response = client.post(
            "/internal/analyze",
            files={"file": ("sample.exe", b"MZ" + bad_body, "application/octet-stream")},
        )
        assert response.status_code == status.HTTP_400_BAD_REQUEST, (
            f"Expected 400 for MZ+garbage body, got {response.status_code}"
        )
        assert response.json()["error"] == "malformed_pe"
