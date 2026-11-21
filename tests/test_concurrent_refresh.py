# tests/test_concurrent_refresh.py

from concurrent.futures import ThreadPoolExecutor
from threading import Barrier
from uuid import uuid4

from fastapi.testclient import TestClient

from app.main import app


def test_concurrent_refresh_rotation():
    username = f"race-{uuid4().hex}"

    with TestClient(app) as client:
        # 1. Register and log in
        response = client.post(
            "/register",
            json = {
                "username": username,
                "password": "secure-test-password-123",
            },
        )
        assert response.status_code in (200, 201)

        response = client.post(
            "/login",
            json = {
                "username": username,
                "password": "secure-test-password-123",
            },
        )
        assert response.status_code == 200

        original_token = response.json()["refresh_token"]

    # 2. Coordinate simultaneous requests
    barrier = Barrier(2)

    def refresh():
        barrier.wait(timeout = 10)

        with TestClient(app) as worker_client:
            return worker_client.post(
                "/refresh",
                json = {"refresh_token": original_token},
            )

    # 3. Execute requests concurrently
    with ThreadPoolExecutor(max_workers = 2) as executor:
        futures = [
            executor.submit(refresh)
            for _ in range(2)
        ]
        responses = [f.result(timeout = 15) for f in futures]

    # 4. Verify single-use semantics
    status_codes = sorted(
        response.status_code for response in responses
    )

    assert status_codes == [200, 401], status_codes
