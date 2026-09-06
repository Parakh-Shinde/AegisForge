from fastapi.testclient import TestClient

from aegisforge.api.main import app

client = TestClient(app)


def test_health() -> None:
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json()["status"] == "ok"


def test_target_validation_rejects_public_target() -> None:
    response = client.post("/v1/targets/validate", json={"url": "https://8.8.8.8"})
    assert response.status_code == 200
    assert response.json()["allowed"] is False


def test_vulnerable_demo_proves_the_attack_chain() -> None:
    response = client.post("/v1/lab/demo/vulnerable")
    assert response.status_code == 200
    payload = response.json()
    assert payload["attack_succeeded"] is True
    assert payload["detected"] is True


def test_secure_demo_blocks_the_attack_chain() -> None:
    response = client.post("/v1/lab/demo/secure")
    assert response.status_code == 200
    payload = response.json()
    assert payload["attack_succeeded"] is False
    assert payload["detected"] is True
