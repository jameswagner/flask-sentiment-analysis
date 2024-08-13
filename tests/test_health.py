import pytest
from app import app

@pytest.fixture
def client():
    with app.test_client() as client:
        yield client

def test_hello(client):
    response = client.get('/')
    assert response.data.decode() == 'Hello, World!'

def test_health(client):
    response = client.get('/health')
    assert response.status_code == 200
    assert response.json == {"status": "healthy"}