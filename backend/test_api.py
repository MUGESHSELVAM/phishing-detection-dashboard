import json
import json
from app import app
import time

client = app.test_client()


def register_and_get_token():
    # register a temporary user
    email = f"test+{int(time.time())}@example.com"
    resp = client.post('/auth/register', json={'email': email, 'password': 'TestPass123'})
    assert resp.status_code in (200, 201)
    # login
    resp = client.post('/auth/login', json={'email': email, 'password': 'TestPass123'})
    assert resp.status_code == 200
    data = resp.get_json()
    return data.get('access_token')


def test_health():
    resp = client.get('/health')
    assert resp.status_code == 200
    data = resp.get_json()
    assert data.get('status') == 'ok'


def test_scan():
    token = register_and_get_token()
    headers = {'Authorization': f'Bearer {token}'}
    resp = client.post('/api/scan', json={'url': 'http://example.com'}, headers=headers)
    if resp.status_code != 200:
        print('SCAN FAILED', resp.status_code, resp.get_data(as_text=True))
    assert resp.status_code == 200
    data = resp.get_json()
    assert 'risk_score' in data


if __name__ == '__main__':
    test_health()
    test_scan()
    print('backend tests passed')
