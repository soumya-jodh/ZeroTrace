import io
from pathlib import Path
import sys
sys.path.insert(0, str(Path(__file__).parent))
from ui.app import app


def test_certificate_upload_rejects_non_json():
    client = app.test_client()
    r = client.post('/api/verify-certificate-upload', data={'certificate': (io.BytesIO(b'%PDF'), 'cert.pdf')}, content_type='multipart/form-data')
    assert r.status_code == 400
    assert 'signed certificate JSON' in r.get_json()['message']


def test_certificate_upload_requires_file():
    client = app.test_client()
    r = client.post('/api/verify-certificate-upload', data={}, content_type='multipart/form-data')
    assert r.status_code == 400
