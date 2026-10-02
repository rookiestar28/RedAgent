import hashlib

from tests.integration import test_bounded_child_live as fixture


def test_history_export_digest_binds_exact_bytes_on_every_platform(tmp_path):
    class History:
        calls = 0

        def to_json(self):
            self.calls += 1
            return '{\n  "history": "actual UTF-8: 資格"\n}\n'

    history = History()
    path = tmp_path / "owned-history.json"
    digest = fixture._write_history_bytes(path, history)
    saved = path.read_bytes()
    assert digest == hashlib.sha256(saved).hexdigest()
    assert saved == '{\n  "history": "actual UTF-8: 資格"\n}\n'.encode("utf-8")
    assert history.calls == 1
