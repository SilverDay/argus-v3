import json

import pytest

from src.shared import broker_protocol as bp

KEY = b"k" * 32
OTHER = b"x" * 32


def test_request_round_trip():
    line, nonce = bp.build_request(KEY, "mount", {"session_id": "s", "partition_id": "part1"})
    got_nonce, cmd, args = bp.verify_request(KEY, line, bp.NonceCache(30))
    assert (got_nonce, cmd, args) == (nonce, "mount", {"session_id": "s", "partition_id": "part1"})


def test_wrong_key_rejected():
    line, _ = bp.build_request(OTHER, "ping")
    with pytest.raises(bp.ProtocolError) as exc:
        bp.verify_request(KEY, line, bp.NonceCache(30))
    assert exc.value.code == bp.E_UNAUTHORIZED


def test_tampered_args_rejected():
    line, _ = bp.build_request(KEY, "enumerate", {"sysfs_path": "/sys/bus/usb/devices/1-1"})
    obj = json.loads(line)
    obj["args"]["sysfs_path"] = "/dev/sda1"
    with pytest.raises(bp.ProtocolError) as exc:
        bp.verify_request(KEY, json.dumps(obj).encode(), bp.NonceCache(30))
    assert exc.value.code == bp.E_UNAUTHORIZED


def test_replay_and_stale_rejected():
    cache = bp.NonceCache(30)
    line, _ = bp.build_request(KEY, "ping", now=1000)
    bp.verify_request(KEY, line, cache, now=1000)
    with pytest.raises(bp.ProtocolError, match="replay"):
        bp.verify_request(KEY, line, cache, now=1001)
    old, _ = bp.build_request(KEY, "ping", now=1000)
    with pytest.raises(bp.ProtocolError, match="replay"):
        bp.verify_request(KEY, old, bp.NonceCache(30), now=1100)


def test_response_cannot_be_replayed_as_request():
    resp = bp.build_response(KEY, "a" * 32, result={})
    with pytest.raises(bp.ProtocolError):
        bp.verify_request(KEY, resp, bp.NonceCache(30))


def test_response_bound_to_request_nonce():
    resp = bp.build_response(KEY, "a" * 32, result={"pong": True})
    assert bp.parse_response(KEY, resp, "a" * 32) == {"pong": True}
    with pytest.raises(bp.ProtocolError):
        bp.parse_response(KEY, resp, "b" * 32)
    with pytest.raises(bp.ProtocolError) as exc:
        bp.parse_response(OTHER, resp, "a" * 32)
    assert exc.value.code == bp.E_UNAUTHORIZED


def test_error_response():
    resp = bp.build_response(KEY, "a" * 32, error=bp.E_MOUNT_FAILED, detail="x")
    with pytest.raises(bp.ProtocolError) as exc:
        bp.parse_response(KEY, resp, "a" * 32)
    assert exc.value.code == bp.E_MOUNT_FAILED


@pytest.mark.parametrize("line", [b"not json", b"[]", b'{"nonce": "zz"}', b"x" * (bp.MAX_MESSAGE_BYTES + 1)])
def test_malformed(line):
    with pytest.raises(bp.ProtocolError):
        bp.verify_request(KEY, line, bp.NonceCache(30))


def test_short_key_refused():
    with pytest.raises(bp.ProtocolError):
        bp.check_key(b"short")
