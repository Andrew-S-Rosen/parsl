import os
import pathlib
from typing import Callable, Tuple
from unittest import mock

import pytest
import zmq
import zmq.auth
from zmq.auth.thread import ThreadAuthenticator

from parsl import curvezmq

ADDR = "tcp://127.0.0.1"


def _get_server_socket_factory(ctx: curvezmq.BaseContext):
    def factory():
        sock = ctx.socket(zmq.PULL)
        sock.setsockopt(zmq.RCVTIMEO, 200)
        sock.setsockopt(zmq.LINGER, 0)
        port = sock.bind_to_random_port(ADDR)
        return sock, port

    return factory


def _get_client_socket_factory(ctx: curvezmq.BaseContext):
    def factory(port: int):
        sock = ctx.socket(zmq.PUSH)
        sock.setsockopt(zmq.SNDTIMEO, 200)
        sock.setsockopt(zmq.LINGER, 0)
        sock.connect(f"{ADDR}:{port}")
        return sock

    return factory


@pytest.fixture
def get_server_socket(tmpd_cwd: pathlib.Path):
    ctx = curvezmq.ServerContext(tmpd_cwd, encrypted=True)
    factory = _get_server_socket_factory(ctx)
    yield factory
    ctx.destroy()


@pytest.fixture
def get_client_socket(tmpd_cwd: pathlib.Path):
    ctx = curvezmq.ClientContext(tmpd_cwd, encrypted=True)
    factory = _get_client_socket_factory(ctx)
    yield factory
    ctx.destroy()


@pytest.fixture
def get_server_socket_unencrypted(tmpd_cwd: pathlib.Path):
    ctx = curvezmq.ServerContext(tmpd_cwd, encrypted=False)
    factory = _get_server_socket_factory(ctx)
    yield factory
    ctx.destroy()


@pytest.fixture
def get_client_socket_unencrypted(tmpd_cwd: pathlib.Path):
    ctx = curvezmq.ClientContext(tmpd_cwd, encrypted=False)
    factory = _get_client_socket_factory(ctx)
    yield factory
    ctx.destroy()


@pytest.fixture
def get_external_server_socket():
    ctx = zmq.Context()

    auth_thread = ThreadAuthenticator(ctx)
    auth_thread.start()
    auth_thread.configure_curve(domain="*", location=zmq.auth.CURVE_ALLOW_ANY)

    def factory(secret_key: str):
        sock = ctx.socket(zmq.PULL)
        sock.setsockopt(zmq.RCVTIMEO, 200)
        sock.setsockopt(zmq.LINGER, 0)
        sock.setsockopt(zmq.CURVE_SECRETKEY, secret_key)
        sock.setsockopt(zmq.CURVE_SERVER, True)
        port = sock.bind_to_random_port(ADDR)
        return sock, port

    yield factory

    auth_thread.stop()
    ctx.destroy()


@pytest.fixture
def get_external_client_socket():
    ctx = zmq.Context()

    def factory(public_key: str, secret_key: str, server_key: str, port: int):
        sock = ctx.socket(zmq.PUSH)
        sock.setsockopt(zmq.LINGER, 0)
        sock.setsockopt(zmq.CURVE_PUBLICKEY, public_key)
        sock.setsockopt(zmq.CURVE_SECRETKEY, secret_key)
        sock.setsockopt(zmq.CURVE_SERVERKEY, server_key)
        sock.connect(f"{ADDR}:{port}")
        return sock

    yield factory

    ctx.destroy()


@pytest.mark.local
def test_ensure_certificates(tmpd_cwd: pathlib.Path):
    certs_dir = tmpd_cwd / "certificates"
    assert not os.path.exists(certs_dir)

    ret = curvezmq._ensure_certificates(tmpd_cwd)

    assert str(certs_dir) == ret
    assert os.path.exists(certs_dir)
    assert len(os.listdir(certs_dir)) == 4


@pytest.mark.local
@pytest.mark.parametrize("encrypted", (True, False))
@mock.patch.object(curvezmq, "_ensure_certificates")
def test_client_context_init(
    mock_ensure_certs: mock.MagicMock, encrypted: bool, tmpd_cwd: pathlib.Path
):
    certs_dir = "/path/to/certs/dir"
    mock_ensure_certs.return_value = certs_dir

    ctx = curvezmq.ServerContext(base_dir=tmpd_cwd, encrypted=encrypted)

    assert ctx.encrypted is encrypted
    if encrypted:
        assert ctx.certs_dir == certs_dir
        assert isinstance(ctx.auth_thread, ThreadAuthenticator)
        assert mock_ensure_certs.called
    else:
        assert not hasattr(ctx, "certs_dir")
        assert not hasattr(ctx, "auth_thread")
        assert not mock_ensure_certs.called

    ctx.destroy()


@pytest.mark.local
@pytest.mark.parametrize("encrypted", (True, False))
@mock.patch.object(curvezmq, "_ensure_certificates")
def test_server_context_init(
    mock_ensure_certs: mock.MagicMock, encrypted: bool, tmpd_cwd: pathlib.Path
):
    certs_dir = "/path/to/certs/dir"
    mock_ensure_certs.return_value = certs_dir

    ctx = curvezmq.ClientContext(base_dir=tmpd_cwd, encrypted=encrypted)

    assert ctx.encrypted is encrypted
    if encrypted:
        assert ctx.certs_dir == certs_dir
        assert mock_ensure_certs.called
    else:
        assert not hasattr(ctx, "certs_dir")
        assert not mock_ensure_certs.called

    ctx.destroy()


@pytest.mark.local
@pytest.mark.parametrize("encrypted", (True, False))
@pytest.mark.parametrize("method", ("term", "destroy"))
def test_client_context_term_destroy(
    encrypted: bool, method: str, tmpd_cwd: pathlib.Path
):
    ctx = curvezmq.ClientContext(tmpd_cwd, encrypted)
    sock = ctx.socket(zmq.REQ)

    assert not sock.closed
    assert not ctx._ctx.closed

    getattr(ctx, method)()

    assert sock.closed
    assert ctx._ctx.closed


@pytest.mark.local
@pytest.mark.parametrize("encrypted", (True, False))
@pytest.mark.parametrize("method", ("term", "destroy"))
def test_server_context_term_destroy(
    encrypted: bool, method: str, tmpd_cwd: pathlib.Path
):
    ctx = curvezmq.ServerContext(tmpd_cwd, encrypted)
    sock = ctx.socket(zmq.REP)

    assert not sock.closed
    assert not ctx._ctx.closed
    if encrypted:
        assert ctx.auth_thread.pipe

    getattr(ctx, method)()

    assert sock.closed
    assert ctx._ctx.closed
    if encrypted:
        assert not ctx.auth_thread.pipe


@pytest.mark.local
@pytest.mark.parametrize("encrypted", (True, False))
def test_client_context_recreate(encrypted: bool, tmpd_cwd: pathlib.Path):
    ctx = curvezmq.ClientContext(tmpd_cwd, encrypted)
    hidden_ctx = ctx._ctx
    sock = ctx.socket(zmq.REQ)

    assert not sock.closed
    assert not ctx._ctx.closed
    assert sock in ctx._sockets

    ctx.recreate()

    assert sock.closed
    assert hidden_ctx.closed
    assert hidden_ctx != ctx._ctx
    assert len(ctx._sockets) == 0

    ctx.destroy()


@pytest.mark.local
@pytest.mark.parametrize("encrypted", (True, False))
def test_server_context_recreate(encrypted: bool, tmpd_cwd: pathlib.Path):
    ctx = curvezmq.ServerContext(tmpd_cwd, encrypted)
    hidden_ctx = ctx._ctx
    sock = ctx.socket(zmq.REP)

    assert not sock.closed
    assert not ctx._ctx.closed
    assert sock in ctx._sockets
    if encrypted:
        auth_thread = ctx.auth_thread
        assert auth_thread.pipe

    ctx.recreate()

    assert sock.closed
    assert hidden_ctx.closed
    assert hidden_ctx != ctx._ctx
    assert len(ctx._sockets) == 0
    if encrypted:
        assert auth_thread != ctx.auth_thread
        assert ctx.auth_thread.pipe

    ctx.destroy()


@pytest.mark.local
def test_connection(
    get_server_socket: Callable[[], Tuple[zmq.Socket, int]],
    get_client_socket: Callable[[int], zmq.Socket],
):
    server_socket, port = get_server_socket()
    client_socket = get_client_socket(port)

    msg = b"howdy"
    client_socket.send(msg)
    recv = server_socket.recv()

    assert recv == msg


@pytest.mark.local
def test_connection_unencrypted(
    get_server_socket_unencrypted: Callable[[], Tuple[zmq.Socket, int]],
    get_client_socket_unencrypted: Callable[[int], zmq.Socket],
):
    server_socket, port = get_server_socket_unencrypted()
    client_socket = get_client_socket_unencrypted(port)

    msg = b"howdy"
    client_socket.send(msg)
    recv = server_socket.recv()

    assert recv == msg


@pytest.mark.local
@mock.patch.object(curvezmq, "_load_certificate")
def test_invalid_key_format(
    mock_load_cert,
    get_server_socket: Callable[[], Tuple[zmq.Socket, int]],
    get_client_socket: Callable[[int], zmq.Socket],
):
    mock_load_cert.return_value = (b"badkey", b"badkey")

    with pytest.raises(ValueError) as e1_info:
        get_server_socket()
    with pytest.raises(ValueError) as e2_info:
        get_client_socket(0)
    e1, e2 = e1_info.exconly, e2_info.exconly

    assert str(e1) == str(e2)
    assert "Invalid CurveZMQ key format" in str(e1)


@pytest.mark.local
def test_invalid_client_keys(
    get_server_socket: Callable[[], Tuple[zmq.Socket, int]],
    get_external_client_socket: Callable[[str, str, str, int], zmq.Socket],
    tmpd_cwd: pathlib.Path,
):
    server_socket, port = get_server_socket()

    certs_dir = curvezmq._ensure_certificates(tmpd_cwd)
    public_key, secret_key = curvezmq._load_certificate(certs_dir, "client")
    server_key, _ = curvezmq._load_certificate(certs_dir, "server")

    BAD_KEY = b"a" * 40
    msg = b"howdy"

    client_socket = get_external_client_socket(public_key, secret_key, server_key, port)
    client_socket.send(msg)
    assert server_socket.recv() == msg

    client_socket = get_external_client_socket(BAD_KEY, secret_key, server_key, port)
    client_socket.send(msg)
    with pytest.raises(zmq.Again):
        server_socket.recv()

    client_socket = get_external_client_socket(public_key, BAD_KEY, server_key, port)
    client_socket.send(msg)
    with pytest.raises(zmq.Again):
        server_socket.recv()

    client_socket = get_external_client_socket(public_key, secret_key, BAD_KEY, port)
    client_socket.send(msg)
    with pytest.raises(zmq.Again):
        server_socket.recv()

    # Ensure sockets are operational
    client_socket = get_external_client_socket(public_key, secret_key, server_key, port)
    client_socket.send(msg)
    assert server_socket.recv() == msg


@pytest.mark.local
def test_invalid_server_key(
    get_client_socket: Callable[[int], zmq.Socket],
    get_external_server_socket: Callable[[str], Tuple[zmq.Socket, int]],
    tmpd_cwd: pathlib.Path,
):
    certs_dir = curvezmq._ensure_certificates(tmpd_cwd)
    _, secret_key = curvezmq._load_certificate(certs_dir, "server")

    BAD_KEY = b"a" * 40
    msg = b"howdy"

    server_socket, port = get_external_server_socket(secret_key)
    client_socket = get_client_socket(port)
    client_socket.send(msg)
    assert server_socket.recv() == msg

    server_socket, port = get_external_server_socket(BAD_KEY)
    client_socket = get_client_socket(port)
    client_socket.send(msg)
    with pytest.raises(zmq.Again):
        server_socket.recv()

    # Ensure sockets are operational
    server_socket, port = get_external_server_socket(secret_key)
    client_socket = get_client_socket(port)
    client_socket.send(msg)
    assert server_socket.recv() == msg
