import pathlib
from typing import Callable, Tuple
from unittest import mock

import pytest
import zmq
import zmq.auth
from zmq.auth.thread import ThreadAuthenticator

from parsl import curvezmq

ADDR = "tcp://127.0.0.1"


@pytest.fixture
def get_server_socket(tmpd_cwd: pathlib.Path):
    ctx = curvezmq.ServerContext(tmpd_cwd)

    def inner():
        sock = ctx.socket(zmq.PULL)
        sock.setsockopt(zmq.RCVTIMEO, 200)
        sock.setsockopt(zmq.LINGER, 0)
        port = sock.bind_to_random_port(ADDR)
        return sock, port

    yield inner

    ctx.destroy()


@pytest.fixture
def get_client_socket(tmpd_cwd: pathlib.Path):
    ctx = curvezmq.ClientContext(tmpd_cwd)

    def inner(port: int):
        sock = ctx.socket(zmq.PUSH)
        sock.setsockopt(zmq.SNDTIMEO, 200)
        sock.setsockopt(zmq.LINGER, 0)
        sock.connect(f"{ADDR}:{port}")
        return sock

    yield inner

    ctx.destroy()


@pytest.fixture
def get_external_server_socket():
    ctx = zmq.Context()

    auth_thread = ThreadAuthenticator(ctx)
    auth_thread.start()
    auth_thread.configure_curve(domain="*", location=zmq.auth.CURVE_ALLOW_ANY)

    def inner(secret_key: str):
        sock = ctx.socket(zmq.PULL)
        sock.setsockopt(zmq.RCVTIMEO, 200)
        sock.setsockopt(zmq.LINGER, 0)
        sock.setsockopt(zmq.CURVE_SECRETKEY, secret_key)
        sock.setsockopt(zmq.CURVE_SERVER, True)
        port = sock.bind_to_random_port(ADDR)
        return sock, port

    yield inner

    auth_thread.stop()
    ctx.destroy()


@pytest.fixture
def get_external_client_socket():
    ctx = zmq.Context()

    def inner(public_key: str, secret_key: str, server_key: str, port: int):
        sock = ctx.socket(zmq.PUSH)
        sock.setsockopt(zmq.LINGER, 0)
        sock.setsockopt(zmq.CURVE_PUBLICKEY, public_key)
        sock.setsockopt(zmq.CURVE_SECRETKEY, secret_key)
        sock.setsockopt(zmq.CURVE_SERVERKEY, server_key)
        sock.connect(f"{ADDR}:{port}")
        return sock

    yield inner

    ctx.destroy()


@pytest.mark.local
def test_curvezmq_connection(
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
def test_curvezmq_invalid_key_format(
    get_server_socket: Callable[[], Tuple[zmq.Socket, int]],
    get_client_socket: Callable[[int], zmq.Socket],
):
    public_key = b"badkey"
    secret_key = b"badkey"
    with mock.patch(
        "parsl.curvezmq._load_certificate", return_value=(public_key, secret_key)
    ):
        with pytest.raises(ValueError) as e1_info:
            get_server_socket()
        with pytest.raises(ValueError) as e2_info:
            get_client_socket(0)
    e1, e2 = e1_info.exconly, e2_info.exconly
    assert str(e1) == str(e2)
    assert "Invalid CurveZMQ key format" in str(e1)


@pytest.mark.local
def test_curvezmq_invalid_client_keys(
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
def test_curvezmq_invalid_server_key(
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
