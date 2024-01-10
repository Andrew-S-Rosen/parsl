import pathlib
import time
from typing import Tuple

import pytest
import zmq

from parsl import curvezmq


@pytest.fixture
def curvezmq_sockets(tmpd_cwd: pathlib.Path) -> Tuple[zmq.Socket, zmq.Socket, int]:
    server_ctx = curvezmq.ServerContext(tmpd_cwd)
    server_socket = server_ctx.socket(zmq.PULL)
    server_socket.setsockopt(zmq.RCVTIMEO, 300)
    port = server_socket.bind_to_random_port("tcp://127.0.0.1")

    client_ctx = curvezmq.ClientContext(tmpd_cwd)
    client_socket = client_ctx.socket(zmq.PUSH)
    client_socket.setsockopt(zmq.SNDTIMEO, 300)
    client_socket.connect(f"tcp://127.0.0.1:{port}")

    yield server_socket, client_socket, port

    server_ctx.destroy()
    client_ctx.destroy()


@pytest.mark.local
def test_curvezmq_connection(curvezmq_sockets: Tuple[zmq.Socket, zmq.Socket, int]):
    server_socket, client_socket, _ = curvezmq_sockets

    msg = b"howdy"
    client_socket.send(msg)
    recv = server_socket.recv()

    assert recv == msg


@pytest.mark.local
def test_curvezmq_invalid_keys(
    curvezmq_sockets: Tuple[zmq.Socket, zmq.Socket, int], tmpd_cwd: pathlib.Path
):
    server_socket, _, port = curvezmq_sockets
    ctx = zmq.Context()

    def connect(public_key: bytes, secret_key: bytes, server_key: bytes):
        sock = ctx.socket(zmq.PUSH)
        sock.setsockopt(zmq.LINGER, 0)
        sock.setsockopt(zmq.CURVE_PUBLICKEY, public_key)
        sock.setsockopt(zmq.CURVE_SECRETKEY, secret_key)
        sock.setsockopt(zmq.CURVE_SERVERKEY, server_key)
        sock.connect(f"tcp://127.0.0.1:{port}")
        return sock

    certs_dir = curvezmq._ensure_certificates(tmpd_cwd)
    public_key, secret_key = curvezmq._load_certificate(certs_dir, "client")
    server_public_key, _ = curvezmq._load_certificate(certs_dir, "server")
    BAD_KEY = b"a" * 40
    msg = b"howdy"

    sock = connect(public_key, secret_key, server_public_key)
    sock.send(msg)
    assert server_socket.recv() == msg

    sock = connect(BAD_KEY, secret_key, server_public_key)
    sock.send(msg)
    with pytest.raises(zmq.Again):
        server_socket.recv()

    sock = connect(public_key, BAD_KEY, server_public_key)
    sock.send(msg)
    with pytest.raises(zmq.Again):
        server_socket.recv()

    sock = connect(public_key, secret_key, BAD_KEY)
    sock.send(msg)
    with pytest.raises(zmq.Again):
        server_socket.recv()

    ctx.destroy()
