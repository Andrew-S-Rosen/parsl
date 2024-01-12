import os
from abc import ABCMeta, abstractmethod
from functools import lru_cache
from typing import Union, Set

import zmq
import zmq.auth
from zmq.auth.thread import ThreadAuthenticator


def _ensure_certificates(base_dir: str | os.PathLike):
    certs_dir = os.path.join(base_dir, "certificates")
    try:
        os.mkdir(certs_dir)
    except FileExistsError:
        return certs_dir
    os.chmod(certs_dir, 0o700)

    zmq.auth.create_certificates(certs_dir, "server")
    zmq.auth.create_certificates(certs_dir, "client")

    return certs_dir


@lru_cache
def _load_certificate(
    certs_dir: Union[str, os.PathLike], name: str
) -> tuple[bytes, bytes]:
    secret_key_file = os.path.join(certs_dir, f"{name}.key_secret")
    public_key, secret_key = zmq.auth.load_certificate(secret_key_file)
    if secret_key is None:
        raise ValueError(f"No secret key found in {secret_key_file}")
    return public_key, secret_key


class BaseContext(metaclass=ABCMeta):
    def __init__(
        self, base_dir: Union[str, os.PathLike], encrypted: bool = True
    ) -> None:
        self.base_dir = base_dir
        self.encrypted = encrypted
        self._ctx = zmq.Context()
        self._sockets: Set[zmq.Socket] = set()
        if encrypted:
            self.certs_dir = _ensure_certificates(base_dir)

    def __del__(self):
        self.destroy()

    @abstractmethod
    def socket(self, socket_type: int, *args, **kwargs) -> zmq.Socket:
        ...

    def term(self):
        for sock in self._sockets:
            sock.close()
        self._ctx.term()

    def destroy(self, linger: int | None = None):
        self._ctx.destroy(linger)

    def recreate(self, linger: int | None = None):
        self.destroy(linger)
        self._ctx = zmq.Context()
        self._sockets = set()


class ClientContext(BaseContext):
    def socket(self, socket_type: int, *args, **kwargs) -> zmq.Socket:
        sock = self._ctx.socket(socket_type, *args, **kwargs)
        if self.encrypted:
            public_key, secret_key = _load_certificate(
                certs_dir=self.certs_dir, name="client"
            )
            server_public_key, _ = _load_certificate(
                certs_dir=self.certs_dir, name="server"
            )
            try:
                sock.setsockopt(zmq.CURVE_PUBLICKEY, public_key)
                sock.setsockopt(zmq.CURVE_SECRETKEY, secret_key)
                sock.setsockopt(zmq.CURVE_SERVERKEY, server_public_key)
            except zmq.ZMQError:
                raise ValueError("Invalid CurveZMQ key format")
        self._sockets.add(sock)
        return sock


class ServerContext(BaseContext):
    def __init__(
        self, base_dir: Union[str, os.PathLike], encrypted: bool = True
    ) -> None:
        super().__init__(base_dir, encrypted)
        if encrypted:
            self._start_auth_thread()

    def _start_auth_thread(self):
        self.auth_thread = ThreadAuthenticator(self._ctx)
        self.auth_thread.start()
        self.auth_thread.configure_curve(domain="*", location=self.certs_dir)

    def socket(self, socket_type: int, *args, **kwargs) -> zmq.Socket:
        sock = self._ctx.socket(socket_type, *args, **kwargs)
        if self.encrypted:
            _, secret_key = _load_certificate(certs_dir=self.certs_dir, name="server")
            try:
                # The server public key is only needed by the client to
                # encrypt messages and verify the server's identity
                # Ref: http://curvezmq.org/page:read-the-docs
                sock.setsockopt(zmq.CURVE_SECRETKEY, secret_key)
            except zmq.ZMQError:
                raise ValueError("Invalid CurveZMQ key format")
            sock.setsockopt(zmq.CURVE_SERVER, True)  # Must come before bind
        self._sockets.add(sock)
        return sock

    def term(self):
        if self.encrypted:
            self.auth_thread.stop()
        super().term()

    def destroy(self, linger: int | None = None):
        if self.encrypted:
            self.auth_thread.stop()
        super().destroy(linger)

    def recreate(self, linger: int | None = None):
        super().recreate(linger)
        if self.encrypted:
            self._start_auth_thread()
