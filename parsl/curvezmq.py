import logging
import os

import zmq
import zmq.auth
from zmq.auth.thread import ThreadAuthenticator

logger = logging.getLogger(__name__)


def _get_certificates(certs_dir: str | os.PathLike, name: str) -> tuple[bytes, bytes]:
    secret_key_file = os.path.join(certs_dir, f"{name}.key_secret")

    try:
        public_key, secret_key = zmq.auth.load_certificate(secret_key_file)
        if secret_key is None:
            raise ValueError
    except (OSError, ValueError):
        logger.debug(f"Generating certificates for CurveZMQ ({name})")
        _, secret_key_file = zmq.auth.create_certificates(certs_dir, name)
        public_key, secret_key = zmq.auth.load_certificate(secret_key_file)
        assert secret_key  # Satisfy mypy

    return public_key, secret_key


class BaseContext:
    def __init__(self, base_dir: str | os.PathLike, encrypted: bool = True) -> None:
        self.base_dir = base_dir
        self.encrypted = encrypted
        self._ctx = zmq.Context()
        if encrypted:
            self.certs_dir = os.path.join(base_dir, "certificates")
            os.makedirs(self.certs_dir, exist_ok=True)  # Ensure dir exists


class ServerContext(BaseContext):
    def __init__(self, base_dir: str | os.PathLike, encrypted: bool = True) -> None:
        super().__init__(base_dir, encrypted)
        self.auth_thread = None
        if encrypted:
            self._start_auth_thread()

    def _start_auth_thread(self):
        self.auth_thread = ThreadAuthenticator(self._ctx)
        self.auth_thread.start()
        self.auth_thread.configure_curve(domain="*", location=self.certs_dir)

    def socket(self, *args, **kwargs) -> zmq.Socket:
        sock = self._ctx.socket(*args, **kwargs)
        if self.encrypted:
            public_key, secret_key = _get_certificates(
                certs_dir=self.certs_dir, name="server"
            )
            sock.setsockopt(zmq.CURVE_PUBLICKEY, public_key)
            sock.setsockopt(zmq.CURVE_SECRETKEY, secret_key)
            sock.setsockopt(zmq.CURVE_SERVER, True)  # Must come before bind
        return sock

    def term(self):
        self._ctx.term()
        if self.auth_thread:
            self.auth_thread.stop()

    def destroy(self):
        self._ctx.destroy()
        if self.auth_thread:
            self.auth_thread.stop()

    def recreate(self):
        self.destroy()
        self._ctx = zmq.Context()
        if self.encrypted:
            self._start_auth_thread()


class ClientContext(BaseContext):
    def socket(self, *args, **kwargs) -> zmq.Socket:
        sock = self._ctx.socket(*args, **kwargs)
        if self.encrypted:
            public_key, secret_key = _get_certificates(
                certs_dir=self.certs_dir, name="client"
            )
            server_public_key, _ = _get_certificates(
                certs_dir=self.certs_dir, name="server"
            )
            sock.setsockopt(zmq.CURVE_PUBLICKEY, public_key)
            sock.setsockopt(zmq.CURVE_SECRETKEY, secret_key)
            sock.setsockopt(zmq.CURVE_SERVERKEY, server_public_key)
        return sock

    def term(self):
        self._ctx.term()

    def destroy(self):
        self._ctx.destroy()

    def recreate(self):
        self.destroy()
        self._ctx = zmq.Context()
