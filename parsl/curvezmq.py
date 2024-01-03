import logging
import os

import zmq
import zmq.auth
from zmq.auth.thread import ThreadAuthenticator

logger = logging.getLogger(__name__)


def get_certificates(certs_dir: str | os.PathLike, name: str) -> tuple[bytes, bytes]:
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


class CurveZMQBase:
    def __init__(self, base_dir: str | os.PathLike) -> None:
        self.certs_dir = os.path.join(base_dir, "certificates")
        os.makedirs(self.certs_dir, exist_ok=True)  # Ensure it exists
        self.ctx = zmq.Context()
        self._sockets: set[zmq.Socket] = set()

    def term(self):
        for sock in self._sockets:
            sock.close()
        self.ctx.term()

    def destroy(self):
        self.ctx.destroy()


class CurveZMQServer(CurveZMQBase):
    def __init__(self, base_dir: str | os.PathLike) -> None:
        super().__init__(base_dir)
        self.auth_thread = ThreadAuthenticator(self.ctx)
        self.auth_thread.start()
        self.auth_thread.configure_curve(domain="*", location=self.certs_dir)

    def socket(self, *args, **kwargs) -> zmq.Socket:
        public_key, secret_key = get_certificates(
            certs_dir=self.certs_dir, name="server"
        )

        sock = self.ctx.socket(*args, **kwargs)
        sock.setsockopt(zmq.CURVE_PUBLICKEY, public_key)
        sock.setsockopt(zmq.CURVE_SECRETKEY, secret_key)
        sock.setsockopt(zmq.CURVE_SERVER, True)  # Must come before bind

        self._sockets.add(sock)
        return sock

    def term(self):
        super().term()
        self.auth_thread.stop()

    def destroy(self):
        super().destroy()
        self.auth_thread.stop()


class CurveZMQClient(CurveZMQBase):
    def socket(self, *args, **kwargs) -> zmq.Socket:
        public_key, secret_key = get_certificates(
            certs_dir=self.certs_dir, name="client"
        )
        server_public_key, _ = get_certificates(certs_dir=self.certs_dir, name="server")

        sock = self.ctx.socket(*args, **kwargs)
        sock.setsockopt(zmq.CURVE_PUBLICKEY, public_key)
        sock.setsockopt(zmq.CURVE_SECRETKEY, secret_key)
        sock.setsockopt(zmq.CURVE_SERVERKEY, server_public_key)

        self._sockets.add(sock)
        return sock
