"""Bounded standard-library HTTP requests; no retries or redirects."""
import http.client
import socket
import select
import ssl
import threading
import time
import urllib.request


class RequestStopped(Exception):
    pass


class RequestBudget:
    """Interrupt socket I/O even when headers or body arrive continuously.

    The OS resolver may still block before a socket exists. No request is sent
    after that resolution completes if the deadline/cancellation already fired.
    """
    def __init__(self, seconds, cancel=None):
        self.deadline = time.monotonic() + seconds
        self.cancel = cancel
        self.reason = None
        self.sock = None
        self.lock = threading.Lock()
        self.finished = threading.Event()
        self.watcher = threading.Thread(target=self._watch, daemon=True)

    def __enter__(self):
        self.watcher.start()
        return self

    def check(self):
        if self.cancel is not None and self.cancel.is_set():
            self.reason = 'cancelled'
        elif time.monotonic() >= self.deadline and self.reason is None:
            self.reason = 'deadline_exceeded'
        if self.reason:
            raise RequestStopped(self.reason)

    def _watch(self):
        while not self.finished.wait(0.02):
            try:
                self.check()
            except RequestStopped:
                with self.lock:
                    if self.sock is not None:
                        try:
                            # Bypass SSLSocket.shutdown: clearing its SSL object
                            # can wait on an in-progress TLS handshake on Windows.
                            socket.socket.shutdown(self.sock, socket.SHUT_RDWR)
                        except OSError:
                            pass
                return

    def connection(self, cls, *args, **kwargs):
        self.check()
        kwargs['timeout'] = max(0.001, self.deadline - time.monotonic())
        conn = cls(*args, **kwargs)
        create = conn._create_connection
        def connect(*a, **kw):
            self.check()
            sock = create(*a, **kw)
            with self.lock:
                self.sock = sock
            try:
                self.check()
            except RequestStopped:
                sock.close()
                raise
            return sock
        conn._create_connection = connect
        original_connect = conn.connect
        def connected():
            original_connect()
            # HTTPS wraps (and detaches) the original socket during connect.
            with self.lock:
                self.sock = conn.sock
            try:
                self.check()
            except RequestStopped:
                conn.close()
                raise
        conn.connect = connected
        return conn

    def opener(self):
        budget = self
        class TLSSocket(ssl.SSLSocket):
            # Blocking SSL I/O is not reliably interrupted by shutdown on all
            # platforms. Poll the nonblocking socket so cancellation and the
            # deadline are checked during handshake, upload and response reads.
            def _bounded(self, operation, *args, **kwargs):
                while True:
                    budget.check()
                    try:
                        return operation(*args, **kwargs)
                    except ssl.SSLWantReadError:
                        select.select([self], [], [], .02)
                    except ssl.SSLWantWriteError:
                        select.select([], [self], [], .02)

            def do_handshake(self, *args, **kwargs):
                return self._bounded(super().do_handshake, *args, **kwargs)

            def read(self, *args, **kwargs):
                return self._bounded(super().read, *args, **kwargs)

            def send(self, *args, **kwargs):
                return self._bounded(super().send, *args, **kwargs)

        class TLSConnection(http.client.HTTPSConnection):
            def connect(self):
                http.client.HTTPConnection.connect(self)
                hostname = self._tunnel_host or self.host
                # Attach the wrapped socket before the handshake, so both TLS
                # negotiation and subsequent HTTPS reads can be interrupted.
                socket_class = self._context.sslsocket_class
                try:
                    self._context.sslsocket_class = TLSSocket
                    self.sock = self._context.wrap_socket(self.sock, server_hostname=hostname,
                                                         do_handshake_on_connect=False)
                finally:
                    self._context.sslsocket_class = socket_class
                with budget.lock:
                    budget.sock = self.sock
                budget.check()
                self.sock.setblocking(False)
                self.sock.do_handshake()
        class HTTP(urllib.request.HTTPHandler):
            def http_open(self, req):
                return self.do_open(lambda *a, **k: budget.connection(http.client.HTTPConnection, *a, **k), req)
        class HTTPS(urllib.request.HTTPSHandler):
            def https_open(self, req):
                return self.do_open(lambda *a, **k: budget.connection(TLSConnection, *a, **k),
                                    req, context=self._context)
        class NoRedirect(urllib.request.HTTPRedirectHandler):
            def redirect_request(self, *args):
                return None
        return urllib.request.build_opener(HTTP(), HTTPS(), NoRedirect())

    def __exit__(self, *args):
        self.finished.set()
        self.watcher.join()


def read_chunks(response, budget, raw, limit):
    """Keep a bounded partial body even on cancellation or a read failure."""
    while True:
        budget.check()
        block = response.read1(min(65536, limit - len(raw) + 1))
        if block:
            available = limit - len(raw)
            raw.extend(block[:available])
            if len(block) > available:
                raise RequestStopped('response_size_limit')
            yield block
        budget.check()
        if not block:
            break
