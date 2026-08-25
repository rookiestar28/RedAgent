"""Synthetic banner-only TCP services for the owned R107 qualification fixture."""

from __future__ import annotations

import socket
import threading


SERVICES = {
    8080: b"HTTP/1.1 200 OK\r\nServer: redagent-r107-fixture\r\nContent-Length: 0\r\n\r\n",
    8443: b"SSH-2.0-RedAgent_R107_Fixture\r\n",
}


def serve(port: int, banner: bytes) -> None:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind(("0.0.0.0", port))
        listener.listen(8)
        while True:
            connection, _ = listener.accept()
            with connection:
                connection.sendall(banner)


for service_port, service_banner in SERVICES.items():
    threading.Thread(target=serve, args=(service_port, service_banner), daemon=True).start()
threading.Event().wait()
