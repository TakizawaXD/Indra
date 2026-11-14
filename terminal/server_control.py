"""
INDRA INFINITY SECURITY ∞ — API SERVER CONTROL (TERMINAL)
Starts / stops the optional REST API (protected by Infinity Shield) in a background
thread, fully controlled from the interactive terminal. There is no web interface:
all user interaction happens in the terminal.
"""

import socket
import threading
import time
from typing import Any, Dict, Optional

from core.config import settings


class APIServerController:
    """Owns a single uvicorn server running in a daemon thread."""

    def __init__(self):
        self._server = None
        self._thread: Optional[threading.Thread] = None
        self._port: Optional[int] = None
        self._error: Optional[str] = None

    @property
    def is_running(self) -> bool:
        return bool(self._thread and self._thread.is_alive() and self._server and self._server.started)

    @staticmethod
    def _port_in_use(host: str, port: int) -> bool:
        probe_host = "127.0.0.1" if host in ("0.0.0.0", "::") else host
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(0.5)
            return s.connect_ex((probe_host, port)) == 0

    def start(self, port: Optional[int] = None, timeout: float = 10.0) -> Dict[str, Any]:
        """Starts the API server. Returns a status dict; never raises."""
        if self.is_running:
            return {"ok": True, "message": f"El servidor API ya esta activo en http://{settings.HOST}:{self._port}"}

        import uvicorn  # imported lazily: the terminal works without starting the server

        if port:
            target_port = port
            if self._port_in_use(settings.HOST, target_port):
                return {"ok": False, "message": f"El puerto {target_port} ya esta en uso. Elige otro puerto."}
        else:
            # Default port busy -> try the next ones automatically
            candidates = [p for p in range(settings.PORT, settings.PORT + 11) if p <= 65535]
            target_port = next((p for p in candidates if not self._port_in_use(settings.HOST, p)), None)
            if target_port is None:
                return {"ok": False, "message": f"Puertos {candidates[0]}-{candidates[-1]} ocupados. Usa: server start <puerto>"}

        config = uvicorn.Config(
            "backend.main:app",
            host=settings.HOST,
            port=target_port,
            log_level="warning",
            access_log=False,
            proxy_headers=False,
        )
        self._server = uvicorn.Server(config)
        self._error = None
        self._port = target_port

        def _run():
            try:
                self._server.run()
            except BaseException as e:  # uvicorn may raise SystemExit on bind errors
                self._error = str(e) or e.__class__.__name__

        self._thread = threading.Thread(target=_run, name="indra-api-server", daemon=True)
        self._thread.start()

        deadline = time.time() + timeout
        while time.time() < deadline:
            if self._server.started:
                return {"ok": True, "message": f"Servidor API activo en http://{settings.HOST}:{target_port} (Infinity Shield protegiendo)"}
            if not self._thread.is_alive():
                break
            time.sleep(0.1)

        self._server.should_exit = True
        return {"ok": False, "message": f"No se pudo iniciar el servidor API: {self._error or 'tiempo de espera agotado'}"}

    def stop(self, timeout: float = 10.0) -> Dict[str, Any]:
        """Stops the API server gracefully."""
        if not self._thread or not self._thread.is_alive():
            self._server = None
            return {"ok": True, "message": "El servidor API no esta en ejecucion."}
        self._server.should_exit = True
        self._thread.join(timeout)
        stopped = not self._thread.is_alive()
        if stopped:
            self._server = None
        return {
            "ok": stopped,
            "message": "Servidor API detenido." if stopped else "El servidor API no respondio a tiempo a la orden de parada.",
        }

    def status(self) -> Dict[str, Any]:
        return {
            "running": self.is_running,
            "host": settings.HOST,
            "port": self._port if self.is_running else settings.PORT,
            "url": f"http://{settings.HOST}:{self._port}" if self.is_running else None,
            "api_token": "configurado" if settings.API_TOKEN else "no configurado",
        }


# Singleton used by the terminal
api_server = APIServerController()
