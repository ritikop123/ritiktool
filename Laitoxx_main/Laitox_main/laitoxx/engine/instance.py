"""Single attack state machine."""

import datetime
import random
import threading


class AttackInstance:
    """Tracks the lifecycle and metrics of one running attack.

    ``native_instance`` is either a ``GoBypassInstance``, a C++ ``laitoxx_core``
    instance, or ``None`` (mock/fallback mode).
    """

    _next_id = 1
    _id_lock = threading.Lock()

    def __init__(
        self,
        attack_type_gui: str,
        backend_code: str,
        target: str,
        port: int,
        duration: int,
        threads: int,
        rps: int,
        native_instance=None,
    ) -> None:
        with AttackInstance._id_lock:
            self.id = AttackInstance._next_id
            AttackInstance._next_id += 1

        self.attack_type    = attack_type_gui
        self.backend_code   = backend_code
        self.target         = target
        self.port           = port
        self.duration       = duration
        self.threads        = threads
        self.rps            = rps
        self.status         = "Running"
        self.started_at     = datetime.datetime.now()
        self._native        = native_instance
        self.pps            = 0
        self.bps            = 0.0
        self.connections    = 0
        self._prev_packets  = 0

    # ── Derived properties ────────────────────────────────────────────────

    @property
    def display_target(self) -> str:
        return f"{self.target}:{self.port}"

    @property
    def elapsed(self) -> float:
        return (datetime.datetime.now() - self.started_at).total_seconds()

    @property
    def progress_pct(self) -> float:
        if self.duration <= 0:
            return 0.0
        return min(100.0, self.elapsed / self.duration * 100)

    # ── Lifecycle ─────────────────────────────────────────────────────────

    def tick(self) -> None:
        """Update metrics; called once per second by the manager tick loop."""
        if self.status != "Running":
            return

        if self.duration and self.elapsed >= self.duration:
            self.stop()
            self.status = "Finished"
            return

        if self._native:
            packets_now     = self._native.get_packets_sent()
            self.pps        = max(0, packets_now - self._prev_packets)
            self._prev_packets = packets_now
            self.bps        = round(self.pps * 500 / 1_000_000, 1)
            per_thread_rps  = self.rps // self.threads if self.rps else 1
            self.connections = min(self.threads, self.pps // max(per_thread_rps, 1))
        else:
            # Mock mode: synthesize plausible values
            base = self.rps * self.threads // 10
            self.pps = max(0, base + random.randint(-base // 5, base // 5)) if base else 0
            self.bps = round(self.pps * 0.0005, 1)
            self.connections = self.threads

    def stop(self) -> None:
        if self._native:
            self._native.stop()
        self.status      = "Stopped"
        self.pps         = 0
        self.bps         = 0.0
        self.connections = 0
