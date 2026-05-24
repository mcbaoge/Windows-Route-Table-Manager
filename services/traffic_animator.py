"""Real-time traffic flow particle animation system.

Renders animated particles along TopologyEdge lines to visualize
TX/RX traffic flow. Uses QTimer + dirty-rect repaint for CPU efficiency.

Design:
- ParticlePool manages a fixed pool of pre-allocated particles
- Particles move along edge lines with per-edge speed/color/density
- Bandwidth determines particle count, speed, color brightness
- Only dirty edges are repainted (no full-scene redraw)
"""
import math
import random
import time
from typing import Optional

from PyQt5.QtCore import Qt, QObject, QTimer, QPointF, QRectF
from PyQt5.QtGui import QPainter, QColor, QPen, QPolygonF


class Particle:
    __slots__ = (
        "edge_key", "progress", "speed", "direction",
        "size", "color", "lifetime", "age", "active",
    )

    def __init__(self):
        self.edge_key: str = ""
        self.progress: float = 0.0
        self.speed: float = 0.0
        self.direction: int = 1  # 1 = source->target, -1 = target->source
        self.size: float = 3.0
        self.color: QColor = QColor(255, 255, 255, 180)
        self.lifetime: float = 2.0
        self.age: float = 0.0
        self.active: bool = False

    def reset(self, edge_key: str, speed: float, direction: int,
              size: float, color: QColor, lifetime: float = 2.0):
        self.edge_key = edge_key
        self.progress = random.random() if direction > 0 else 1.0
        self.speed = speed
        self.direction = direction
        self.size = size
        self.color = color
        self.lifetime = lifetime
        self.age = 0.0
        self.active = True

    def update(self, dt: float) -> bool:
        if not self.active:
            return False
        self.age += dt
        if self.age > self.lifetime:
            self.active = False
            return False
        self.progress += self.speed * dt * self.direction
        if self.progress < 0 or self.progress > 1:
            self.active = False
            return False
        return True


class EdgeParticleSystem:
    """Manages particles for a single edge."""

    def __init__(self, edge_key: str, max_particles: int = 20):
        self.edge_key = edge_key
        self.particles: list[Particle] = [Particle() for _ in range(max_particles)]
        self._next_idx = 0
        self._active_count = 0
        self.last_spawn_time = 0.0
        self.spawn_interval = 0.1  # seconds between spawns
        self.base_speed = 0.3
        self.base_density = 3
        self.tx_color = QColor(46, 204, 113, 200)   # green for TX
        self.rx_color = QColor(52, 152, 219, 200)   # blue for RX
        self.current_line_width = 2.0

    def set_traffic_rate(self, rx_rate: float, tx_rate: float):
        """Adjust particle parameters based on bandwidth."""
        total_rate = rx_rate + tx_rate

        # Density: 3-20 particles based on rate (clamped)
        density = min(20, max(3, int(total_rate / 50000)))
        self.base_density = density

        # Speed: faster for higher rates
        self.base_speed = min(0.8, max(0.15, total_rate / 500000))

        # Line width: 1.5-8 based on rate
        self.current_line_width = min(8.0, max(1.5, 1.5 + total_rate / 200000))

        # Spawn interval
        self.spawn_interval = max(0.02, 0.15 - total_rate / 2000000)

    def spawn_particles(self, now: float, dt: float):
        """Spawn new particles if interval has elapsed."""
        if now - self.last_spawn_time < self.spawn_interval:
            return
        self.last_spawn_time = now

        count = min(self.base_density, 5)
        for _ in range(count):
            particle = self._get_free_particle()
            if particle is None:
                break
            direction = 1 if random.random() < 0.5 else -1
            color = self.tx_color if direction > 0 else self.rx_color
            size = random.uniform(2.0, 4.5)
            speed = self.base_speed * random.uniform(0.7, 1.3)
            particle.reset(
                self.edge_key, speed, direction, size, color,
                lifetime=random.uniform(1.0, 3.0),
            )
            self._active_count += 1

    def _get_free_particle(self) -> Optional[Particle]:
        for _ in range(len(self.particles)):
            p = self.particles[self._next_idx]
            self._next_idx = (self._next_idx + 1) % len(self.particles)
            if not p.active:
                return p
        return None

    def update(self, dt: float) -> bool:
        """Update all particles. Returns True if any particle is active."""
        still_active = False
        for p in self.particles:
            if p.update(dt):
                still_active = True
            elif p.active is False:
                pass
        if not still_active:
            self._active_count = 0
        else:
            self._active_count = sum(1 for p in self.particles if p.active)
        return self._active_count > 0

    def render(self, painter: QPainter, line_p1: QPointF, line_p2: QPointF):
        """Draw all active particles on this edge."""
        dx = line_p2.x() - line_p1.x()
        dy = line_p2.y() - line_p1.y()

        for p in self.particles:
            if not p.active:
                continue
            t = p.progress
            x = line_p1.x() + dx * t
            y = line_p1.y() + dy * t

            alpha = int(180 * (1 - p.age / p.lifetime))
            color = QColor(p.color)
            color.setAlpha(max(30, alpha))
            painter.setPen(Qt.NoPen)
            painter.setBrush(color)
            painter.drawEllipse(QPointF(x, y), p.size, p.size)


class TrafficAnimator(QObject):
    """Central traffic flow animation controller.

    Manages a global timer, delta-time tracking, and all edge particle systems.
    Emits update signals for dirty-region repaint.
    """

    def __init__(self, parent=None):
        super().__init__(parent)
        self._edge_systems: dict[str, EdgeParticleSystem] = {}
        self._timer = QTimer(self)
        self._timer.setInterval(16)  # ~60 FPS
        self._timer.timeout.connect(self._tick)
        self._last_time = time.time()
        self._running = False
        self._dirty_edges: set[str] = set()

    def start(self):
        if self._running:
            return
        self._running = True
        self._last_time = time.time()
        self._timer.start()

    def stop(self):
        self._running = False
        self._timer.stop()

    def register_edge(self, edge_key: str, max_particles: int = 20):
        if edge_key not in self._edge_systems:
            self._edge_systems[edge_key] = EdgeParticleSystem(edge_key, max_particles)

    def unregister_edge(self, edge_key: str):
        self._edge_systems.pop(edge_key, None)

    def unregister_all(self):
        self._edge_systems.clear()

    def update_edge_traffic(self, edge_key: str, rx_rate: float, tx_rate: float):
        system = self._edge_systems.get(edge_key)
        if system is None:
            return
        system.set_traffic_rate(rx_rate, tx_rate)

    def get_line_width(self, edge_key: str) -> float:
        system = self._edge_systems.get(edge_key)
        if system is None:
            return 2.0
        return system.current_line_width

    def get_particle_system(self, edge_key: str) -> Optional[EdgeParticleSystem]:
        return self._edge_systems.get(edge_key)

    def _tick(self):
        now = time.time()
        dt = min(now - self._last_time, 0.1)
        self._last_time = now

        for key, system in self._edge_systems.items():
            system.spawn_particles(now, dt)
            if system.update(dt):
                self._dirty_edges.add(key)

        if self._dirty_edges:
            self._emit_dirty()

    def _emit_dirty(self):
        """Override in subclass or connect signal."""
        pass

    @property
    def dirty_edges(self) -> set[str]:
        d = set(self._dirty_edges)
        self._dirty_edges.clear()
        return d

    @property
    def has_active_particles(self) -> bool:
        return any(s._active_count > 0 for s in self._edge_systems.values())
