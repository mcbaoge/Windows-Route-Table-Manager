"""Real-time network topology visualization with modern dynamic graphics.

Incremental rendering — no scene.clear().
Supports:
  - Traffic particle animation (TX/RX flow)
  - Bandwidth labels with auto-scaling
  - RTT/loss color-coded nodes and edges
  - Default route fade-in/out transitions
  - Force-directed layout
  - Minimap
  - Node glow/shadow effects
  - Security alert flashing
  - High-DPI / 1000+ node support
"""
import logging
import math
import time
from typing import Optional

from PyQt5.QtWidgets import (
    QGraphicsView, QGraphicsScene, QGraphicsItem,
    QGraphicsEllipseItem, QGraphicsTextItem, QGraphicsLineItem,
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton,
    QSizePolicy, QFrame,
)
from PyQt5.QtCore import Qt, QRectF, QPointF, QTimer, QLineF, pyqtSignal
from PyQt5.QtGui import (
    QBrush, QPen, QColor, QFont, QPainter, QRadialGradient,
    QFontMetrics, QPolygonF, QPainterPath,
)

from services.topology_engine import (
    build_topology, auto_layout, NetworkGraph, TopologyNode, TopologyEdge,
    NodeType, LinkStatus, diff_graph, GraphDiff,
)
from services.traffic_animator import TrafficAnimator, EdgeParticleSystem
from services.bandwidth_monitor import InterfaceBandwidthTracker, format_bandwidth

logger = logging.getLogger(__name__)

# Colors
COLOR_UP = QColor("#27ae60")
COLOR_DOWN = QColor("#e74c3c")
COLOR_DEGRADED = QColor("#f39c12")
COLOR_DEFAULT = QColor("#2ecc71")
COLOR_NORMAL = QColor("#3498db")
COLOR_TEXT = QColor("#ecf0f1")
COLOR_BG = QColor("#1a1a2e")
COLOR_BG_GRADIENT_1 = QColor("#16213e")
COLOR_BG_GRADIENT_2 = QColor("#0f3460")
COLOR_EDGE = QColor("#7f8c8d")
COLOR_LOCAL = QColor("#9b59b6")
COLOR_VPN = QColor("#e67e22")
COLOR_ALERT = QColor("#e74c3c")

NODE_RADIUS = 22
NODE_DIAMETER = NODE_RADIUS * 2

# RTT thresholds
RTT_GREEN = 20.0
RTT_YELLOW = 80.0
RTT_RED = 150.0
LOSS_ALERT = 5.0  # %


def _rtt_color(rtt_ms: float) -> QColor:
    if rtt_ms < 0:
        return COLOR_NORMAL
    if rtt_ms < RTT_GREEN:
        return QColor("#27ae60")
    elif rtt_ms < RTT_YELLOW:
        return QColor("#f1c40f")
    elif rtt_ms < RTT_RED:
        return QColor("#e67e22")
    return QColor("#e74c3c")


def _color_for_status(status: LinkStatus, is_default: bool = False,
                       rtt: float = 0.0, loss: float = 0.0,
                       alerts: list = None) -> QColor:
    if alerts:
        return COLOR_ALERT
    if loss > LOSS_ALERT:
        return QColor("#e74c3c")  # red on high loss
    if is_default:
        return COLOR_DEFAULT
    if status == LinkStatus.DOWN:
        return COLOR_DOWN
    if status == LinkStatus.DEGRADED:
        return COLOR_DEGRADED
    if status == LinkStatus.UP and rtt > 0:
        return _rtt_color(rtt)
    if status == LinkStatus.UP:
        return COLOR_NORMAL
    return COLOR_EDGE


def _elide_text(text: str, max_len: int = 16) -> str:
    if len(text) > max_len:
        return text[:max_len - 2] + ".."
    return text


# ---------------------------------------------------------------------------
# Graphics Items
# ---------------------------------------------------------------------------

class TopologyNodeItem(QGraphicsEllipseItem):
    """Network topology node with glow, shadow, RTT coloring, alerts."""

    def __init__(self, node: TopologyNode, pos: QPointF, parent=None):
        rect = QRectF(-NODE_RADIUS, -NODE_RADIUS, NODE_DIAMETER, NODE_DIAMETER)
        super().__init__(rect, parent)
        self.node_data = node
        self.setPos(pos)
        self.setZValue(10)
        self._connected_edges: list["TopologyEdgeItem"] = []
        self._hovered = False
        self._alert_timer = 0.0
        self._alert_visible = False
        self._glow_intensity = 0.0
        self._label = ""
        self._sub_label = ""

        self._update_appearance()

        # Label
        label = _elide_text(node.label, 18)
        self._label_item = QGraphicsTextItem(label, self)
        self._label_item.setDefaultTextColor(COLOR_TEXT)
        font = QFont("Microsoft YaHei UI", 8)
        self._label_item.setFont(font)
        self._label_item.setPos(-self._label_item.boundingRect().width() / 2, NODE_RADIUS + 2)

        # Sub-label (IP/bandwidth)
        sub = self._get_sub_label()
        if sub:
            self._sub_item = QGraphicsTextItem(sub, self)
            self._sub_item.setDefaultTextColor(QColor("#95a5a6"))
            sf = QFont("Consolas", 7)
            self._sub_item.setFont(sf)
            self._sub_item.setPos(-self._sub_item.boundingRect().width() / 2, NODE_RADIUS + 16)

        # Bandwidth label
        self._bw_label = QGraphicsTextItem("", self)
        self._bw_label.setDefaultTextColor(QColor("#2ecc71"))
        bf = QFont("Consolas", 7, QFont.Bold)
        self._bw_label.setFont(bf)
        self._bw_label.setPos(-NODE_RADIUS * 2, -NODE_RADIUS - 24)

        # RTT label
        self._rtt_label = QGraphicsTextItem("", self)
        self._rtt_label.setDefaultTextColor(QColor("#95a5a6"))
        rf = QFont("Consolas", 7)
        self._rtt_label.setFont(rf)
        self._rtt_label.setPos(NODE_RADIUS + 4, -NODE_RADIUS - 12)

        self.setFlag(QGraphicsItem.ItemIsMovable, True)
        self.setFlag(QGraphicsItem.ItemSendsGeometryChanges, True)
        self.setAcceptHoverEvents(True)

    def _get_sub_label(self) -> str:
        if self.node_data.ip_addresses:
            return self.node_data.ip_addresses[0]
        if self.node_data.gateway:
            return self.node_data.gateway
        return ""

    def _update_appearance(self):
        color = _color_for_status(
            self.node_data.status, self.node_data.is_default,
            self.node_data.rtt_ms, self.node_data.loss_percent,
            self.node_data.security_alerts,
        )
        self._brush = QBrush(color)
        self._pen = QPen(QColor("#2c3e50"), 2)
        if self.node_data.is_default:
            self._pen = QPen(COLOR_DEFAULT, 3)
        if self.node_data.loss_percent > LOSS_ALERT:
            self._pen = QPen(COLOR_ALERT, 3)

        # Glow
        self._glow_color = QColor(color)
        self._glow_color.setAlpha(60)

        self.setBrush(self._brush)
        self.setPen(self._pen)

    def update_data(self, node: TopologyNode):
        """Hot-update node appearance without recreation."""
        self.node_data = node
        self._update_appearance()
        self.update()

    def update_bandwidth(self, rx_rate: float, tx_rate: float):
        """Update bandwidth label with auto-scaling."""
        total = rx_rate + tx_rate
        if total > 1024:
            bw_str = f"↓{format_bandwidth(rx_rate)}  ↑{format_bandwidth(tx_rate)}"
            self._bw_label.setPlainText(bw_str)
            self._bw_label.setPos(-self._bw_label.boundingRect().width() / 2, -NODE_RADIUS - 24)
            self._bw_label.show()
        else:
            self._bw_label.hide()

    def update_rtt(self, rtt_ms: float, loss: float):
        """Update RTT label."""
        if rtt_ms > 0:
            color = _rtt_color(rtt_ms)
            txt = f"{rtt_ms:.0f}ms"
            if loss > 0:
                txt += f" ⚠{loss:.0f}%"
            self._rtt_label.setDefaultTextColor(color)
            self._rtt_label.setPlainText(txt)
            self._rtt_label.show()
        else:
            self._rtt_label.hide()

    def itemChange(self, change, value):
        if change == QGraphicsItem.ItemPositionHasChanged:
            for edge in self._connected_edges:
                edge.updateLine()
        return super().itemChange(change, value)

    def hoverEnterEvent(self, event):
        self._hovered = True
        self._pen.setWidth(4)
        self.setPen(self._pen)
        super().hoverEnterEvent(event)

    def hoverLeaveEvent(self, event):
        self._hovered = False
        base = 3 if self.node_data.is_default else 2
        self._pen = QPen(QColor("#2c3e50"), base)
        if self.node_data.loss_percent > LOSS_ALERT:
            self._pen.setColor(COLOR_ALERT)
            self._pen.setWidth(3)
        self.setPen(self._pen)
        super().hoverLeaveEvent(event)

    def paint(self, painter, option, widget=None):
        # Outer glow
        glow_radius = NODE_RADIUS * 2.0 if self._hovered else NODE_RADIUS * 1.3
        glow = QRadialGradient(QPointF(0, 0), glow_radius)
        if self._hovered:
            glow.setColorAt(0, QColor(255, 255, 255, 50))
            glow.setColorAt(0.5, self._glow_color)
            glow.setColorAt(1, QColor(255, 255, 255, 0))
        else:
            glow.setColorAt(0, self._glow_color)
            glow.setColorAt(1, QColor(255, 255, 255, 0))
        painter.setBrush(QBrush(glow))
        painter.setPen(Qt.NoPen)
        painter.drawEllipse(self.rect().adjusted(-8, -8, 8, 8))

        # Alert flash effect
        if self.node_data.security_alerts:
            now = time.time()
            if now - self._alert_timer > 0.5:
                self._alert_visible = not self._alert_visible
                self._alert_timer = now
            if self._alert_visible:
                flash = QRadialGradient(QPointF(0, 0), NODE_RADIUS * 1.5)
                flash.setColorAt(0, QColor(231, 76, 60, 180))
                flash.setColorAt(1, QColor(231, 76, 60, 0))
                painter.setBrush(QBrush(flash))
                painter.setPen(Qt.NoPen)
                painter.drawEllipse(self.rect().adjusted(-4, -4, 4, 4))

        super().paint(painter, option, widget)

        # Icon hint (first char)
        painter.setPen(COLOR_TEXT)
        font = QFont("Segoe UI", 11, QFont.Bold)
        painter.setFont(font)
        icon = self.node_data.label[0] if self.node_data.label else "?"
        painter.drawText(self.rect(), Qt.AlignCenter, icon)

    def boundingRect(self):
        r = super().boundingRect()
        return r.adjusted(-18, -18, 18, 36)


class TopologyEdgeItem(QGraphicsLineItem):
    """Edge with traffic animation, bandwidth label, RTT color, fade transitions."""

    def __init__(self, edge: TopologyEdge, src_item: TopologyNodeItem,
                 dst_item: TopologyNodeItem, animator: Optional[TrafficAnimator] = None,
                 parent=None):
        super().__init__(parent)
        self.edge_data = edge
        self._src_item = src_item
        self._dst_item = dst_item
        self._animator = animator
        self._fade_alpha = 1.0
        self._fade_target = 1.0
        self._highlight_alpha = 0.0
        self._is_new = edge.is_new
        self._is_fading = edge.is_fading

        self.edge_key = f"{edge.source_id}->{edge.target_id}"

        # Bandwidth label at midpoint — must be created before updateLine()
        self._bw_label_item = QGraphicsTextItem("", parent=None)
        self._bw_label_item.setDefaultTextColor(QColor("#2ecc71"))
        bf = QFont("Consolas", 7, QFont.Bold)
        self._bw_label_item.setFont(bf)
        self._bw_label_item.setZValue(5)

        self.updateLine()

        color = _color_for_status(edge.status, edge.is_default, edge.rtt_ms, edge.loss_percent)
        self._base_color = color
        pen = QPen(color, 2)
        if edge.is_default:
            pen.setWidth(3)
        if edge.status == LinkStatus.DOWN:
            pen.setStyle(Qt.DashLine)
        self.setPen(pen)
        self.setZValue(1)

        # Register with animator
        if self._animator:
            self._animator.register_edge(self.edge_key)

    def updateLine(self):
        src = self._src_item.pos()
        dst = self._dst_item.pos()
        self.prepareGeometryChange()
        self.setLine(src.x(), src.y(), dst.x(), dst.y())
        self._update_label_pos()

    def _update_label_pos(self):
        line = self.line()
        mid = QPointF((line.x1() + line.x2()) / 2, (line.y1() + line.y2()) / 2)
        self._bw_label_item.setPos(mid.x() - self._bw_label_item.boundingRect().width() / 2,
                                   mid.y() - 8)

    def update_edge_data(self, edge: TopologyEdge):
        """Hot-update edge appearance."""
        self.edge_data = edge
        color = _color_for_status(edge.status, edge.is_default, edge.rtt_ms, edge.loss_percent)
        self._base_color = color
        pen = self.pen()
        pen.setColor(color)
        if edge.is_default:
            pen.setWidth(3)
            pen.setStyle(Qt.SolidLine)
        elif edge.status == LinkStatus.DOWN:
            pen.setStyle(Qt.DashLine)
        else:
            pen.setStyle(Qt.SolidLine)
        self.setPen(pen)

        # Handle transition effects
        if edge.is_new:
            self._fade_alpha = 0.0
            self._fade_target = 1.0
            self._highlight_alpha = 1.0
        if edge.is_fading:
            self._fade_target = 0.0

    def update_bandwidth(self, rx_rate: float, tx_rate: float):
        """Update bandwidth label at edge midpoint."""
        total = rx_rate + tx_rate
        if total > 1024:
            lines = []
            if tx_rate > 1024:
                lines.append(f"↑ {format_bandwidth(tx_rate)}")
            if rx_rate > 1024:
                lines.append(f"↓ {format_bandwidth(rx_rate)}")
            text = "\n".join(lines) if lines else ""
            self._bw_label_item.setPlainText(text)
            self._bw_label_item.setDefaultTextColor(QColor("#2ecc71"))
            self._update_label_pos()
            self._bw_label_item.show()
        else:
            self._bw_label_item.hide()

    def paint(self, painter, option, widget=None):
        line = self.line()
        if line.isNull():
            return

        # Fade transition
        if self._fade_alpha < 1.0:
            self._fade_alpha += 0.02  # fade in over ~50 frames
            if self._fade_alpha > 1.0:
                self._fade_alpha = 1.0
        if self._is_fading and self._fade_alpha > 0:
            self._fade_alpha -= 0.02
            if self._fade_alpha < 0:
                self._fade_alpha = 0

        pen = self.pen()
        color = pen.color()
        color.setAlpha(int(color.alpha() * self._fade_alpha))
        pen.setColor(color)
        self.setPen(pen)

        # Highlight glow for new default routes
        if self._highlight_alpha > 0:
            glow_pen = QPen(QColor(46, 204, 113, int(60 * self._highlight_alpha)), pen.width() + 4)
            painter.setPen(glow_pen)
            painter.drawLine(line)
            self._highlight_alpha -= 0.01
            if self._highlight_alpha < 0:
                self._highlight_alpha = 0

        super().paint(painter, option, widget)

        # Draw arrow at midpoint
        mid = QPointF((line.x1() + line.x2()) / 2, (line.y1() + line.y2()) / 2)
        angle = math.atan2(line.y2() - line.y1(), line.x2() - line.x1())

        arrow_size = 8
        arrow_p1 = QPointF(
            mid.x() - arrow_size * math.cos(angle - math.pi / 6),
            mid.y() - arrow_size * math.sin(angle - math.pi / 6),
        )
        arrow_p2 = QPointF(
            mid.x() - arrow_size * math.cos(angle + math.pi / 6),
            mid.y() - arrow_size * math.sin(angle + math.pi / 6),
        )

        painter.setBrush(self._base_color)
        painter.setPen(Qt.NoPen)
        painter.drawPolygon(mid, arrow_p1, arrow_p2)

        # Traffic particles
        if self._animator:
            particle_sys = self._animator.get_particle_system(self.edge_key)
            if particle_sys:
                particle_sys.render(painter,
                                    QPointF(line.x1(), line.y1()),
                                    QPointF(line.x2(), line.y2()))

                # Dynamic line width based on traffic
                bw = particle_sys.current_line_width
                p = self.pen()
                p.setWidthF(bw)
                # Don't override for default edges
                if not self.edge_data.is_default:
                    self.setPen(p)

    def set_scene(self, scene):
        """Add bandwidth label to scene."""
        if scene:
            scene.addItem(self._bw_label_item)

    def cleanup(self):
        """Remove bandwidth label and unregister animator."""
        if self._bw_label_item and self._bw_label_item.scene():
            self._bw_label_item.scene().removeItem(self._bw_label_item)
        if self._animator:
            self._animator.unregister_edge(self.edge_key)


# ---------------------------------------------------------------------------
# Minimap
# ---------------------------------------------------------------------------

class MinimapWidget(QFrame):
    """Minimap overview of the entire topology."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setFixedSize(180, 140)
        self.setStyleSheet("background: rgba(0,0,0,160); border: 1px solid #3c3c3c; border-radius: 4px;")
        self._scene_rect = QRectF()
        self._node_positions: list[QPointF] = []
        self._view_rect = QRectF()
        self.setAttribute(Qt.WA_TransparentForMouseEvents, False)

    def update_minimap(self, scene_rect: QRectF, node_positions: list[QPointF], view_rect: QRectF):
        self._scene_rect = scene_rect
        self._node_positions = node_positions
        self._view_rect = view_rect
        self.update()

    def paintEvent(self, event):
        painter = QPainter(self)
        painter.setRenderHint(QPainter.Antialiasing)

        w, h = self.width(), self.height()
        painter.fillRect(0, 0, w, h, QColor(0, 0, 0, 160))

        sr = self._scene_rect
        if sr.isNull() or sr.width() <= 0 or sr.height() <= 0:
            return

        # Scale to minimap
        scale_x = w / sr.width()
        scale_y = h / sr.height()
        scale = min(scale_x, scale_y) * 0.85
        ox = (w - sr.width() * scale) / 2
        oy = (h - sr.height() * scale) / 2

        # Draw nodes
        painter.setPen(Qt.NoPen)
        painter.setBrush(QColor(52, 152, 219, 180))
        for pos in self._node_positions:
            x = ox + (pos.x() - sr.x()) * scale
            y = oy + (pos.y() - sr.y()) * scale
            painter.drawEllipse(QPointF(x, y), 2, 2)

        # Draw viewport rectangle
        if not self._view_rect.isNull():
            vx = ox + (self._view_rect.x() - sr.x()) * scale
            vy = oy + (self._view_rect.y() - sr.y()) * scale
            vw = self._view_rect.width() * scale
            vh = self._view_rect.height() * scale
            painter.setPen(QPen(QColor(255, 255, 255, 120), 1))
            painter.setBrush(QColor(255, 255, 255, 20))
            painter.drawRect(int(vx), int(vy), int(vw), int(vh))


# ---------------------------------------------------------------------------
# Custom Graphics View
# ---------------------------------------------------------------------------

class TopologyGraphicsView(QGraphicsView):
    """QGraphicsView with smooth zoom, minimap support, and wheel zoom."""

    zoom_changed = pyqtSignal(float)
    viewport_changed = pyqtSignal()

    def __init__(self, scene, parent=None):
        super().__init__(scene, parent)
        self.setRenderHints(QPainter.Antialiasing | QPainter.SmoothPixmapTransform)
        self.setDragMode(QGraphicsView.ScrollHandDrag)
        self.setTransformationAnchor(QGraphicsView.AnchorUnderMouse)
        self.setViewportUpdateMode(QGraphicsView.SmartViewportUpdate)
        self.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        self.setVerticalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        self.setStyleSheet("border: none; background: transparent;")
        self._current_zoom = 1.0

    def wheelEvent(self, event):
        factor = 1.15
        if event.angleDelta().y() > 0:
            self.scale(factor, factor)
            self._current_zoom *= factor
        else:
            self.scale(1 / factor, 1 / factor)
            self._current_zoom /= factor
        self.zoom_changed.emit(self._current_zoom)
        self.viewport_changed.emit()

    def resizeEvent(self, event):
        super().resizeEvent(event)
        self.viewport_changed.emit()


# ---------------------------------------------------------------------------
# Main Topology Widget
# ---------------------------------------------------------------------------

class TopologyWidget(QFrame):
    """Main network topology visualization widget with real-time updates."""

    refresh_requested = pyqtSignal()

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setFrameStyle(QFrame.StyledPanel)

        self._graph: Optional[NetworkGraph] = None
        self._prev_graph: Optional[NetworkGraph] = None
        self._node_items: dict[str, TopologyNodeItem] = {}
        self._edge_items: list[TopologyEdgeItem] = []
        self._edge_item_map: dict[str, TopologyEdgeItem] = {}
        self._positions: dict[str, QPointF] = {}

        # Animator
        self._animator = TrafficAnimator(self)

        # Layout
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)

        # Top bar
        top_bar = QHBoxLayout()
        title = QLabel("网络拓扑")
        title.setStyleSheet("color: #ecf0f1; font-size: 14px; font-weight: bold; padding: 8px;")
        top_bar.addWidget(title)
        top_bar.addStretch()

        info_label = QLabel("粒子动画 | 带宽监控 | RTT 延迟")
        info_label.setStyleSheet("color: #7f8c8d; font-size: 10px;")
        top_bar.addWidget(info_label)
        top_bar.addSpacing(12)

        self._fps_label = QLabel("60 FPS")
        self._fps_label.setStyleSheet("color: #95a5a6; font-size: 10px;")
        top_bar.addWidget(self._fps_label)
        top_bar.addSpacing(8)

        btn_refresh = QPushButton("刷新")
        btn_refresh.setFixedWidth(60)
        btn_refresh.clicked.connect(self.refresh)
        btn_refresh.setStyleSheet("""
            QPushButton { background: #3498db; color: white; border: none;
                          padding: 4px 12px; border-radius: 3px; }
            QPushButton:hover { background: #2980b9; }
        """)
        top_bar.addWidget(btn_refresh)
        layout.addLayout(top_bar)

        # Scene + View
        self._scene = QGraphicsScene(self)
        self._scene.setBackgroundBrush(QBrush(COLOR_BG))

        self._view = TopologyGraphicsView(self._scene)
        self._view.viewport_changed.connect(self._update_minimap)
        layout.addWidget(self._view, 1)

        # Minimap overlay
        self._minimap = MinimapWidget(self)
        self._minimap.move(8, 8)

        # Legend
        legend = QHBoxLayout()
        legend.setContentsMargins(8, 4, 8, 4)
        for color, text in [
            (COLOR_DEFAULT, "默认出口"),
            (COLOR_NORMAL, "在线"),
            (COLOR_DOWN, "离线"),
            (COLOR_DEGRADED, "高延迟"),
            (QColor("#27ae60"), "低延迟"),
            (QColor("#f1c40f"), "中延迟"),
            (QColor("#e74c3c"), "高延迟/丢包"),
        ]:
            lbl = QLabel(text)
            lbl.setStyleSheet(f"color: {color.name()}; font-size: 10px; padding: 2px 6px;")
            legend.addWidget(lbl)
        legend.addStretch()
        layout.addLayout(legend)

        # Timers
        self._refresh_timer = QTimer(self)
        self._refresh_timer.setInterval(5000)
        self._refresh_timer.timeout.connect(self._incremental_refresh)

        self._anim_timer = QTimer(self)
        self._anim_timer.setInterval(16)
        self._anim_timer.timeout.connect(self._tick_animation)

        self._stats_timer = QTimer(self)
        self._stats_timer.setInterval(1000)
        self._stats_timer.timeout.connect(self._update_stats)

        # FPS tracking
        self._frame_count = 0
        self._fps_time = time.time()

        # Bandwidth tracking per interface
        self._bw_trackers: dict[str, "InterfaceBandwidthTracker"] = {}

    def start(self):
        self.refresh()
        self._refresh_timer.start()
        self._anim_timer.start()
        self._stats_timer.start()
        self._animator.start()

    def stop(self):
        self._refresh_timer.stop()
        self._anim_timer.stop()
        self._stats_timer.stop()
        self._animator.stop()

    def refresh(self):
        """Full rebuild of topology."""
        try:
            new_graph = build_topology()
            self._apply_graph(new_graph)
        except Exception as e:
            logger.error("Topology refresh error: %s", e)
            import traceback
            traceback.print_exc()

    def _incremental_refresh(self):
        """Incremental refresh — no scene.clear()."""
        try:
            new_graph = build_topology()
            if self._prev_graph is None:
                self._apply_graph(new_graph)
                return

            diff = diff_graph(self._prev_graph, new_graph)
            if (not diff.added_nodes and not diff.removed_nodes
                    and not diff.changed_nodes
                    and not diff.added_edges and not diff.removed_edges
                    and not diff.changed_edges):
                # Only bandwidth/rtt update needed
                self._update_live_stats(new_graph)
                return

            # Apply diff
            self._apply_diff(diff, new_graph)
        except Exception as e:
            logger.debug("Incremental refresh error: %s", e)

    def _apply_graph(self, graph: NetworkGraph):
        """Full graph application (initial render)."""
        self._prev_graph = graph
        self._graph = graph

        # Clean up old items
        for item in self._edge_items:
            item.cleanup()
        self._scene.clear()
        self._node_items.clear()
        self._edge_items.clear()
        self._edge_item_map.clear()
        self._positions.clear()
        self._animator.unregister_all()

        if not graph or not graph.nodes:
            txt = self._scene.addText("无法获取网络拓扑数据")
            txt.setDefaultTextColor(QColor("#7f8c8d"))
            txt.setPos(-100, 0)
            return

        # Layout
        view_rect = self._view.viewport().rect()
        canvas_w = max(view_rect.width(), 600)
        canvas_h = max(view_rect.height(), 400)
        positions = auto_layout(graph, float(canvas_w), float(canvas_h))
        self._positions = {k: QPointF(x, y) for k, (x, y) in positions.items()}

        # Create node items
        for nid, node in graph.nodes.items():
            pos = self._positions.get(nid, QPointF(0, 0))
            item = TopologyNodeItem(node, pos)
            self._scene.addItem(item)
            self._node_items[nid] = item

        # Create edge items
        for edge in graph.edges:
            src_item = self._node_items.get(edge.source_id)
            dst_item = self._node_items.get(edge.target_id)
            if src_item and dst_item:
                item = TopologyEdgeItem(edge, src_item, dst_item, self._animator)
                self._scene.addItem(item)
                item.set_scene(self._scene)
                self._edge_items.append(item)
                key = (edge.source_id, edge.target_id)
                self._edge_item_map[f"{edge.source_id}->{edge.target_id}"] = item
                src_item._connected_edges.append(item)
                dst_item._connected_edges.append(item)

        # Scene rect
        self._scene.setSceneRect(self._scene.itemsBoundingRect().adjusted(-50, -50, 50, 50))
        self._view.fitInView(self._scene.sceneRect(), Qt.KeepAspectRatio)
        self._update_minimap()

        # Initialize bandwidth trackers
        self._init_bw_trackers(graph)

    def _apply_diff(self, diff: GraphDiff, new_graph: NetworkGraph):
        """Apply incremental diff to scene without full clear."""
        self._prev_graph = new_graph
        self._graph = new_graph

        # Remove nodes
        for nid in diff.removed_nodes:
            item = self._node_items.pop(nid, None)
            if item:
                for edge in list(item._connected_edges):
                    edge.cleanup()
                    if edge in self._edge_items:
                        self._edge_items.remove(edge)
                    key = (edge.edge_data.source_id, edge.edge_data.target_id)
                    self._edge_item_map.pop(key, None)
                    try:
                        self._scene.removeItem(edge)
                    except RuntimeError:
                        pass
                try:
                    self._scene.removeItem(item)
                except RuntimeError:
                    pass

        # Remove edges
        for src, dst in diff.removed_edges:
            ekey = f"{src}->{dst}"
            item = self._edge_item_map.pop(ekey, None)
            if item:
                item.cleanup()
                if item in self._edge_items:
                    self._edge_items.remove(item)
                try:
                    self._scene.removeItem(item)
                except RuntimeError:
                    pass

        # Add nodes
        view_rect = self._view.viewport().rect()
        canvas_w = max(view_rect.width(), 600)
        canvas_h = max(view_rect.height(), 400)
        positions = auto_layout(new_graph, float(canvas_w), float(canvas_h))
        self._positions = {k: QPointF(x, y) for k, (x, y) in positions.items()}

        for nid, node in diff.added_nodes.items():
            pos = self._positions.get(nid, QPointF(0, 0))
            item = TopologyNodeItem(node, pos)
            self._scene.addItem(item)
            self._node_items[nid] = item

        # Add edges
        for edge in diff.added_edges:
            edge.is_new = True
            src_item = self._node_items.get(edge.source_id)
            dst_item = self._node_items.get(edge.target_id)
            if src_item and dst_item:
                item = TopologyEdgeItem(edge, src_item, dst_item, self._animator)
                self._scene.addItem(item)
                item.set_scene(self._scene)
                self._edge_items.append(item)
                ekey = f"{edge.source_id}->{edge.target_id}"
                self._edge_item_map[ekey] = item
                src_item._connected_edges.append(item)
                dst_item._connected_edges.append(item)

        # Update changed nodes
        for nid, node in diff.changed_nodes.items():
            item = self._node_items.get(nid)
            if item:
                item.update_data(node)

        # Update changed edges
        for edge in diff.changed_edges:
            ekey = f"{edge.source_id}->{edge.target_id}"
            item = self._edge_item_map.get(ekey)
            if item:
                item.update_edge_data(edge)

        # Update live stats
        self._update_live_stats(new_graph)

        # Update scene rect
        self._scene.setSceneRect(self._scene.itemsBoundingRect().adjusted(-50, -50, 50, 50))

    def _update_live_stats(self, graph: NetworkGraph):
        """Update bandwidth, RTT, and other live stats on existing items."""
        # Update bandwidth trackers
        for nid, node in graph.nodes.items():
            if node.iface_idx and node.iface_idx.isdigit():
                idx = int(node.iface_idx)
                tracker = self._bw_trackers.get(nid)
                if tracker is None:
                    tracker = InterfaceBandwidthTracker(idx)
                    self._bw_trackers[nid] = tracker

                rx, tx, pkts = tracker.tick()
                node.rx_rate = rx
                node.tx_rate = tx
                node.packets_rate = pkts

                node_item = self._node_items.get(nid)
                if node_item:
                    node_item.update_bandwidth(rx, tx)

        # Update edges with bandwidth info
        for edge in graph.edges:
            ekey = f"{edge.source_id}->{edge.target_id}"
            item = self._edge_item_map.get(ekey)
            if item is None:
                continue

            # Get rates from source node
            src_node = graph.nodes.get(edge.source_id)
            if src_node:
                edge.rx_rate = src_node.rx_rate if edge.target_id.startswith(("iface_", "gw_")) else src_node.rx_rate * 0.5
                edge.tx_rate = src_node.tx_rate if edge.target_id.startswith(("iface_", "gw_")) else src_node.tx_rate * 0.5

                item.update_bandwidth(edge.rx_rate, edge.tx_rate)

                # Update animator
                self._animator.update_edge_traffic(
                    item.edge_key, edge.rx_rate, edge.tx_rate)

    def _init_bw_trackers(self, graph: NetworkGraph):
        """Initialize bandwidth trackers for all interface nodes."""
        self._bw_trackers.clear()
        for nid, node in graph.nodes.items():
            if node.iface_idx and node.iface_idx.isdigit():
                idx = int(node.iface_idx)
                self._bw_trackers[nid] = InterfaceBandwidthTracker(idx)

    def _tick_animation(self):
        """Animation tick — update particle effects and repaint dirty regions."""
        now = time.time()
        dt = min(now - self._fps_time, 0.1)

        self._frame_count += 1
        if now - self._fps_time >= 1.0:
            fps = self._frame_count / (now - self._fps_time)
            self._fps_label.setText(f"{fps:.0f} FPS")
            self._frame_count = 0
            self._fps_time = now

        # Get dirty edges from animator
        dirty = self._animator.dirty_edges
        if dirty:
            for edge_key in dirty:
                edge_item = self._edge_item_map.get(edge_key)
                if edge_item:
                    edge_item.update()
        elif self._animator.has_active_particles:
            for item in self._edge_items:
                sys = self._animator.get_particle_system(item.edge_key)
                if sys and sys._active_count > 0:
                    item.update()

    def _update_stats(self):
        """Periodic bandwidth stats update."""
        if self._graph:
            self._update_live_stats(self._graph)

    def _update_minimap(self):
        """Update minimap widget."""
        if not self._node_items:
            return

        positions = [item.pos() for item in self._node_items.values()]
        scene_rect = self._scene.sceneRect()
        view_rect = self._view.mapToScene(self._view.viewport().rect()).boundingRect()

        self._minimap.update_minimap(scene_rect, positions, view_rect)

    def resizeEvent(self, event):
        super().resizeEvent(event)
        if self._graph and self._graph.nodes:
            self._view.fitInView(self._scene.sceneRect(), Qt.KeepAspectRatio)
            self._update_minimap()
