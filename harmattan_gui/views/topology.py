"""Topology view — QGraphicsScene-based network graph."""
from __future__ import annotations

import math
from typing import Any, Optional

from PyQt6.QtCore import Qt, QRectF, QPointF
from PyQt6.QtGui import (
    QBrush, QColor, QPen, QFont, QPainter,
    QLinearGradient, QRadialGradient,
)
from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel,
    QGraphicsScene, QGraphicsView, QGraphicsItem, QGraphicsEllipseItem,
    QGraphicsTextItem, QGraphicsLineItem, QPushButton, QLineEdit,
    QGroupBox, QTableWidget, QTableWidgetItem, QHeaderView,
)

from harmattan_gui.views.base_view import BaseView
from harmattan_gui.api.client import ApiClient
from harmattan_gui.api import endpoints as E

ROLE_COLORS = {
    "router": "#EF4444", "switch": "#F97316", "firewall": "#DC2626",
    "server": "#3B82F6", "workstation": "#22C55E", "printer": "#8B5CF6",
    "phone": "#EC4899", "camera": "#14B8A6", "iot": "#84CC16",
    "nas": "#0D9488", "vm": "#6366F1", "container": "#0EA5E9",
    "unknown": "#6B7280",
}


class NodeItem(QGraphicsEllipseItem):
    """A network host node in the topology graph."""

    def __init__(self, host: dict, radius: float = 24, parent=None):
        self._host = host
        self._ip = host.get("ip", "?")
        self._role = host.get("role", "unknown")
        color = ROLE_COLORS.get(self._role, "#6B7280")
        super().__init__(-radius, -radius, radius * 2, radius * 2, parent)

        self.setBrush(QBrush(QColor(color)))
        self.setPen(QPen(QColor(color).lighter(120), 2))
        self.setFlag(QGraphicsItem.GraphicsItemFlag.ItemIsSelectable, True)
        self.setCursor(Qt.CursorShape.PointingHandCursor)
        self.setToolTip(f"{self._ip}\n{self._role}\nMAC: {host.get('mac', '')}")

        # Label
        self._label = QGraphicsTextItem(self._ip, self)
        self._label.setDefaultTextColor(QColor("#F1F5F9"))
        font = QFont("monospace", 8, QFont.Weight.Bold)
        self._label.setFont(font)
        self._label.setPos(-self._label.boundingRect().width() / 2, radius + 2)

    def host(self) -> dict:
        return self._host


class TopologyView(BaseView):
    TITLE = "Topologie Réseau"
    ICON = "🕸️"

    def __init__(self, parent=None):
        self._api = ApiClient.instance()
        super().__init__(parent)
        self._nodes: list[NodeItem] = []
        self._edges: list[QGraphicsLineItem] = []
        self._build_ui()

    def _build_ui(self) -> None:
        # Controls
        ctrl_row = QHBoxLayout()
        self._refresh_btn = QPushButton("🔄  Rafraîchir")
        self._refresh_btn.clicked.connect(self.refresh)
        ctrl_row.addWidget(self._refresh_btn)
        ctrl_row.addStretch()
        self._layout.addLayout(ctrl_row)

        # Graph area
        self._scene = QGraphicsScene()
        self._scene.setSceneRect(-2000, -2000, 4000, 4000)
        self._view = QGraphicsView(self._scene)
        self._view.setRenderHint(QPainter.RenderHint.Antialiasing)
        self._view.setDragMode(QGraphicsView.DragMode.ScrollHandDrag)
        self._view.setBackgroundBrush(QBrush(QColor("#0F172A")))
        self._layout.addWidget(self._view, 3)

        # Host detail panel
        detail_group = QGroupBox("Détail hôte")
        detail_layout = QVBoxLayout()
        self._detail_label = QLabel("Cliquez sur un hôte dans le graphe")
        self._detail_label.setWordWrap(True)
        self._detail_label.setStyleSheet("color: #94A3B8; padding: 8px;")
        detail_layout.addWidget(self._detail_label)
        detail_group.setLayout(detail_layout)
        self._layout.addWidget(detail_group, 1)

    def refresh(self) -> None:
        self._api.get_topology(callback=self._on_topology)

    def _on_topology(self, data: dict) -> None:
        self._scene.clear()
        self._nodes.clear()
        self._edges.clear()

        nodes_data = data.get("nodes", [])
        edges_data = data.get("edges", [])

        if not nodes_data:
            self._detail_label.setText("Aucune topologie disponible. Lancez d'abord un scan ARP.")
            return

        # Place nodes in a circular layout
        n = len(nodes_data)
        radius = min(n * 40, 800)
        center = QPointF(0, 0)

        for i, node in enumerate(nodes_data):
            angle = (2 * math.pi * i) / n
            x = center.x() + radius * math.cos(angle)
            y = center.y() + radius * math.sin(angle)

            item = NodeItem(node)
            item.setPos(x, y)
            self._scene.addItem(item)
            self._nodes.append(item)

            item.mousePressEvent = lambda e, ip=node.get("ip", ""): self._on_node_click(ip)

        # Draw edges
        for edge in edges_data:
            src_ip = edge.get("source", edge.get("from", ""))
            dst_ip = edge.get("target", edge.get("to", ""))
            src_item = self._find_node(src_ip)
            dst_item = self._find_node(dst_ip)
            if src_item and dst_item:
                line = self._scene.addLine(
                    src_item.pos().x(), src_item.pos().y(),
                    dst_item.pos().x(), dst_item.pos().y(),
                    QPen(QColor("#334155"), 1, Qt.PenStyle.DashLine),
                )
                self._edges.append(line)

        self._view.fitInView(self._scene.sceneRect(), Qt.AspectRatioMode.KeepAspectRatio)
        self._detail_label.setText(f"{len(nodes_data)} hôtes, {len(edges_data)} connexions")

    def _find_node(self, ip: str) -> Optional[NodeItem]:
        for node in self._nodes:
            if node.host().get("ip") == ip:
                return node
        return None

    def _on_node_click(self, ip: str) -> None:
        self._api.get_host_detail(ip, callback=self._on_host_detail)

    def _on_host_detail(self, data: dict) -> None:
        ip = data.get("ip", "")
        mac = data.get("mac", "")
        vendor = data.get("vendor", "")
        role = data.get("role", "unknown")
        ports = data.get("ports", [])
        os_hint = data.get("os", data.get("os_hint", ""))

        text = f"**{ip}**  ({role})\nMAC: {mac}\nVendeur: {vendor}\nOS: {os_hint}\n"
        if ports:
            text += f"\nPorts ouverts ({len(ports)}):\n"
            for p in ports[:20]:
                text += f"  {p.get('port', '')}/{p.get('proto', 'tcp')}  {p.get('service', '')}\n"
        self._detail_label.setText(text)
