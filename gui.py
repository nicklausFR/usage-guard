from datetime import date, datetime, timedelta
import os
import sys
import winreg

from PySide6.QtCore import QDate, QMimeData, QPoint, QTimer, Qt, QSize, Signal
from PySide6.QtGui import QAction, QColor, QCursor, QDrag, QIcon, QPainter, QPixmap
from PySide6.QtWidgets import (
    QApplication,
    QAbstractItemView,
    QComboBox,
    QDateEdit,
    QHBoxLayout,
    QInputDialog,
    QLabel,
    QMenu,
    QMessageBox,
    QPushButton,
    QProgressBar,
    QScrollArea,
    QStackedWidget,
    QSystemTrayIcon,
    QTreeWidget,
    QTreeWidgetItem,
    QVBoxLayout,
    QWidget,
)
from i18n import _, language_preference, save_language_preference

from usage_guard import computer_on_seconds_today, config, debug_log


_DURATION_SECONDS_ROLE = Qt.UserRole + 3
_UNCATEGORIZED_LABEL = "Applications non classées"
_LIMIT_TARGET_MIME = "application/x-usage-guard-limit-target"


def _compact_duration(seconds):
    seconds = max(0, int(round(seconds)))
    hours, remainder = divmod(seconds, 3600)
    minutes, seconds = divmod(remainder, 60)
    if hours:
        return f"{hours} h {minutes:02d} min {seconds:02d} s"
    if minutes:
        return f"{minutes} min {seconds:02d} s"
    return f"{seconds} s"


class TrayProgressCard(QWidget):
    """Notification-style limit progress shown while hovering the tray icon."""

    def __init__(self, service):
        super().__init__(None, Qt.ToolTip | Qt.FramelessWindowHint | Qt.WindowStaysOnTopHint)
        self.service = service
        self.setAttribute(Qt.WA_ShowWithoutActivating)
        # Keep the progress popup fully opaque.  A translucent top-level
        # surface made the notification and its progress bars look washed out.
        self.setAttribute(Qt.WA_TranslucentBackground, False)
        self.setObjectName("trayProgressCard")
        self.setStyleSheet(
            "#trayProgressCard { background:#171b19; border:1px solid #46534d; "
            "border-radius:12px; color:#f1f6f3; }"
            "QLabel#cardTitle { font-size:15px; font-weight:700; color:#f1f6f3; }"
            "QLabel#cardSubtitle { color:#98aaa1; }"
            "QLabel#limitName { color:#eaf2ee; font-weight:600; }"
            "QLabel#limitTime { color:#9fb0a8; }"
            "QLabel#limitRemaining { color:#f1f6f3; font-size:15px; font-weight:700; }"
            "QProgressBar { height:7px; border:0; border-radius:3px; background:#303934; }"
            "QProgressBar::chunk { border-radius:3px; background:#58d69a; }"
        )
        self.setFixedWidth(360)
        self.layout = QVBoxLayout(self)
        self.layout.setContentsMargins(16, 14, 16, 15)
        self.layout.setSpacing(5)
        self.title = QLabel(_("Limitations aujourd’hui"))
        self.title.setObjectName("cardTitle")
        self.layout.addWidget(self.title)
        self.empty_state = QLabel(_("Aucune limitation aujourd’hui"))
        self.empty_state.setObjectName("limitTime")
        self.layout.addWidget(self.empty_state)
        self.rows_widget = QWidget()
        self.rows = QVBoxLayout(self.rows_widget)
        self.rows.setContentsMargins(0, 0, 0, 0)
        self.rows.setSpacing(9)
        self.layout.addWidget(self.rows_widget)

    def refresh(self):
        while self.rows.count():
            item = self.rows.takeAt(0)
            widget = item.widget()
            if widget is not None:
                # Qt deletes widgets later in the event loop. Hide and detach
                # them now so a disabled last limit cannot leave a stale bar
                # visible during the next tray hover.
                widget.hide()
                widget.setParent(None)
                widget.deleteLater()

        entries = []
        for key, policy in self.service.app_limiter.policies.items():
            if not policy.get("enabled", True):
                continue
            status = self.service.app_limiter.current_status(key)
            temporal = bool(policy.get("block_during_validity"))
            if not status.get("schedule_active", True) and not (
                temporal and status.get("schedule_pending")
            ):
                continue
            entries.append({
                "label": self.service.app_limiter.label_for_key(key),
                "temporal": temporal,
                "policy": policy,
                **status,
            })
        entries.sort(
            key=lambda item: float(item["seconds"]) / max(1.0, float(item["allowed"])),
            reverse=True,
        )
        computer_status = {}
        computer_status_provider = getattr(
            self.service.app_limiter, "computer_block_status", None
        )
        if callable(computer_status_provider):
            computer_status = computer_status_provider()
        computer_visible = bool(
            computer_status.get("enabled") and computer_status.get("mode")
        )
        has_limits = bool(entries) or computer_visible
        self.empty_state.setVisible(not has_limits)
        self.rows_widget.setVisible(has_limits)

        def add_temporal_row(
            label, starts_at, ends_at, range_text, active, pending,
            show_progress=True,
        ):
            now = datetime.now().astimezone()
            row = QWidget()
            row_layout = QVBoxLayout(row)
            row_layout.setContentsMargins(0, 4, 0, 0)
            row_layout.setSpacing(3)
            heading = QHBoxLayout()
            name = QLabel(str(label))
            name.setObjectName("limitName")
            remaining_seconds = None
            if active and ends_at:
                remaining_seconds = max(0.0, (ends_at - now).total_seconds())
            elif pending and starts_at:
                remaining_seconds = max(0.0, (starts_at - now).total_seconds())
            remaining = QLabel(
                _("reste {duration}").format(duration=_compact_duration(remaining_seconds))
                if remaining_seconds is not None else _("configurée")
            )
            remaining.setObjectName("limitRemaining")
            heading.addWidget(name, 1)
            heading.addWidget(remaining)
            detail = QLabel(range_text)
            detail.setObjectName("limitTime")
            row_layout.addLayout(heading)
            if show_progress:
                progress = QProgressBar()
                if starts_at and ends_at:
                    total_seconds = max(1, int(round((ends_at - starts_at).total_seconds())))
                    elapsed_seconds = (
                        max(0, int(round((now - starts_at).total_seconds())))
                        if active else total_seconds if not pending else 0
                    )
                    progress.setRange(0, total_seconds)
                    progress.setValue(min(total_seconds, elapsed_seconds))
                else:
                    progress.setRange(0, 0)
                progress.setTextVisible(False)
                row_layout.addWidget(progress)
            row_layout.addWidget(detail)
            self.rows.addWidget(row)

        if computer_visible:
            starts_at = ends_at = None
            try:
                starts_at = datetime.fromisoformat(str(computer_status["started_at"]))
                ends_at = datetime.fromisoformat(str(computer_status["ends_at"]))
            except (KeyError, TypeError, ValueError):
                pass
            daily_start = str(computer_status.get("daily_start") or "")
            daily_end = str(computer_status.get("daily_end") or "")
            if daily_start and daily_end:
                range_text = f"{daily_start}–{daily_end}"
            elif starts_at and ends_at:
                range_text = (
                    f"{starts_at.astimezone().strftime('%d/%m/%Y %H:%M')}–"
                    f"{ends_at.astimezone().strftime('%d/%m/%Y %H:%M')}"
                )
            else:
                range_text = _("configurée")
            add_temporal_row(
                _("Tout l’ordinateur"), starts_at, ends_at, range_text,
                bool(computer_status.get("active")), bool(computer_status.get("pending")),
                show_progress=computer_status.get("mode") != "schedule",
            )

        for entry in entries[:5]:
            if entry.get("temporal"):
                policy = entry["policy"]
                starts_at = ends_at = None
                try:
                    if policy.get("valid_from"):
                        starts_at = datetime.combine(
                            date.fromisoformat(str(policy["valid_from"])),
                            datetime.strptime(str(policy["valid_from_time"]), "%H:%M").time(),
                        ).astimezone()
                    if policy.get("valid_until"):
                        ends_at = datetime.combine(
                            date.fromisoformat(str(policy["valid_until"])),
                            datetime.strptime(str(policy["valid_until_time"]), "%H:%M").time(),
                        ).astimezone()
                except (TypeError, ValueError):
                    starts_at = ends_at = None
                boundaries = []
                if starts_at:
                    boundaries.append(starts_at.strftime("%d/%m/%Y %H:%M"))
                if ends_at:
                    boundaries.append(ends_at.strftime("%d/%m/%Y %H:%M"))
                add_temporal_row(
                    entry["label"], starts_at, ends_at,
                    "–".join(boundaries) or _("configurée"),
                    bool(entry.get("schedule_active")), bool(entry.get("schedule_pending")),
                )
                continue
            row = QWidget()
            row_layout = QVBoxLayout(row)
            row_layout.setContentsMargins(0, 4, 0, 0)
            row_layout.setSpacing(3)
            heading = QHBoxLayout()
            name = QLabel(str(entry["label"]))
            name.setObjectName("limitName")
            remaining = QLabel(_("reste {duration}").format(duration=_compact_duration(entry['remaining'])))
            remaining.setObjectName("limitTime")
            heading.addWidget(name, 1)
            heading.addWidget(remaining)
            progress = QProgressBar()
            allowed_seconds = max(1, int(round(float(entry["allowed"]))))
            progress.setRange(0, allowed_seconds)
            progress.setValue(min(allowed_seconds, int(round(float(entry["seconds"])))))
            progress.setTextVisible(False)
            detail_parts = [
                f"{_compact_duration(entry['seconds'])} / {_compact_duration(entry['allowed'])}"
            ]
            policy = entry.get("policy", {})
            if policy.get("schedule_start") and policy.get("schedule_end"):
                detail_parts.append(
                    f"{policy['schedule_start']}–{policy['schedule_end']}"
                )
            detail = QLabel(" · ".join(detail_parts))
            detail.setObjectName("limitTime")
            row_layout.addLayout(heading)
            row_layout.addWidget(progress)
            row_layout.addWidget(detail)
            self.rows.addWidget(row)
        self.adjustSize()

    def show_near(self, tray_geometry):
        self.refresh()
        screen = QApplication.screenAt(tray_geometry.center()) or QApplication.primaryScreen()
        available = screen.availableGeometry()
        # Match a Windows notification: rounded and aligned close to the
        # lower-right edge of the available desktop.
        right_margin = 0
        bottom_margin = 8
        x = available.right() - self.width() + 1 - right_margin
        y = available.bottom() - self.height() + 1 - bottom_margin
        self.move(x, y)
        self.show()
        self.raise_()


def _limit_drop_target(mime_data):
    if mime_data.hasFormat(_LIMIT_TARGET_MIME):
        return bytes(mime_data.data(_LIMIT_TARGET_MIME)).decode("utf-8")
    if mime_data.hasText():
        target = mime_data.text()
        if target.startswith(("app:", "site:", "category:", "other-site:")):
            return target
    return ""


class CategoryHeader(QLabel):
    target_dropped = Signal(str)
    drag_started = Signal()
    drag_finished = Signal()
    clicked = Signal()

    def __init__(self, category, seconds, target_keys=None, nested=False, indent_level=None,
                 tree_depth=0, tree_ancestors=()):
        super().__init__(f"{category}    {_format_seconds(seconds)}")
        self.category = category
        self.target_keys = target_keys or []
        self.nested = nested
        indent_level = (1 if nested else 0) if indent_level is None else indent_level
        self.tree_depth = tree_depth
        self.tree_ancestors = tuple(tree_ancestors)
        self._drag_start = QPoint()
        self.setAcceptDrops(True)
        self.setStyleSheet(
            "color: #8fcaff; font-size: 12px; font-weight: bold; padding: "
            f"8px 4px 1px {10 + indent_level * 16}px;"
        )

    def paintEvent(self, event):
        super().paintEvent(event)
        self._paint_tree_lines()

    def _paint_tree_lines(self):
        if not self.tree_depth:
            return
        painter = QPainter(self)
        painter.setPen(QColor("#74bced"))
        center_y = self.height() // 2
        for depth in self.tree_ancestors:
            x = 10 + (depth - 1) * 16
            painter.drawLine(x, 0, x, self.height())
        x = 10 + (self.tree_depth - 1) * 16
        painter.drawLine(x, 0, x, center_y)
        painter.drawLine(x, center_y, x + 12, center_y)

    def dragEnterEvent(self, event):
        if event.mimeData().hasText():
            event.acceptProposedAction()

    def dropEvent(self, event):
        self.target_dropped.emit(event.mimeData().text())
        event.acceptProposedAction()

    def mousePressEvent(self, event):
        if event.button() == Qt.LeftButton and self.target_keys:
            self._drag_start = event.position().toPoint()
        super().mousePressEvent(event)

    def mouseMoveEvent(self, event):
        if not self.target_keys or not event.buttons() & Qt.LeftButton:
            return super().mouseMoveEvent(event)
        if (event.position().toPoint() - self._drag_start).manhattanLength() < 8:
            return super().mouseMoveEvent(event)
        drag = QDrag(self)
        mime_data = QMimeData()
        mime_data.setText("group:" + "|".join(self.target_keys))
        drag.setMimeData(mime_data)
        self.drag_started.emit()
        drag.exec(Qt.MoveAction)
        self.drag_finished.emit()

    def mouseReleaseEvent(self, event):
        if (
            event.button() == Qt.LeftButton
            and (event.position().toPoint() - self._drag_start).manhattanLength() < 8
        ):
            self.clicked.emit()
        super().mouseReleaseEvent(event)


class UsageRow(QWidget):
    drag_started = Signal()
    drag_finished = Signal()
    target_dropped = Signal(str)
    clicked = Signal()

    def __init__(self, target_key):
        super().__init__()
        self.target_key = target_key
        self._drag_start = QPoint()
        self.tree_depth = 0
        self.tree_ancestors = ()
        self.setCursor(Qt.OpenHandCursor)
        self.setAcceptDrops(True)

    def set_tree_branch(self, depth, ancestors=()):
        self.tree_depth = depth
        self.tree_ancestors = tuple(ancestors)

    def paintEvent(self, event):
        super().paintEvent(event)
        if not self.tree_depth:
            return
        painter = QPainter(self)
        painter.setPen(QColor("#74bced"))
        center_y = self.height() // 2
        for depth in self.tree_ancestors:
            x = 10 + (depth - 1) * 16
            painter.drawLine(x, 0, x, self.height())
        x = 10 + (self.tree_depth - 1) * 16
        painter.drawLine(x, 0, x, self.height())
        painter.drawLine(x, center_y, x + 12, center_y)

    def dragEnterEvent(self, event):
        source_key = event.mimeData().text()
        if source_key and not source_key.startswith("group:") and source_key != self.target_key:
            event.acceptProposedAction()

    def dropEvent(self, event):
        self.target_dropped.emit(event.mimeData().text())
        event.acceptProposedAction()

    def mousePressEvent(self, event):
        if event.button() == Qt.LeftButton:
            self._drag_start = event.position().toPoint()
        super().mousePressEvent(event)

    def mouseMoveEvent(self, event):
        if not event.buttons() & Qt.LeftButton:
            return super().mouseMoveEvent(event)
        if (event.position().toPoint() - self._drag_start).manhattanLength() < 8:
            return super().mouseMoveEvent(event)
        drag = QDrag(self)
        mime_data = QMimeData()
        mime_data.setText(self.target_key)
        drag.setMimeData(mime_data)
        self.drag_started.emit()
        # A usage row can be moved into a category or copied into the limits list.
        drag.exec(Qt.CopyAction | Qt.MoveAction, Qt.MoveAction)
        self.drag_finished.emit()

    def mouseReleaseEvent(self, event):
        if (
            event.button() == Qt.LeftButton
            and (event.position().toPoint() - self._drag_start).manhattanLength() < 8
        ):
            self.clicked.emit()
        super().mouseReleaseEvent(event)


class UsageTree(QTreeWidget):
    moved_to_root = Signal(str)
    moved_to_category = Signal(str, str)
    moved_to_browser = Signal(str)
    category_reordered = Signal(str, str, bool)
    drag_started = Signal()
    drag_finished = Signal()

    def __init__(self, parent=None):
        super().__init__(parent)
        self._dragged_target_key = None
        # Qt's default edge is quite narrow.  A larger zone makes it possible
        # to carry an item to a category that is outside the visible area.
        self.setAutoScroll(True)
        self.setAutoScrollMargin(64)

    def dragEnterEvent(self, event):
        event.acceptProposedAction()

    def dragMoveEvent(self, event):
        # Keep scrolling while the cursor is held at an edge.  The explicit
        # step complements Qt's auto-scroll, which can otherwise be sluggish
        # on Windows when the drag originated from a tree row.
        viewport = self.viewport()
        margin = self.autoScrollMargin()
        y = event.position().toPoint().y()
        bar = self.verticalScrollBar()
        if y < margin:
            bar.setValue(bar.value() - max(4, (margin - y) // 3))
        elif y > viewport.height() - margin:
            bar.setValue(bar.value() + max(4, (y - (viewport.height() - margin)) // 3))
        event.acceptProposedAction()

    def startDrag(self, supported_actions):
        item = self.currentItem()
        self._dragged_target_key = None
        limit_target_key = ""
        if item is not None:
            kind = item.data(0, Qt.UserRole)
            payload = item.data(0, Qt.UserRole + 1)
            if kind == "target":
                self._dragged_target_key = payload
                limit_target_key = payload
            elif kind == "other-site":
                browser, host = payload
                self._dragged_target_key = f"other-site:{browser}:{host}"
                limit_target_key = self._dragged_target_key
            elif kind == "category" and item.text(0) != _UNCATEGORIZED_LABEL:
                # A category is moved as one group: dropping it on another
                # category moves every assigned activity, including targets
                # that have no usage in the currently displayed period.
                self._dragged_target_key = "category-group:" + item.text(0)
                limit_target_key = f"category:{item.text(0)}"
            elif kind == "site-category":
                category, target_keys = payload
                self._dragged_target_key = "group:" + "|".join(target_keys)
                limit_target_key = f"category:{category}"
        if not self._dragged_target_key:
            super().startDrag(supported_actions)
            return

        # QTreeWidget's native MIME payload contains only internal model data.
        # External targets (the Limits tab/button) need the actual usage key.
        drag = QDrag(self)
        mime_data = QMimeData()
        mime_data.setText(self._dragged_target_key)
        if limit_target_key:
            mime_data.setData(_LIMIT_TARGET_MIME, limit_target_key.encode("utf-8"))
        drag.setMimeData(mime_data)

        # Preserve the native tree drag feel: carry a translucent snapshot of
        # the row under the pointer while keeping our interoperable MIME data.
        item_rect = self.visualItemRect(item)
        if item_rect.isValid() and not item_rect.isEmpty():
            row_snapshot = self.viewport().grab(item_rect)
            drag_preview = QPixmap(row_snapshot.size())
            drag_preview.fill(Qt.transparent)
            painter = QPainter(drag_preview)
            painter.setOpacity(0.82)
            painter.drawPixmap(0, 0, row_snapshot)
            painter.end()
            drag.setPixmap(drag_preview)
            cursor_in_view = self.viewport().mapFromGlobal(QCursor.pos())
            hot_spot = cursor_in_view - item_rect.topLeft()
            hot_spot.setX(max(0, min(hot_spot.x(), drag_preview.width() - 1)))
            hot_spot.setY(max(0, min(hot_spot.y(), drag_preview.height() - 1)))
            drag.setHotSpot(hot_spot)
        self.drag_started.emit()
        debug_log(f"usage drag started: {self._dragged_target_key}")
        if self._dragged_target_key.startswith("group:"):
            drag.exec(Qt.CopyAction | Qt.MoveAction, Qt.MoveAction)
        else:
            drag.exec(Qt.CopyAction | Qt.MoveAction, Qt.MoveAction)
        self.drag_finished.emit()
        self._dragged_target_key = None

    @staticmethod
    def _parent_category(item):
        while item is not None:
            if item.data(0, Qt.UserRole) in {"category", "site-category"}:
                return item.text(0)
            item = item.parent()
        return None

    @staticmethod
    def _parent_browser(item):
        while item is not None:
            if item.data(0, Qt.UserRole) == "browser":
                return item
            item = item.parent()
        return None

    def dropEvent(self, event):
        source_view = event.source()
        source = source_view.currentItem() if isinstance(source_view, QTreeWidget) else self.currentItem()
        source_key = self._dragged_target_key
        if source_key is None and source is not None and source.data(0, Qt.UserRole) == "target":
            source_key = source.data(0, Qt.UserRole + 1)
        if source_key is not None:
            destination = self.itemAt(event.position().toPoint())
            if source is not None and source.data(0, Qt.UserRole) == "category":
                if (
                    destination is None
                    or destination.data(0, Qt.UserRole) != "category"
                    or source is destination
                    or source.parent() is not destination.parent()
                ):
                    event.ignore()
                    return
                destination_rect = self.visualItemRect(destination)
                before = event.position().toPoint().y() < destination_rect.center().y()
                self.category_reordered.emit(source.text(0), destination.text(0), before)
                event.setDropAction(Qt.MoveAction)
                event.accept()
                return
            category = self._parent_category(destination)
            if category is not None:
                if source is not None and source.data(0, Qt.UserRole) == "category" and source.text(0) == category:
                    event.ignore()
                    return
                self.moved_to_category.emit(source_key, category)
                event.setDropAction(Qt.MoveAction)
                event.accept()
                return
            if self._parent_browser(destination) is not None:
                self.moved_to_browser.emit(source_key)
                event.setDropAction(Qt.MoveAction)
                event.accept()
                return
            if destination is None or destination.parent() is None:
                self.moved_to_root.emit(source_key)
                event.setDropAction(Qt.MoveAction)
                event.accept()
                return
        super().dropEvent(event)


class LimitDropButton(QPushButton):
    target_dropped = Signal(str)

    def __init__(self, text, parent=None):
        super().__init__(text, parent)
        self.setAcceptDrops(True)

    def dragEnterEvent(self, event):
        if _limit_drop_target(event.mimeData()):
            event.setDropAction(Qt.CopyAction)
            event.accept()
        else:
            event.ignore()

    def dragMoveEvent(self, event):
        if _limit_drop_target(event.mimeData()):
            event.setDropAction(Qt.CopyAction)
            event.accept()
        else:
            event.ignore()

    def dropEvent(self, event):
        target_key = _limit_drop_target(event.mimeData())
        if target_key:
            event.setDropAction(Qt.CopyAction)
            event.accept()
            debug_log(f"limit drop accepted on tab: {target_key}")
            QTimer.singleShot(0, lambda: self.target_dropped.emit(target_key))
        else:
            event.ignore()


class LimitsTree(QTreeWidget):
    target_dropped = Signal(str)

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setAcceptDrops(True)

    def dragEnterEvent(self, event):
        if _limit_drop_target(event.mimeData()):
            event.setDropAction(Qt.CopyAction)
            event.accept()
        else:
            event.ignore()

    def dragMoveEvent(self, event):
        if _limit_drop_target(event.mimeData()):
            event.setDropAction(Qt.CopyAction)
            event.accept()
        else:
            event.ignore()

    def dropEvent(self, event):
        target_key = _limit_drop_target(event.mimeData())
        if target_key:
            event.setDropAction(Qt.CopyAction)
            event.accept()
            debug_log(f"limit drop accepted in list: {target_key}")
            QTimer.singleShot(0, lambda: self.target_dropped.emit(target_key))
        else:
            event.ignore()


def create_usage_icon(active=False):
    pixmap = QPixmap(64, 64)
    pixmap.fill(Qt.transparent)
    painter = QPainter(pixmap)
    painter.setRenderHint(QPainter.Antialiasing)
    painter.setBrush(QColor("#27d17f" if active else "#00aaff"))
    painter.setPen(Qt.NoPen)
    painter.drawRoundedRect(10, 8, 44, 48, 10, 10)
    painter.setBrush(QColor(45, 45, 45))
    painter.drawRoundedRect(18, 18, 28, 24, 5, 5)
    painter.setBrush(QColor(245, 245, 245))
    painter.drawRect(25, 42, 14, 5)
    painter.drawRect(21, 48, 22, 4)
    painter.end()
    return QIcon(pixmap)


def create_drag_handle_icon():
    """Small six-dot grip used consistently for every draggable tree row."""
    pixmap = QPixmap(28, 28)
    pixmap.fill(Qt.transparent)
    painter = QPainter(pixmap)
    painter.setRenderHint(QPainter.Antialiasing)
    painter.setBrush(QColor("#2f3336"))
    painter.setPen(QColor("#596269"))
    painter.drawRoundedRect(2, 2, 24, 24, 5, 5)
    painter.setPen(Qt.NoPen)
    painter.setBrush(QColor("#b7d5c5"))
    for x in (10, 17):
        for y in (9, 14, 19):
            painter.drawEllipse(x - 1, y - 1, 3, 3)
    painter.end()
    return QIcon(pixmap)


def create_tray_icon(toggle_callback, service):
    app = QApplication.instance()
    usage_icon = create_usage_icon()
    app.setWindowIcon(usage_icon)
    icon = QSystemTrayIcon(usage_icon, app)
    icon.setToolTip(_("Usage Guard — suivi actif"))
    menu = QMenu()
    progress_card = TrayProgressCard(service)
    open_action = QAction(_("Ouvrir Usage Guard"), icon)
    open_action.triggered.connect(toggle_callback)

    def quit_app():
        icon.hide()
        app.quit()

    quit_action = QAction(_("Quitter"), icon)
    quit_action.triggered.connect(quit_app)
    menu.addAction(open_action)
    menu.addSeparator()
    menu.addAction(quit_action)
    icon.setContextMenu(menu)
    def handle_activation(reason):
        if reason in (
            QSystemTrayIcon.ActivationReason.Trigger,
            QSystemTrayIcon.ActivationReason.DoubleClick,
        ):
            # Queue this until the shell's tray-message handler has returned.
            # On Windows this prevents a click from being swallowed while the
            # notification-area menu is being dismissed.
            QTimer.singleShot(0, toggle_callback)

    icon.activated.connect(handle_activation)
    # Keep Python references alive for the lifetime of the tray icon.
    icon._menu = menu
    icon._open_action = open_action
    icon._quit_action = quit_action
    icon._handle_activation = handle_activation

    def update_tooltip():
        def compact_duration(seconds):
            seconds = max(0, int(round(seconds)))
            hours, remainder = divmod(seconds, 3600)
            minutes, seconds = divmod(remainder, 60)
            if hours:
                return f"{hours}h {minutes:02d}min {seconds:02d}s"
            if minutes:
                return f"{minutes}min {seconds:02d}s"
            return f"{seconds}s"

        running = service.app_limiter.running_limits()
        if not running:
            icon.setToolTip(_("Usage Guard — suivi actif"))
            return
        lines = ["Applications limitées"]
        for item in running:
            allowed = max(1.0, float(item["allowed"]))
            used = min(allowed, max(0.0, float(item["seconds"])))
            filled = min(10, int(round(10 * used / allowed)))
            bar = "█" * filled + "░" * (10 - filled)
            lines.append(
                f"{item['label']} {bar} "
                f"{compact_duration(used)}/{compact_duration(allowed)}"
            )
        icon.setToolTip("\n".join(lines))

    # Replace the legacy text-only tooltip with a notification-style progress
    # card. Keeping the old formatter above avoids changing unrelated startup
    # behavior while this local function becomes the connected updater.
    def update_tooltip():
        icon.setToolTip("")
        if progress_card.isVisible():
            progress_card.refresh()

    service.state_changed.connect(update_tooltip)
    icon._update_tooltip = update_tooltip
    update_tooltip()
    icon.show()

    hover_timer = QTimer(icon)
    hover_timer.setInterval(180)
    hover_state = {"over": False}

    def check_hover():
        cursor = QCursor.pos()
        tray_geometry = icon.geometry()
        over_icon = not tray_geometry.isNull() and tray_geometry.contains(cursor)
        over_card = (
            progress_card.isVisible()
            and progress_card.frameGeometry().contains(cursor)
        )
        if over_icon and not hover_state["over"]:
            progress_card.show_near(tray_geometry)
        elif not over_icon and not over_card and progress_card.isVisible():
            progress_card.hide()
        hover_state["over"] = over_icon or over_card

    hover_timer.timeout.connect(check_hover)
    hover_timer.start()
    icon._progress_card = progress_card
    icon._hover_timer = hover_timer
    icon._check_hover = check_hover

    def promote_in_windows_settings():
        """Keep this exact executable visible in the Windows 11 tray."""
        registry_path = r"Control Panel\NotifyIconSettings"
        executable = os.path.normcase(os.path.abspath(sys.executable))
        try:
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER, registry_path) as root:
                index = 0
                while True:
                    try:
                        child_name = winreg.EnumKey(root, index)
                    except OSError:
                        break
                    index += 1
                    try:
                        with winreg.OpenKey(
                            root,
                            child_name,
                            0,
                            winreg.KEY_QUERY_VALUE | winreg.KEY_SET_VALUE,
                        ) as child:
                            registered_path, _ = winreg.QueryValueEx(
                                child, "ExecutablePath"
                            )
                            if os.path.normcase(os.path.abspath(registered_path)) != executable:
                                continue
                            winreg.SetValueEx(
                                child, "IsPromoted", 0, winreg.REG_DWORD, 1
                            )
                            debug_log(
                                "tray icon promoted in Windows notification settings"
                            )
                            return
                    except (OSError, TypeError):
                        continue
        except OSError as error:
            debug_log(f"tray promotion failed: {error!r}")

    # Calling show() again is a no-op while Qt already considers the icon
    # visible, even when Explorer silently missed the original registration.
    # Force a genuine removal/addition cycle after the event loop starts.
    def finish_registration(attempt):
        icon.setIcon(create_usage_icon())
        icon.setContextMenu(menu)
        icon.show()
        debug_log(
            f"tray registration attempt={attempt}; visible={icon.isVisible()}"
        )

    def reregister_with_shell(attempt):
        icon.hide()
        QTimer.singleShot(100, lambda: finish_registration(attempt))

    icon._finish_registration = finish_registration
    icon._reregister_with_shell = reregister_with_shell
    icon._promote_in_windows_settings = promote_in_windows_settings
    QTimer.singleShot(600, promote_in_windows_settings)
    QTimer.singleShot(2_000, promote_in_windows_settings)
    retry_delays_ms = (250, 1_000, 3_000, 10_000, 30_000)
    for attempt, delay_ms in enumerate(retry_delays_ms, start=1):
        QTimer.singleShot(
            delay_ms,
            lambda attempt=attempt: reregister_with_shell(attempt),
        )
    return icon


class PopupPanel(QWidget):
    def __init__(self, service):
        super().__init__()
        self.service = service
        self._has_rendered = False
        self._expanded_other_sites = set()
        self._collapsed_nodes = set()
        self._tree_expanded = {}
        self._drag_in_progress = False
        self._refresh_pending = False
        self._drop_refresh_scheduled = False
        self.setWindowFlags(Qt.Window)
        self.setWindowTitle("Usage Guard")
        self.setWindowIcon(create_usage_icon(True))
        self.setAttribute(Qt.WA_TranslucentBackground, False)
        self.resize(
            int(getattr(config, "WINDOW_WIDTH", 420)),
            int(getattr(config, "WINDOW_HEIGHT", 520)),
        )
        self.setMinimumSize(560, 620)

        background = QWidget(self)
        self._background = background
        background.setGeometry(0, 0, self.width(), self.height())
        background.setStyleSheet(
            "background-color: #26262a;"
        )
        layout = QVBoxLayout(background)
        layout.setContentsMargins(16, 16, 16, 16)
        layout.setSpacing(12)

        status_row = QHBoxLayout()
        self.status_label = QLabel()
        self.status_label.setStyleSheet("color: #b8b8bd;")
        self.period = QComboBox()
        self.period.addItem(_("Aujourd’hui"), "today")
        self.period.addItem(_("Choisir un jour…"), "date")
        self.period.addItem(_("Depuis le début"), "all")
        self.period.setStyleSheet(_combo_style())
        self.period.currentIndexChanged.connect(self._period_changed)
        self.day_picker = QDateEdit(QDate.currentDate().addDays(-1))
        self.day_picker.setCalendarPopup(True)
        self.day_picker.setDisplayFormat("dd/MM/yyyy")
        self.day_picker.setMaximumDate(QDate.currentDate())
        self.day_picker.setToolTip(_("Choisir le jour à afficher"))
        self.day_picker.setStyleSheet(_combo_style())
        self.day_picker.dateChanged.connect(self.refresh)
        self.day_picker.hide()
        status_row.addWidget(self.status_label, 1)
        # The Usage tab is deliberately limited to today's live data.
        self.period.hide()
        self.day_picker.hide()

        self.system_widget = QWidget()
        self.system_widget.setStyleSheet(
            "background: rgba(55, 55, 60, 190); border-radius: 6px;"
        )
        system_layout = QVBoxLayout(self.system_widget)
        system_layout.setContentsMargins(10, 8, 10, 8)
        system_layout.setSpacing(5)
        system_header = QLabel(_("Ordinateur"))
        system_header.setStyleSheet("color: #8fcaff; font-size: 12px; font-weight: bold;")
        system_layout.addWidget(system_header)
        self.system_on_label = self._system_duration_row(system_layout, _("Session Windows"))
        self.system_foreground_label = self._system_duration_row(
            system_layout, _("Utilisation active")
        )
        self.system_with_passive_label = self._system_duration_row(
            system_layout, _("Usage passif")
        )
        section_bar = QHBoxLayout()
        section_bar.setSpacing(6)
        self.section_buttons = []
        for index, label in enumerate((_("Usage"), _("Analyse"), _("Limites"), _("Paramètres"))):
            button = LimitDropButton(label) if index == 2 else QPushButton(label)
            button.setCheckable(True)
            button.clicked.connect(lambda _checked, page=index: self._switch_section(page))
            button.setStyleSheet(
                "QPushButton { color: #d8d8dd; background: #34343a; border: none; "
                "border-radius: 5px; padding: 6px 10px; }"
                "QPushButton:checked { color: #ffffff; background: #477c9e; }"
            )
            section_bar.addWidget(button)
            self.section_buttons.append(button)
            if index == 2:
                button.target_dropped.connect(self._add_limit_from_drop)
        self.section_buttons[0].setChecked(True)
        layout.addLayout(section_bar)

        self.tree = UsageTree()
        self.tree.setColumnCount(2)
        self.tree.setHeaderHidden(True)
        self.tree.setRootIsDecorated(True)
        self.tree.setIndentation(18)
        self.tree.setAnimated(True)
        self.tree.setDragEnabled(True)
        self.tree.setAcceptDrops(True)
        self.tree.setDropIndicatorShown(True)
        self.tree.setDragDropMode(QAbstractItemView.DragDrop)
        self.tree.setDefaultDropAction(Qt.MoveAction)
        self.tree.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        self.tree.setTextElideMode(Qt.ElideRight)
        self.tree.setStyleSheet(
            "QTreeWidget { background: transparent; border: none; color: white; }"
            "QTreeWidget::item { min-height: 27px; padding: 2px 4px; }"
            "QTreeWidget::item:selected { background: rgba(95, 135, 175, 100); }"
        )
        self.tree.setColumnWidth(0, 270)
        self.tree.setColumnWidth(1, 90)
        self.tree.setContextMenuPolicy(Qt.CustomContextMenu)
        self.tree.customContextMenuRequested.connect(self._show_tree_menu)
        self.tree.itemExpanded.connect(lambda item: self._remember_tree_state(item, True))
        self.tree.itemCollapsed.connect(lambda item: self._remember_tree_state(item, False))
        self.tree.moved_to_root.connect(self._move_target_to_root)
        self.tree.moved_to_category.connect(self._move_target_to_category)
        self.tree.moved_to_browser.connect(self._move_target_to_browser)
        self.tree.category_reordered.connect(self._reorder_category)
        self.tree.drag_started.connect(self._begin_drag)
        self.tree.drag_finished.connect(self._end_drag)
        self.sections = QStackedWidget()
        usage_page = QWidget()
        usage_layout = QVBoxLayout(usage_page)
        usage_layout.setContentsMargins(0, 0, 0, 0)
        usage_layout.addLayout(status_row)
        usage_layout.addWidget(self.system_widget)
        usage_layout.addWidget(self.tree)
        self.sections.addWidget(usage_page)

        analysis_page = QWidget()
        analysis_layout = QVBoxLayout(analysis_page)
        analysis_layout.setContentsMargins(0, 0, 0, 0)
        analysis_controls = QHBoxLayout()
        self.analysis_mode = QComboBox()
        self.analysis_mode.addItem(_("Date précise"), "day")
        self.analysis_mode.addItem(_("Cumul sur une durée"), "range")
        self.analysis_mode.setStyleSheet(_combo_style())
        self.analysis_mode.currentIndexChanged.connect(self._analysis_mode_changed)
        self.analysis_target = QComboBox()
        self.analysis_target.addItem(_("Toutes les activités"), "all")
        self.analysis_target.setMinimumWidth(240)
        self.analysis_target.setStyleSheet(_combo_style())
        self.analysis_target.currentIndexChanged.connect(self._refresh_analysis)
        self.analysis_day_picker = self._analysis_date_picker(QDate.currentDate())
        self.analysis_start_picker = self._analysis_date_picker(QDate.currentDate().addDays(-6))
        self.analysis_end_picker = self._analysis_date_picker(QDate.currentDate())
        analysis_controls.addWidget(self.analysis_mode)
        analysis_controls.addWidget(self.analysis_target)
        analysis_controls.addWidget(self.analysis_day_picker)
        analysis_controls.addWidget(self.analysis_start_picker)
        analysis_controls.addWidget(self.analysis_end_picker)
        analysis_controls.addStretch(1)
        analysis_layout.addLayout(analysis_controls)
        self.analysis_summary = QLabel()
        self.analysis_summary.setWordWrap(True)
        self.analysis_summary.setStyleSheet("color: #b8b8bd; padding: 4px 0;")
        analysis_layout.addWidget(self.analysis_summary)
        self.analysis_tree = QTreeWidget()
        self.analysis_tree.setColumnCount(2)
        self.analysis_tree.setHeaderLabels([_("Activité"), _("Durée")])
        self.analysis_tree.setRootIsDecorated(True)
        self.analysis_tree.setColumnWidth(0, 360)
        self.analysis_tree.setStyleSheet(
            "QTreeWidget { background: transparent; border: none; color: white; }"
            "QTreeWidget::item { min-height: 27px; padding: 2px 4px; }"
        )
        analysis_layout.addWidget(self.analysis_tree)
        self._analysis_mode_changed()
        self.sections.addWidget(analysis_page)

        limits_page = QWidget()
        limits_layout = QVBoxLayout(limits_page)
        limits_layout.setContentsMargins(0, 0, 0, 0)
        limit_header = QLabel(_("Limites d’utilisation"))
        limit_header.setStyleSheet("color:#8fcaff; font-size:16px; font-weight:bold;")
        limits_layout.addWidget(limit_header)
        self.limits_tree = LimitsTree()
        self.limits_tree.setColumnCount(6)
        self.limits_tree.setHeaderLabels(
            [_("Application"), "", _("Limite"), _("Rallonge"), _("Alerte"), _("État aujourd’hui")]
        )
        self.limits_tree.setRootIsDecorated(False)
        self.limits_tree.setAlternatingRowColors(True)
        self.limits_tree.setStyleSheet(
            "QTreeWidget { background:transparent; color:white; border:1px solid #45454b; }"
            "QTreeWidget::item { min-height:30px; padding:3px; }"
        )
        self.limits_tree.itemDoubleClicked.connect(lambda *_: self._edit_selected_limit())
        self.limits_tree.target_dropped.connect(self._add_limit_from_drop)
        limits_layout.addWidget(self.limits_tree, 1)
        limit_actions = QHBoxLayout()
        add_limit = QPushButton(_("Ajouter une limite…"))
        add_limit.clicked.connect(self._add_limit)
        edit_limit = QPushButton(_("Modifier…"))
        edit_limit.clicked.connect(self._edit_selected_limit)
        reset_limit = QPushButton(_("Réinitialiser aujourd’hui"))
        reset_limit.clicked.connect(self._reset_selected_limit)
        remove_limit = QPushButton(_("Supprimer"))
        remove_limit.clicked.connect(self._remove_selected_limit)
        limit_actions.addWidget(add_limit)
        limit_actions.addWidget(edit_limit)
        limit_actions.addWidget(reset_limit)
        limit_actions.addWidget(remove_limit)
        limits_layout.addLayout(limit_actions)
        self.sections.addWidget(limits_page)

        settings_page = QWidget()
        settings_layout = QVBoxLayout(settings_page)
        settings_layout.setContentsMargins(0, 0, 0, 0)
        settings_title = QLabel(_("Paramètres"))
        settings_title.setStyleSheet("color:#8fcaff; font-size:16px; font-weight:bold;")
        settings_layout.addWidget(settings_title)
        language_label = QLabel(_("Langue de l’application"))
        settings_layout.addWidget(language_label)
        self.language_choice = QComboBox()
        self.language_choice.addItem(_("Automatique (langue système)"), "auto")
        self.language_choice.addItem("Français", "fr")
        self.language_choice.addItem("English", "en")
        self.language_choice.setStyleSheet(_combo_style())
        selected_language = language_preference(getattr(config, "LANGUAGE", "auto"))
        self.language_choice.setCurrentIndex(max(0, self.language_choice.findData(selected_language)))
        self.language_choice.currentIndexChanged.connect(self._language_changed)
        settings_layout.addWidget(self.language_choice)
        self.language_restart_note = QLabel(_("Le changement sera appliqué au prochain redémarrage d’Usage Guard."))
        self.language_restart_note.setWordWrap(True)
        self.language_restart_note.setStyleSheet("color:#b8b8bd; padding-top:6px;")
        settings_layout.addWidget(self.language_restart_note)
        settings_layout.addStretch(1)
        self.sections.addWidget(settings_page)
        layout.addWidget(self.sections, 1)

        self.excluded_apps_button = QPushButton(_("Applications exclues…"))
        self.excluded_apps_button.clicked.connect(self._manage_excluded_apps)
        self.excluded_apps_button.hide()

        self.service.state_changed.connect(self.refresh)
        self.refresh()

    def resizeEvent(self, event):
        super().resizeEvent(event)
        if hasattr(self, "_background"):
            self._background.setGeometry(self.rect())

    def refresh(self):
        if self._drag_in_progress:
            self._refresh_pending = True
            return
        # The monitoring timer keeps running while the popup is closed. Do not
        # rebuild its widgets in the background on every tick.
        if self._has_rendered and not self.isVisible():
            return
        page = self.sections.currentIndex() if hasattr(self, "sections") else 0
        if page == 0:
            context = self.service.current_context
            if context.is_afk:
                status = "En pause — ordinateur inactif"
            elif context.app_name:
                target = self.service.usage.target_for_context(context)
                status = f"Actif : {_clean_name(target.label)}"
            else:
                status = "En attente d’une application active"
            self.status_label.setText(status)

            usage = self.service.usage.usage_for_day()
            entries = self.service.usage.presentation(usage)
            passive_usage = self.service.usage.passive_usage_for_day()
            system_usage = self.service.usage.system_usage_for_day()
            system_on_seconds = computer_on_seconds_today() or system_usage["on"]
            self.system_on_label.setText(_format_seconds(system_on_seconds))
            self.system_foreground_label.setText(
                _format_seconds(sum(entry.seconds for entry in entries))
            )
            self.system_with_passive_label.setText(
                _format_seconds(sum(passive_usage.values()))
            )
            self._replace_rows(entries, passive_usage)
        elif page == 1:
            self._refresh_analysis()
        elif page == 2:
            self._refresh_limits()
        self._has_rendered = True

    def _analysis_date_picker(self, initial_date):
        picker = QDateEdit(initial_date)
        picker.setCalendarPopup(True)
        picker.setDisplayFormat("dd/MM/yyyy")
        picker.setMaximumDate(QDate.currentDate())
        picker.setStyleSheet(_combo_style())
        picker.dateChanged.connect(self._refresh_analysis)
        return picker

    def _language_changed(self):
        language = self.language_choice.currentData()
        if language:
            save_language_preference(language)
            self.language_restart_note.setText(
                _("Langue enregistrée. Redémarrez Usage Guard pour l’appliquer.")
            )

    def _selected_limit_key(self):
        item = self.limits_tree.currentItem() if hasattr(self, "limits_tree") else None
        return item.data(0, Qt.UserRole) if item is not None else ""

    def _add_limit(self):
        existing = set(self.service.app_limiter.policies)
        candidates = [
            (key, label) for key, label in self.service.app_limiter.available_targets()
            if key not in existing
        ]
        if not candidates:
            QMessageBox.information(self, "Ajouter une limite", "Toutes les applications connues ont déjà une limite.")
            return
        labels = [f"{label}  ({key})" for key, label in candidates]
        selected, accepted = QInputDialog.getItem(
            self, "Ajouter une limite", "Application :", labels, 0, False
        )
        if not accepted:
            return
        target_key = candidates[labels.index(selected)][0]
        self._edit_limit(target_key, {
            "enabled": True,
            "limit_seconds": 15,
            "extension_seconds": 15,
            "warning_seconds": 5,
        })

    def _add_limit_from_drop(self, target_key):
        other_site = _other_site_drag_parts(target_key)
        if other_site:
            browser, host = other_site
            self.service.usage.make_browser_site_specific(browser, host)
            target_key = f"site:{browser}:{host}"
        target_key = self.service.app_limiter._canonical_limit_target(target_key)
        self._switch_section(2)
        if target_key in self.service.app_limiter.policies:
            self._refresh_limits(select_key=target_key)
            return
        self.service.app_limiter.apply_settings(target_key, {
            "enabled": True,
            "limit_seconds": 15,
            "extension_seconds": 15,
            "warning_seconds": 5,
        })
        self._refresh_limits(select_key=target_key)

    def _toggle_limit(self, target_key):
        settings = dict(self.service.app_limiter.policies[target_key])
        settings["enabled"] = not settings["enabled"]
        self.service.app_limiter.apply_settings(target_key, settings)
        self.service._notify_limit_toggle(target_key, settings["enabled"])
        self._refresh_limits(select_key=target_key)

    def _edit_selected_limit(self):
        target_key = self._selected_limit_key()
        if target_key:
            self._edit_limit(target_key, self.service.app_limiter.policies[target_key])

    def _edit_limit(self, target_key, settings):
        label = self.service.app_limiter.label_for_key(target_key)
        enabled_label, accepted = QInputDialog.getItem(
            self, f"Limite — {label}", "État :", ["Activée", "Désactivée"],
            0 if settings.get("enabled", True) else 1, False,
        )
        if not accepted:
            return
        limit, accepted = QInputDialog.getInt(
            self, f"Limite — {label}", "Durée autorisée (secondes) :",
            int(settings.get("limit_seconds", 15)), 1, 86_400,
        )
        if not accepted:
            return
        extension, accepted = QInputDialog.getInt(
            self, f"Limite — {label}", "Rallonge exceptionnelle (secondes) :",
            int(settings.get("extension_seconds", 15)), 1, 3_600,
        )
        if not accepted:
            return
        warning, accepted = QInputDialog.getInt(
            self, f"Limite — {label}", "Notification avant la fin (secondes) :",
            min(int(settings.get("warning_seconds", 5)), limit), 1, limit,
        )
        if not accepted:
            return
        previous_enabled = (
            bool(self.service.app_limiter.policies[target_key].get("enabled"))
            if target_key in self.service.app_limiter.policies else None
        )
        normalized = self.service.app_limiter.apply_settings(target_key, {
            "enabled": enabled_label == "Activée",
            "limit_seconds": limit,
            "extension_seconds": extension,
            "warning_seconds": warning,
        })
        if previous_enabled is not None and previous_enabled != normalized["enabled"]:
            self.service._notify_limit_toggle(target_key, normalized["enabled"])
        self._refresh_limits(select_key=target_key)

    def _reset_selected_limit(self):
        target_key = self._selected_limit_key()
        if target_key:
            self.service.app_limiter.reset_today(target_key)
            self._refresh_limits(select_key=target_key)

    def _remove_selected_limit(self):
        target_key = self._selected_limit_key()
        if not target_key:
            return
        label = self.service.app_limiter.label_for_key(target_key)
        answer = QMessageBox.question(
            self, "Supprimer la limite", f"Supprimer la limite de « {label} » ?",
            QMessageBox.Yes | QMessageBox.No, QMessageBox.No,
        )
        if answer == QMessageBox.Yes:
            self.service.app_limiter.remove_limit(target_key)
            self._refresh_limits()

    def _refresh_limits(self, select_key=""):
        if not hasattr(self, "limits_tree"):
            return
        _selected_identity, top_identity, scroll_value = self._capture_tree_position(
            self.limits_tree
        )
        selected_key = select_key or self._selected_limit_key()
        self.limits_tree.setUpdatesEnabled(False)
        self.limits_tree.clear()
        for limit in self.service.app_limiter.limits():
            state = f"{_format_seconds(limit['seconds'])} / {_format_seconds(limit['allowed'])}"
            if limit["extension_used"]:
                state += " — rallonge utilisée"
            item = QTreeWidgetItem([
                limit["label"],
                "",
                _format_seconds(limit["limit_seconds"]),
                _format_seconds(limit["extension_seconds"]),
                _format_seconds(limit["warning_seconds"]),
                state,
            ])
            item.setData(0, Qt.UserRole, limit["key"])
            self.limits_tree.addTopLevelItem(item)
            toggle = QPushButton("")
            toggle.setFixedSize(28, 22)
            toggle.setToolTip(
                "Désactiver cette limite" if limit["enabled"] else "Activer cette limite"
            )
            toggle.setAccessibleName(
                "Limite activée" if limit["enabled"] else "Limite désactivée"
            )
            toggle.setStyleSheet(
                "QPushButton { border:1px solid rgba(255,255,255,45); border-radius:7px; "
                f"background:{'#238b57' if limit['enabled'] else '#8b3038'}; }}"
                "QPushButton:hover { border:2px solid white; }"
            )
            toggle.clicked.connect(
                lambda _checked=False, key=limit["key"]: self._toggle_limit(key)
            )
            self.limits_tree.setItemWidget(item, 1, toggle)
            if limit["key"] == selected_key:
                self.limits_tree.setCurrentItem(item)
        for column in range(self.limits_tree.columnCount()):
            self.limits_tree.resizeColumnToContents(column)
        self._restore_tree_position(
            self.limits_tree, None, top_identity, scroll_value
        )
        self.limits_tree.setUpdatesEnabled(True)

    def _analysis_mode_changed(self):
        is_range = self.analysis_mode.currentData() == "range"
        self.analysis_day_picker.setVisible(not is_range)
        self.analysis_start_picker.setVisible(is_range)
        self.analysis_end_picker.setVisible(is_range)
        self._refresh_analysis()

    @staticmethod
    def _python_date(qdate):
        return date(qdate.year(), qdate.month(), qdate.day())

    def _analysis_period(self):
        if self.analysis_mode.currentData() == "day":
            selected = self._python_date(self.analysis_day_picker.date())
            return selected, selected
        start = self._python_date(self.analysis_start_picker.date())
        end = self._python_date(self.analysis_end_picker.date())
        return min(start, end), max(start, end)

    def _refresh_analysis(self):
        if not hasattr(self, "analysis_tree"):
            return
        selected_identity, top_identity, scroll_value = self._capture_tree_position(
            self.analysis_tree
        )
        expansion = self._capture_tree_expansion(self.analysis_tree)
        start, end = self._analysis_period()
        usage = self.service.usage.usage_for_period(start, end)
        entries = self.service.usage.presentation(usage)
        selected_target = self.analysis_target.currentData() or "all"
        category_totals = {
            category: 0.0
            for category in self.service.usage.top_level_categories()
        }
        for entry in entries:
            for category in {entry.category, entry.site_category}:
                if category and category != "__root__":
                    category_totals[category] = category_totals.get(category, 0.0) + entry.seconds
        self.analysis_target.blockSignals(True)
        self.analysis_target.clear()
        self.analysis_target.addItem(_("Toutes les activités"), "all")
        for category, _seconds in sorted(
            category_totals.items(), key=lambda item: (-item[1], item[0].lower())
        ):
            self.analysis_target.addItem(
                _("Catégorie : {name}").format(name=category), f"category:{category}"
            )
        for entry in sorted(entries, key=lambda item: (-item.seconds, item.label.lower())):
            self.analysis_target.addItem(
                _("Application : {name}").format(name=entry.label), f"target:{entry.key}"
            )
        selected_index = self.analysis_target.findData(selected_target)
        self.analysis_target.setCurrentIndex(max(0, selected_index))
        selected_target = self.analysis_target.currentData() or "all"
        self.analysis_target.blockSignals(False)
        entries = [
            entry for entry in entries
            if self._analysis_entry_matches(entry, selected_target)
        ]
        system_usage = self.service.usage.system_usage_for_period(start, end)
        period_label = start.strftime("%d/%m/%Y")
        if start != end:
            period_label += f" - {end:%d/%m/%Y}"
        day_totals = []
        current_day = start
        while current_day <= end:
            day_entries = self.service.usage.presentation(
                self.service.usage.usage_for_day(current_day)
            )
            day_totals.append((
                current_day,
                sum(
                    entry.seconds for entry in day_entries
                    if self._analysis_entry_matches(entry, selected_target)
                ),
            ))
            current_day += timedelta(days=1)
        total_seconds = sum(seconds for _day, seconds in day_totals)
        active_days = sum(seconds > 0 for _day, seconds in day_totals)
        best_day, best_seconds = max(day_totals, key=lambda item: item[1])
        selection_label = self.analysis_target.currentText()
        self.analysis_summary.setText(
            f"{period_label} | {selection_label} : {_format_seconds(total_seconds)} | "
            f"Moyenne/jour : {_format_seconds(total_seconds / len(day_totals))} | "
            f"Jours actifs : {active_days}/{len(day_totals)} | "
            f"Maximum : {best_day:%d/%m} ({_format_seconds(best_seconds)}) | "
            f"Ordinateur : {_format_seconds(system_usage['on'])}"
        )
        self.analysis_tree.setUpdatesEnabled(False)
        self.analysis_tree.clear()
        grouped = {}
        for entry in entries:
            grouped.setdefault(entry.category, []).append(entry)
        if selected_target == "all":
            for category in self.service.usage.top_level_categories():
                grouped.setdefault(category, [])
        elif selected_target.startswith("category:"):
            grouped.setdefault(selected_target.removeprefix("category:"), [])
        root_entries = grouped.pop("__root__", [])
        root_entries = sorted(root_entries, key=lambda item: item.seconds, reverse=True)
        for entry in (entry for entry in root_entries if entry.seconds > 0):
            item = QTreeWidgetItem([entry.label, _format_seconds(entry.seconds)])
            item.setData(0, Qt.UserRole + 2, f"analysis-target:{entry.key}")
            self.analysis_tree.addTopLevelItem(item)
        inactive_root_entries = [entry for entry in root_entries if entry.seconds <= 0]
        if inactive_root_entries:
            inactive = QTreeWidgetItem([f"Inactifs ({len(inactive_root_entries)})", ""])
            inactive.setData(0, Qt.UserRole + 2, "analysis-inactive:root")
            self.analysis_tree.addTopLevelItem(inactive)
            for entry in inactive_root_entries:
                child = QTreeWidgetItem([entry.label, _format_seconds(entry.seconds)])
                child.setData(0, Qt.UserRole + 2, f"analysis-target:{entry.key}")
                inactive.addChild(child)
            inactive.setExpanded(expansion.get("analysis-inactive:root", False))
        analysis_category_items = {}
        analysis_category_totals = {}
        for category, category_entries in sorted(
            grouped.items(), key=lambda item: self.service.usage.category_order_key(item[0])
        ):
            total = sum(entry.seconds for entry in category_entries)
            analysis_category_totals[category] = total
            category_item = QTreeWidgetItem([category, _format_seconds(total)])
            category_item.setChildIndicatorPolicy(
                QTreeWidgetItem.ChildIndicatorPolicy.ShowIndicator
            )
            category_item.setData(0, Qt.UserRole + 2, f"analysis-category:{category}")
            self.analysis_tree.addTopLevelItem(category_item)
            analysis_category_items[category] = category_item
            ordered_entries = sorted(
                category_entries, key=lambda item: item.seconds, reverse=True
            )
            for entry in (entry for entry in ordered_entries if entry.seconds > 0):
                child = QTreeWidgetItem([entry.label, _format_seconds(entry.seconds)])
                child.setData(0, Qt.UserRole + 2, f"analysis-target:{entry.key}")
                category_item.addChild(child)
            inactive_entries = [entry for entry in ordered_entries if entry.seconds <= 0]
            if inactive_entries:
                inactive = QTreeWidgetItem([f"Inactifs ({len(inactive_entries)})", ""])
                inactive_identity = f"analysis-inactive:{category}"
                inactive.setData(0, Qt.UserRole + 2, inactive_identity)
                category_item.addChild(inactive)
                for entry in inactive_entries:
                    child = QTreeWidgetItem([entry.label, _format_seconds(entry.seconds)])
                    child.setData(0, Qt.UserRole + 2, f"analysis-target:{entry.key}")
                    inactive.addChild(child)
                inactive.setExpanded(expansion.get(inactive_identity, False))
            identity = self._tree_identity(category_item)
            category_item.setExpanded(expansion.get(identity, True))
        category_children = {}
        for category, parent_name in self.service.usage.data.get("category_parents", {}).items():
            child = analysis_category_items.get(category)
            parent = analysis_category_items.get(parent_name)
            if child is None or parent is None or child is parent or child.parent() is not None:
                continue
            index = self.analysis_tree.indexOfTopLevelItem(child)
            if index >= 0:
                parent.addChild(self.analysis_tree.takeTopLevelItem(index))
                category_children.setdefault(parent_name, []).append(category)

        def hierarchical_total(category):
            total = analysis_category_totals.get(category, 0.0)
            total += sum(
                hierarchical_total(child)
                for child in category_children.get(category, [])
            )
            analysis_category_items[category].setText(1, _format_seconds(total))
            return total

        for category, item in analysis_category_items.items():
            if item.parent() is None:
                hierarchical_total(category)
        self._restore_tree_position(
            self.analysis_tree, selected_identity, top_identity, scroll_value
        )
        self.analysis_tree.setUpdatesEnabled(True)

    def _analysis_entry_matches(self, entry, selected_target):
        if selected_target == "all":
            return True
        if selected_target.startswith("target:"):
            return entry.key == selected_target[len("target:"):]
        if selected_target.startswith("category:"):
            category = selected_target[len("category:"):]
            return any(
                category in self.service.usage.category_lineage(entry_category)
                for entry_category in {entry.category, entry.site_category}
            )
        return True

    def _period_changed(self):
        self.refresh()

    def _selected_day(self):
        """The Usage tab always represents the current day."""
        return date.today()

    def _switch_section(self, page):
        self.sections.setCurrentIndex(page)
        for index, button in enumerate(self.section_buttons):
            button.setChecked(index == page)
        self.refresh()

    def showEvent(self, event):
        super().showEvent(event)
        self.refresh()

    def _replace_rows(self, entries, passive_usage):
        selected_identity, top_identity, scroll_value = self._capture_tree_position(
            self.tree
        )
        self.tree.setUpdatesEnabled(False)
        self.tree.blockSignals(True)
        self.tree.clear()
        grouped = {}
        for entry in entries:
            grouped.setdefault(entry.category, []).append(entry)
        for category in self.service.usage.top_level_categories():
            grouped.setdefault(category, [])
        brave_displayed = False
        category_items = {}
        for category, category_entries in sorted(
            grouped.items(), key=lambda item: self.service.usage.category_order_key(item[0])
        ):
            if category == "__root__":
                brave_entries = [entry for entry in category_entries if _is_brave_entry(entry)]
                self._add_timed_tree_rows(
                    None,
                    [
                        (entry.label, entry.seconds, "target", entry.key)
                        for entry in category_entries
                        if entry not in brave_entries
                    ],
                    "root",
                )
                if brave_entries:
                    brave_displayed = True
                    browser = self._tree_item(
                        None, self.service.usage.browser_label("brave.exe"), sum(entry.seconds for entry in brave_entries),
                        "browser", "brave.exe"
                    )
                    direct, grouped_sites, other_sites = [], {}, []
                    for entry in brave_entries:
                        if _clean_name(entry.label).lower() == "brave":
                            continue
                        if _other_sites_browser(entry.key):
                            other_sites.append(entry)
                        elif entry.site_category:
                            grouped_sites.setdefault(entry.site_category, []).append(entry)
                        else:
                            direct.append(entry)
                    self._add_timed_tree_rows(
                        browser,
                        [(entry.label, entry.seconds, "target", entry.key) for entry in direct],
                        "browser:brave.exe:direct",
                    )
                    for name in sorted(set(grouped_sites) | set(self.service.usage.site_categories())):
                        site_entries = grouped_sites.get(name, [])
                        node = self._tree_item(browser, name, sum(x.seconds for x in site_entries), "site-category", (name, [x.key for x in site_entries]))
                        self._add_timed_tree_rows(
                            node,
                            [(entry.label, entry.seconds, "target", entry.key) for entry in site_entries],
                            f"site-category:{name}",
                        )
                    for entry in other_sites:
                        node = self._tree_item(browser, "Autres sites", entry.seconds, "other-sites", entry.key)
                        self._add_timed_tree_rows(
                            node,
                            [
                                (host, seconds, "other-site", ("brave.exe", host))
                                for host, seconds in self._other_sites_for_display("brave.exe").items()
                            ],
                            "other-sites:brave.exe",
                        )
                continue
            root = self._tree_item(None, category, sum(x.seconds for x in category_entries), "category", [x.key for x in category_entries])
            category_items[category] = root
            brave = [x for x in category_entries if _is_brave_entry(x)]
            self._add_timed_tree_rows(
                root,
                [
                    (entry.label, entry.seconds, "target", entry.key)
                    for entry in category_entries
                    if entry not in brave
                ],
                f"category:{category}",
            )
            if brave:
                brave_displayed = True
                browser = self._tree_item(root, self.service.usage.browser_label("brave.exe"), sum(x.seconds for x in brave), "browser", "brave.exe")
                site_groups = {}
                direct_sites = []
                other_sites = []
                for entry in brave:
                    if _clean_name(entry.label).lower() == "brave":
                        direct_sites.append(
                            type(entry)(
                                key=entry.key,
                                label="Brave (sans site identifié)",
                                category=entry.category,
                                seconds=entry.seconds,
                                site_category="",
                            )
                        )
                    else:
                        if _other_sites_browser(entry.key):
                            other_sites.append(entry)
                        elif entry.site_category:
                            site_groups.setdefault(entry.site_category, []).append(entry)
                        else:
                            direct_sites.append(entry)
                self._add_timed_tree_rows(
                    browser,
                    [(entry.label, entry.seconds, "target", entry.key) for entry in direct_sites],
                    f"category:{category}:browser:brave.exe:direct",
                )
                for site_category in sorted(
                    set(site_groups) | set(self.service.usage.site_categories())
                ):
                    site_entries = site_groups.get(site_category, [])
                    parent = self._tree_item(
                        browser, site_category, sum(x.seconds for x in site_entries),
                        "site-category", (site_category, [x.key for x in site_entries])
                    )
                    self._add_timed_tree_rows(
                        parent,
                        [(entry.label, entry.seconds, "target", entry.key) for entry in site_entries],
                        f"category:{category}:site-category:{site_category}",
                    )
                for entry in sorted(other_sites, key=lambda x: x.seconds, reverse=True):
                    node = self._tree_item(browser, "Autres sites", entry.seconds, "other-sites", entry.key)
                    self._add_timed_tree_rows(
                        node,
                        [
                            (host, seconds, "other-site", ("brave.exe", host))
                            for host, seconds in self._other_sites_for_display("brave.exe").items()
                        ],
                        f"category:{category}:other-sites:brave.exe",
                    )
        for category, parent_name in self.service.usage.data.get("category_parents", {}).items():
            child = category_items.get(category)
            parent = category_items.get(parent_name)
            if child is None or parent is None or child is parent or child.parent() is not None:
                continue
            index = self.tree.indexOfTopLevelItem(child)
            if index >= 0:
                parent.addChild(self.tree.takeTopLevelItem(index))
        for item in category_items.values():
            if item.parent() is None:
                self._refresh_category_duration(item)
        if self.service.usage.site_categories() and not brave_displayed:
            browser = self._tree_item(
                None, self.service.usage.browser_label("brave.exe"), 0, "browser", "brave.exe"
            )
            for site_category in self.service.usage.site_categories():
                self._tree_item(browser, site_category, 0, "site-category", (site_category, []))
        excluded_targets = self.service.usage.excluded_targets()
        if excluded_targets:
            excluded = self._tree_item(None, "Applications exclues", None, "excluded", None)
            for target in excluded_targets:
                self._tree_item(excluded, target.label, None, "excluded-target", target.key)
        if passive_usage:
            passive = self._tree_item(None, "Média en arrière-plan", sum(passive_usage.values()), "passive", None)
            for name, seconds in passive_usage.items():
                self._tree_item(passive, name, seconds, "passive-item", name)
        for root_index in range(self.tree.topLevelItemCount()):
            root = self.tree.topLevelItem(root_index)
            self._reconcile_duration_totals(root)
            self._restore_tree_state(root)
        self.tree.blockSignals(False)
        self._restore_tree_position(
            self.tree, selected_identity, top_identity, scroll_value
        )
        self.tree.setUpdatesEnabled(True)

    @staticmethod
    def _tree_identity(item):
        if item is None:
            return None
        stored = item.data(0, Qt.UserRole + 2)
        if stored:
            return ("stored", str(stored))
        path = []
        while item is not None:
            path.append(item.text(0))
            item = item.parent()
        return ("path", tuple(reversed(path)))

    @classmethod
    def _find_tree_identity(cls, tree, identity):
        if identity is None:
            return None
        pending = [tree.topLevelItem(index) for index in range(tree.topLevelItemCount())]
        while pending:
            item = pending.pop(0)
            if cls._tree_identity(item) == identity:
                return item
            pending[0:0] = [item.child(index) for index in range(item.childCount())]
        return None

    @classmethod
    def _capture_tree_position(cls, tree):
        top_item = tree.itemAt(2, 2)
        return (
            cls._tree_identity(tree.currentItem()),
            cls._tree_identity(top_item),
            tree.verticalScrollBar().value(),
        )

    @classmethod
    def _capture_tree_expansion(cls, tree):
        result = {}
        pending = [tree.topLevelItem(index) for index in range(tree.topLevelItemCount())]
        while pending:
            item = pending.pop(0)
            if item.childCount():
                result[cls._tree_identity(item)] = item.isExpanded()
                pending[0:0] = [item.child(index) for index in range(item.childCount())]
        return result

    @classmethod
    def _restore_tree_position(cls, tree, selected_identity, top_identity, scroll_value):
        selected = cls._find_tree_identity(tree, selected_identity)
        if selected is not None:
            tree.setCurrentItem(selected)
        top_item = cls._find_tree_identity(tree, top_identity)
        if top_item is not None:
            tree.scrollToItem(top_item, QAbstractItemView.PositionAtTop)
        else:
            tree.verticalScrollBar().setValue(scroll_value)

    def _other_sites_for_display(self, browser):
        return self.service.usage.other_sites(browser, self._selected_day())

    def _tree_item(self, parent, label, seconds, kind, payload):
        duration = "" if seconds is None else _format_seconds(seconds)
        item = QTreeWidgetItem(parent if parent is not None else self.tree, [str(label), duration])
        item.setData(0, Qt.UserRole, kind)
        item.setData(0, Qt.UserRole + 1, payload)
        state_key = f"{kind}:{payload}"
        item.setData(0, Qt.UserRole + 2, state_key)
        item.setData(0, _DURATION_SECONDS_ROLE, None if seconds is None else float(seconds))
        if kind in {"target", "other-site", "site-category"} or (
            kind == "category" and str(label) != _UNCATEGORIZED_LABEL
        ):
            item.setFlags(item.flags() | Qt.ItemIsDragEnabled)
            item.setIcon(0, create_drag_handle_icon())
        if kind in {"category", "site-category"}:
            item.setChildIndicatorPolicy(
                QTreeWidgetItem.ChildIndicatorPolicy.ShowIndicator
            )
        item.setForeground(1, QColor("#27d17f"))
        if kind in {"category", "browser", "site-category", "other-sites", "passive", "excluded", "inactive"}:
            item.setForeground(0, QColor("#8fcaff"))
        return item

    def _add_timed_tree_rows(self, parent, rows, scope):
        ordered = sorted(rows, key=lambda row: (-float(row[1]), str(row[0]).lower()))
        for label, seconds, kind, payload in (row for row in ordered if row[1] > 0):
            self._tree_item(parent, label, seconds, kind, payload)
        inactive_rows = [row for row in ordered if row[1] <= 0]
        if not inactive_rows:
            return
        inactive = self._tree_item(
            parent,
            f"Inactifs ({len(inactive_rows)})",
            None,
            "inactive",
            scope,
        )
        for label, seconds, kind, payload in inactive_rows:
            self._tree_item(inactive, label, seconds, kind, payload)

    def _reconcile_duration_totals(self, item, displayed_seconds=None):
        """Make the displayed duration of every parent equal its children.

        Usage is stored with sub-second precision. Truncating each row separately
        can otherwise make a category differ by a second or two from the sum of
        the rows visibly below it. The rounding remainder is assigned to the
        children with the largest fractional parts.
        """
        raw_seconds = item.data(0, _DURATION_SECONDS_ROLE)
        if raw_seconds is None:
            return

        children = [
            item.child(index)
            for index in range(item.childCount())
            if item.child(index).data(0, _DURATION_SECONDS_ROLE) is not None
        ]
        if displayed_seconds is None:
            displayed_seconds = int(float(raw_seconds) + 0.5)

        if children:
            child_values = [float(child.data(0, _DURATION_SECONDS_ROLE)) for child in children]
            child_seconds = [int(value) for value in child_values]
            remainder = displayed_seconds - sum(child_seconds)
            for index in sorted(
                range(len(children)),
                key=lambda index: child_values[index] - child_seconds[index],
                reverse=True,
            )[:max(0, remainder)]:
                child_seconds[index] += 1
            for child, seconds in zip(children, child_seconds):
                self._reconcile_duration_totals(child, seconds)

        item.setText(1, _format_seconds(displayed_seconds))

    def _refresh_category_duration(self, item):
        total = 0.0
        for index in range(item.childCount()):
            child = item.child(index)
            if child.data(0, Qt.UserRole) == "category":
                total += self._refresh_category_duration(child)
                continue
            seconds = child.data(0, _DURATION_SECONDS_ROLE)
            if seconds is not None:
                total += float(seconds)
        item.setData(0, _DURATION_SECONDS_ROLE, total)
        return total

    def _restore_tree_state(self, item):
        if item.childCount():
            state_key = item.data(0, Qt.UserRole + 2)
            kind = item.data(0, Qt.UserRole)
            item.setExpanded(self._tree_expanded.get(state_key, kind in {"category", "browser"}))
            for index in range(item.childCount()):
                self._restore_tree_state(item.child(index))

    def _remember_tree_state(self, item, expanded):
        state_key = item.data(0, Qt.UserRole + 2)
        if state_key:
            self._tree_expanded[state_key] = expanded

    def _move_target_to_root(self, target_key):
        if str(target_key).startswith("category-group:"):
            self.service.usage.make_category_root(
                str(target_key).removeprefix("category-group:")
            )
            self.refresh()
            return
        other_site = _other_site_drag_parts(target_key)
        if other_site:
            browser, host = other_site
            self.service.usage.move_browser_site_to_category(
                browser, host, _UNCATEGORIZED_LABEL
            )
            self.refresh()
            return
        self.service.usage.make_root(target_key)
        self.refresh()

    def _reorder_category(self, category, destination, before):
        self.service.usage.reorder_category(category, destination, before)
        self.refresh()

    def _move_target_to_category(self, target_key, category):
        if str(target_key).startswith("category-group:"):
            self.service.usage.move_category(
                str(target_key).removeprefix("category-group:"), category
            )
            self.refresh()
            return
        other_site = _other_site_drag_parts(target_key)
        if other_site:
            browser, host = other_site
            self.service.usage.move_browser_site_to_category(browser, host, category)
            self.refresh()
            return
        if str(target_key).startswith("group:"):
            self.service.usage.set_category_for_keys(target_key[6:].split("|"), category)
        else:
            self.service.usage.set_category(target_key, category)
        self.refresh()

    def _move_target_to_browser(self, target_key):
        if str(target_key).startswith("category-group:"):
            self.service.usage.make_category_root(
                str(target_key).removeprefix("category-group:")
            )
            self.refresh()
            return
        # A specific site dropped directly on its browser remains a browser
        # site; only its optional site sub-category must be removed.
        other_site = _other_site_drag_parts(target_key)
        if other_site:
            self.service.usage.make_browser_site_specific(*other_site)
            self.refresh()
            return
        if str(target_key).startswith("site:"):
            self.service.usage.set_category(target_key, "")
        else:
            self.service.usage.make_root(target_key)
        self.refresh()

    def _show_tree_menu(self, position):
        item = self.tree.itemAt(position)
        if item is None:
            return
        kind = item.data(0, Qt.UserRole)
        payload = item.data(0, Qt.UserRole + 1)
        global_pos = self.tree.viewport().mapToGlobal(position)
        if kind == "target" or kind == "other-sites":
            self._show_tree_target_menu(global_pos, payload)
        elif kind == "other-site":
            self._show_other_site_menu(global_pos, *payload)
        elif kind == "browser":
            self._show_browser_menu(global_pos, payload)
        elif kind == "site-category":
            self._show_site_category_menu(global_pos, payload[0], payload[1])
        elif kind == "category":
            self._show_category_menu(global_pos, item.text(0), payload)
        elif kind == "excluded-target":
            menu = QMenu(self)
            restore = menu.addAction("Réactiver")
            if menu.exec(global_pos) == restore:
                self.service.usage.unexclude(payload)
                self.refresh()

    def _show_tree_target_menu(self, position, target_key):
        menu = QMenu(self)
        root_action = menu.addAction("Sortir de non classé")
        menu.addSeparator()
        rename_action = menu.addAction("Renommer l’activité…")
        category_action = menu.addAction("Ajouter à une catégorie…")
        exclude_action = menu.addAction("Ne pas comptabiliser")
        delete_action = menu.addAction("Supprimer…")
        selected = menu.exec(position)
        if selected == root_action:
            self._move_target_to_root(target_key)
        elif selected == rename_action:
            self._rename_target(target_key)
        elif selected == category_action:
            self._choose_category(target_key)
        elif selected == exclude_action:
            self.service.usage.exclude(target_key)
            self.refresh()
        elif selected == delete_action:
            self._confirm_delete_target(target_key)

    @staticmethod
    def _system_duration_row(layout, label):
        row = QHBoxLayout()
        name = QLabel(label)
        name.setStyleSheet("color: #d8d8dd;")
        duration = QLabel("0 s")
        duration.setStyleSheet("color: #27d17f; font-weight: bold;")
        row.addWidget(name, 1)
        row.addWidget(duration)
        layout.addLayout(row)
        return duration

    def _usage_row(self, entry, indent_level=0, tree_prefix="", tree_depth=0, tree_ancestors=()):
        row = UsageRow(entry.key)
        row.set_tree_branch(tree_depth, tree_ancestors)
        is_other_sites = bool(_other_sites_browser(entry.key))
        row.setStyleSheet(
            "background: rgba(64, 55, 80, 210); border: 1px solid #7f6b9d; border-radius: 6px;"
            if is_other_sites else "background: rgba(55, 55, 60, 190); border-radius: 6px;"
        )
        row_layout = QHBoxLayout(row)
        row_layout.setContentsMargins(10 + indent_level * 16, 8, 10, 8)
        name = QLabel(f"{tree_prefix}{_clean_name(entry.label)}")
        name.setStyleSheet("color: white; font-weight: bold;")
        duration = QLabel(_format_seconds(entry.seconds))
        duration.setStyleSheet("color: #27d17f; font-weight: bold;")
        row_layout.addWidget(name, 1)
        row_layout.addWidget(duration)
        row.setContextMenuPolicy(Qt.CustomContextMenu)
        row.customContextMenuRequested.connect(
            lambda position, target=entry.key, widget=row: self._show_entry_menu(
                widget.mapToGlobal(position), target
            )
        )
        row.target_dropped.connect(
            lambda source_key, destination_key=entry.key: self._confirm_drag_merge(
                source_key, destination_key
            )
        )
        row.drag_started.connect(self._begin_drag)
        row.drag_finished.connect(self._end_drag)
        browser = _other_sites_browser(entry.key)
        if browser:
            row.clicked.connect(lambda key=entry.key: self._toggle_other_sites(key))
        return row

    def _toggle_other_sites(self, target_key):
        if target_key in self._expanded_other_sites:
            self._expanded_other_sites.remove(target_key)
        else:
            self._expanded_other_sites.add(target_key)
        self.refresh()

    def _toggle_node(self, node_key):
        if node_key in self._collapsed_nodes:
            self._collapsed_nodes.remove(node_key)
        else:
            self._collapsed_nodes.add(node_key)
        self.refresh()

    def _other_site_detail_row(self, browser, host, seconds, tree_prefix=""):
        row = UsageRow("")
        row.set_tree_branch(3, (2,))
        row.setAcceptDrops(False)
        row.setToolTip("Clic droit : classer ce site ou le rendre spécifique")
        row.setStyleSheet(
            "background: rgba(48, 48, 53, 190); color: #d8d8dd; "
            "border-radius: 5px;"
        )
        layout = QHBoxLayout(row)
        # This is a child of the already-indented "Autres sites" row.
        layout.setContentsMargins(58, 6, 10, 6)
        name = QLabel(host)
        name.setStyleSheet("color: #d8d8dd;")
        duration = QLabel(_format_seconds(seconds))
        duration.setStyleSheet("color: #d8d8dd;")
        layout.addWidget(name, 1)
        layout.addWidget(duration)
        row.setContextMenuPolicy(Qt.CustomContextMenu)
        row.customContextMenuRequested.connect(
            lambda position, widget=row, browser=browser, host=host: self._show_other_site_menu(
                widget.mapToGlobal(position), browser, host
            )
        )
        return row

    def _show_other_site_menu(self, position, browser, host):
        menu = QMenu(self)
        make_specific = menu.addAction("Rendre spécifique")
        move_to_category = menu.addAction("Déplacer dans une catégorie…")
        exclude_action = menu.addAction("Ne pas comptabiliser")
        delete_action = menu.addAction("Supprimer…")
        selected = menu.exec(position)
        if selected == make_specific:
            self.service.usage.make_browser_site_specific(browser, host)
            self.refresh()
        elif selected == move_to_category:
            self._choose_other_site_category(browser, host)
        elif selected == exclude_action:
            self.service.usage.exclude_browser_site(browser, host)
            self.refresh()
        elif selected == delete_action:
            self._confirm_delete_browser_site(browser, host)

    def _choose_other_site_category(self, browser, host):
        categories = self.service.usage.categories()
        category, accepted = QInputDialog.getItem(
            self,
            "Catégorie",
            f"Catégorie pour « {host} » :",
            categories,
            0,
            True,
        )
        if accepted and category.strip():
            self.service.usage.move_browser_site_to_category(
                browser, host, category.strip()
            )
            self.refresh()

    def _confirm_delete_target(self, target_key):
        label = self.service.usage.data.get("targets", {}).get(
            target_key, {}
        ).get("label", target_key)
        answer = QMessageBox.question(
            self,
            "Supprimer l’activité",
            f"Supprimer définitivement l’historique de « {label} » ?",
            QMessageBox.Yes | QMessageBox.No,
            QMessageBox.No,
        )
        if answer == QMessageBox.Yes:
            self.service.usage.delete_target(target_key)
            self.refresh()

    def _confirm_delete_browser_site(self, browser, host):
        answer = QMessageBox.question(
            self,
            "Supprimer le site",
            f"Supprimer définitivement l’historique de « {host} » ?",
            QMessageBox.Yes | QMessageBox.No,
            QMessageBox.No,
        )
        if answer == QMessageBox.Yes:
            self.service.usage.delete_browser_site(browser, host)
            self.refresh()

    def _show_browser_menu(self, position, browser):
        menu = QMenu(self)
        rename_action = menu.addAction("Renommer l’activité…")
        browser_category = self.service.usage.data.get("browser_categories", {}).get(browser)
        root_action = (
            menu.addAction("Sortir de non classé")
            if browser_category == "Applications non classées" else None
        )
        remove_category = (
            menu.addAction("Retirer de la catégorie")
            if browser_category and browser_category != "__root__" else None
        )
        selected = menu.exec(position)
        if selected == rename_action:
            label, accepted = QInputDialog.getText(
                self, "Renommer l’activité", "Nouveau nom :",
                text=self.service.usage.browser_label(browser),
            )
            if accepted and label.strip():
                self.service.usage.rename_browser(browser, label)
                self.refresh()
        elif root_action is not None and selected == root_action:
            self.service.usage.make_browser_root(browser)
            self.refresh()
        elif remove_category is not None and selected == remove_category:
            self.service.usage.clear_browser_category(browser)
            self.refresh()

    def _show_site_category_menu(self, position, category, target_keys):
        menu = QMenu(self)
        rename_category = menu.addAction("Renommer la catégorie…")
        remove_category = menu.addAction("Retirer de la catégorie")
        selected = menu.exec(position)
        if selected == rename_category:
            label, accepted = QInputDialog.getText(
                self, "Renommer la catégorie", "Nouveau nom :", text=category
            )
            if accepted and label.strip():
                self.service.usage.rename_site_category_for_keys(target_keys, label)
                self.refresh()
        elif selected == remove_category:
            self.service.usage.clear_site_category_for_keys(target_keys, category)
            self.refresh()

    def _passive_row(self, media_name, seconds):
        row = QWidget()
        row.setStyleSheet("background: rgba(68, 56, 88, 190); border-radius: 6px;")
        layout = QHBoxLayout(row)
        layout.setContentsMargins(26, 8, 10, 8)
        name = QLabel(str(media_name))
        name.setStyleSheet("color: white; font-weight: bold;")
        duration = QLabel(_format_seconds(seconds))
        duration.setStyleSheet("color: #cbb8ff; font-weight: bold;")
        layout.addWidget(name, 1)
        layout.addWidget(duration)
        row.setContextMenuPolicy(Qt.CustomContextMenu)
        row.customContextMenuRequested.connect(
            lambda position, media_name=media_name, widget=row: self._show_passive_menu(
                media_name, widget.mapToGlobal(position)
            )
        )
        return row

    def _show_passive_menu(self, media_name, position):
        menu = QMenu(self)
        exclude_action = menu.addAction("Ne pas comptabiliser dans lecture passive")
        if menu.exec(position) == exclude_action:
            self.service.usage.exclude_passive(media_name)
            self.refresh()

    def _begin_drag(self):
        self._drag_in_progress = True

    def _end_drag(self):
        self._drag_in_progress = False
        self._refresh_pending = False
        self.refresh()

    def _move_to_category(self, target_key, category):
        if target_key.startswith("category-group:"):
            self.service.usage.move_category(
                target_key.removeprefix("category-group:"), category
            )
        elif target_key.startswith("group:"):
            self.service.usage.set_category_for_keys(target_key[6:].split("|"), category)
        else:
            self.service.usage.set_category(target_key, category)
        self._schedule_drop_refresh()

    def _schedule_drop_refresh(self):
        if self._drop_refresh_scheduled:
            return
        self._drop_refresh_scheduled = True
        QTimer.singleShot(50, self._finish_drop_refresh)

    def _finish_drop_refresh(self):
        if self._drag_in_progress:
            QTimer.singleShot(50, self._finish_drop_refresh)
            return
        self._drop_refresh_scheduled = False
        self.refresh()

    def _show_category_menu(self, position, category, target_keys):
        menu = QMenu(self)
        rename_action = menu.addAction("Renommer la catégorie…")
        move_action = menu.addAction(f"Déplacer « {category} » dans une catégorie…")
        parent_category = self.service.usage.data.get("category_parents", {}).get(category)
        root_action = (
            menu.addAction("Remonter à la racine") if parent_category else None
        )
        remove_action = menu.addAction("Retirer de la catégorie")
        selected = menu.exec(position)
        if selected == rename_action:
            self._rename_category(category)
            return
        if root_action is not None and selected == root_action:
            self.service.usage.make_category_root(category)
            self.refresh()
            return
        if selected == remove_action:
            self.service.usage.clear_category(category)
            self.refresh()
            return
        if selected != move_action:
            return
        categories = self.service.usage.categories()
        parent, accepted = QInputDialog.getItem(
            self,
            "Catégorie parente",
            f"Catégorie cible pour « {category} » :",
            categories,
            0,
            True,
        )
        if accepted and parent.strip():
            self.service.usage.move_category(category, parent.strip())
            self.refresh()

    def _show_entry_menu(self, position, target_key):
        menu = QMenu(self)
        rename_action = menu.addAction("Renommer l’activité…")
        category_action = menu.addAction("Ajouter à une catégorie…")
        remove_category_action = menu.addAction("Retirer de la catégorie")
        merge_action = menu.addAction("Fusionner dans une autre application…")
        specific_site_actions = {}
        browser = _other_sites_browser(target_key)
        if browser:
            sites_menu = menu.addMenu("Rendre spécifique")
            sites = self.service.usage.other_sites(browser)
            for host, seconds in sorted(sites.items(), key=lambda item: item[1], reverse=True):
                action = sites_menu.addAction(f"{host} ({_format_seconds(seconds)})")
                specific_site_actions[action] = host
        menu.addSeparator()
        exclude_action = menu.addAction("Ne pas comptabiliser")
        selected = menu.exec(position)
        if selected == rename_action:
            self._rename_target(target_key)
        elif selected == category_action:
            self._choose_category(target_key)
        elif selected == remove_category_action:
            self.service.usage.set_category(target_key, "")
            self.refresh()
        elif selected == merge_action:
            self._choose_merge_target(target_key)
        elif selected in specific_site_actions:
            self.service.usage.make_browser_site_specific(
                browser, specific_site_actions[selected]
            )
            self.refresh()
        elif selected == exclude_action:
            self.service.usage.exclude(target_key)
            self.refresh()

    def _rename_target(self, target_key):
        current_label = self.service.usage.data["targets"].get(
            target_key, {}
        ).get("label", target_key)
        label, accepted = QInputDialog.getText(
            self,
            "Renommer l’activité",
            "Nouveau nom :",
            text=current_label,
        )
        if accepted and label.strip():
            self.service.usage.rename_target(target_key, label)
            self.refresh()

    def _rename_category(self, category):
        label, accepted = QInputDialog.getText(
            self,
            "Renommer la catégorie",
            "Nouveau nom :",
            text=category,
        )
        if accepted and label.strip():
            self.service.usage.rename_category(category, label)
            self.refresh()

    def _manage_excluded_apps(self):
        excluded_targets = self.service.usage.excluded_targets()
        if not excluded_targets:
            return
        labels = [f"{target.label} ({target.key})" for target in excluded_targets]
        selected_label, accepted = QInputDialog.getItem(
            self,
            "Applications non comptabilisées",
            "Sélectionne une application à réactiver :",
            labels,
            0,
            False,
        )
        if accepted:
            target = excluded_targets[labels.index(selected_label)]
            self.service.usage.unexclude(target.key)
            self.refresh()

    def _choose_merge_target(self, source_key):
        candidates = self.service.usage.merge_candidates(source_key)
        if not candidates:
            return
        labels = [f"{target.label} ({target.key})" for target in candidates]
        selected_label, accepted = QInputDialog.getItem(
            self,
            "Fusionner l’application",
            "Fusionner toutes les durées dans :",
            labels,
            0,
            False,
        )
        if accepted:
            destination = candidates[labels.index(selected_label)]
            self.service.usage.merge_target_into(source_key, destination.key)
            self.refresh()

    def _confirm_drag_merge(self, source_key, destination_key):
        source = next(
            (target for target in self.service.usage.merge_candidates(destination_key)
             if target.key == source_key),
            None,
        )
        destination = next(
            (target for target in self.service.usage.merge_candidates(source_key)
             if target.key == destination_key),
            None,
        )
        if source is None or destination is None:
            return
        result = QMessageBox.question(
            self,
            "Fusionner les applications",
            f"Fusionner « {source.label} » dans « {destination.label} » ?\n\n"
            "Toutes les durées de la première seront déplacées vers la seconde.",
            QMessageBox.Yes | QMessageBox.No,
            QMessageBox.No,
        )
        if result == QMessageBox.Yes:
            self.service.usage.merge_target_into(source_key, destination_key)
            self.refresh()

    def _choose_category(self, target_key):
        categories = self.service.usage.categories()
        category, accepted = QInputDialog.getItem(
            self,
            "Catégorie",
            "Catégorie existante ou nouveau nom :",
            categories,
            0,
            True,
        )
        if accepted and category.strip():
            self.service.usage.set_category(target_key, category)
            self.refresh()


def _clean_name(name):
    text = str(name).strip()
    return text[:-4] if text.lower().endswith(".exe") else text


def _is_brave_entry(entry):
    if getattr(entry, "category_scope", "") == "site":
        return False
    key = entry.key.lower()
    return key == "app:brave" or key.startswith("site:brave.exe:")


def _other_sites_browser(target_key):
    key = str(target_key).lower()
    if not key.startswith("site:") or not key.endswith(":other-sites"):
        return ""
    return key.removeprefix("site:").removesuffix(":other-sites")


def _other_site_drag_parts(payload):
    """Return the browser and host encoded by an ``other-site`` drag."""
    prefix, separator, value = str(payload).partition("other-site:")
    if prefix or not separator:
        return ()
    browser, separator, host = value.partition(":")
    if not browser or not separator or not host:
        return ()
    return browser, host


def _format_seconds(seconds):
    total = max(0, int(seconds))
    hours, remainder = divmod(total, 3600)
    minutes, secs = divmod(remainder, 60)
    if hours:
        return f"{hours} h {minutes:02d} min {secs:02d} s"
    if minutes:
        return f"{minutes} min {secs:02d} s"
    return f"{secs} s"


def _close_style():
    return """
        QPushButton { color: white; background: transparent; border: none; font-size: 20px; }
        QPushButton:hover { color: #ff6b6b; }
    """


def _combo_style():
    return """
        QComboBox { color: white; background: #39393e; border: none;
                    border-radius: 4px; padding: 5px 8px; }
        QComboBox QAbstractItemView { color: white; background: #39393e;
                                     selection-background-color: #1679b8; }
    """


# Compatibility for callers using the former function name.
create_usage_guard_icon = create_usage_icon
