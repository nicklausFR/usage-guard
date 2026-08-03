from datetime import date

from PySide6.QtCore import QMimeData, QPoint, QTimer, Qt, QSize, Signal
from PySide6.QtGui import QAction, QColor, QDrag, QIcon, QPainter, QPixmap
from PySide6.QtWidgets import (
    QApplication,
    QComboBox,
    QHBoxLayout,
    QInputDialog,
    QLabel,
    QMenu,
    QPushButton,
    QScrollArea,
    QSystemTrayIcon,
    QVBoxLayout,
    QWidget,
)

from usage_guard import config


class CategoryHeader(QLabel):
    target_dropped = Signal(str)
    drag_started = Signal()
    drag_finished = Signal()

    def __init__(self, category, seconds, target_keys=None, nested=False):
        super().__init__(f"{category}    {_format_seconds(seconds)}")
        self.category = category
        self.target_keys = target_keys or []
        self.nested = nested
        self._drag_start = QPoint()
        self.setAcceptDrops(True)
        self.setStyleSheet(
            "color: #8fcaff; font-size: 12px; font-weight: bold; padding: "
            f"8px 4px 1px {22 if nested else 4}px;"
        )

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


class UsageRow(QWidget):
    drag_started = Signal()
    drag_finished = Signal()

    def __init__(self, target_key):
        super().__init__()
        self.target_key = target_key
        self._drag_start = QPoint()
        self.setCursor(Qt.OpenHandCursor)

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
        drag.exec(Qt.MoveAction)
        self.drag_finished.emit()


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


def create_tray_icon(toggle_callback, service):
    app = QApplication.instance()
    icon = QSystemTrayIcon(create_usage_icon(), app)
    icon.setToolTip("Usage Monitor — suivi actif")
    menu = QMenu()
    open_action = QAction("Ouvrir Usage Monitor", icon)
    open_action.triggered.connect(toggle_callback)

    def quit_app():
        icon.hide()
        app.quit()

    quit_action = QAction("Quitter", icon)
    quit_action.triggered.connect(quit_app)
    menu.addAction(open_action)
    menu.addSeparator()
    menu.addAction(quit_action)
    icon.setContextMenu(menu)
    icon.activated.connect(
        lambda reason: toggle_callback()
        if reason == QSystemTrayIcon.ActivationReason.Trigger
        else None
    )
    # Keep Python references alive for the lifetime of the tray icon.
    icon._menu = menu
    icon._open_action = open_action
    icon._quit_action = quit_action
    icon.show()
    return icon


class PopupPanel(QWidget):
    def __init__(self, service):
        super().__init__()
        self.service = service
        self._has_rendered = False
        self._drag_in_progress = False
        self._refresh_pending = False
        self._drop_refresh_scheduled = False
        self.setWindowFlags(Qt.Tool | Qt.FramelessWindowHint | Qt.WindowStaysOnTopHint)
        self.setAttribute(Qt.WA_TranslucentBackground)
        self.setFixedSize(
            int(getattr(config, "WINDOW_WIDTH", 420)),
            int(getattr(config, "WINDOW_HEIGHT", 520)),
        )

        background = QWidget(self)
        background.setGeometry(0, 0, self.width(), self.height())
        background.setStyleSheet(
            "background-color: rgba(38, 38, 42, 242); border-radius: 12px;"
        )
        layout = QVBoxLayout(background)
        layout.setContentsMargins(16, 16, 16, 16)
        layout.setSpacing(12)

        title_row = QHBoxLayout()
        title_icon = QLabel()
        title_icon.setPixmap(create_usage_icon(True).pixmap(QSize(18, 18)))
        title = QLabel("Usage Monitor")
        title.setStyleSheet("color: white; font-size: 16px; font-weight: bold;")
        close_button = QPushButton("×")
        close_button.setFixedSize(26, 26)
        close_button.setStyleSheet(_close_style())
        close_button.clicked.connect(self.close)
        title_row.addWidget(title_icon)
        title_row.addSpacing(6)
        title_row.addWidget(title)
        title_row.addStretch()
        title_row.addWidget(close_button)
        layout.addLayout(title_row)

        status_row = QHBoxLayout()
        self.status_label = QLabel()
        self.status_label.setStyleSheet("color: #b8b8bd;")
        self.period = QComboBox()
        self.period.addItem("Aujourd’hui", "today")
        self.period.addItem("Depuis le début", "all")
        self.period.setStyleSheet(_combo_style())
        self.period.currentIndexChanged.connect(self.refresh)
        status_row.addWidget(self.status_label, 1)
        status_row.addWidget(self.period)
        layout.addLayout(status_row)

        self.system_widget = QWidget()
        self.system_widget.setStyleSheet(
            "background: rgba(55, 55, 60, 190); border-radius: 6px;"
        )
        system_layout = QVBoxLayout(self.system_widget)
        system_layout.setContentsMargins(10, 8, 10, 8)
        system_layout.setSpacing(5)
        system_header = QLabel("Ordinateur")
        system_header.setStyleSheet("color: #8fcaff; font-size: 12px; font-weight: bold;")
        system_layout.addWidget(system_header)
        self.system_on_label = self._system_duration_row(system_layout, "Allumé")
        self.system_foreground_label = self._system_duration_row(
            system_layout, "Utilisation active"
        )
        self.system_with_passive_label = self._system_duration_row(
            system_layout, "Utilisation passive"
        )
        layout.addWidget(self.system_widget)

        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QScrollArea.NoFrame)
        scroll.setStyleSheet("QScrollArea { background: transparent; }")
        self.list_widget = QWidget()
        self.list_widget.setStyleSheet("background: transparent;")
        self.apps_layout = QVBoxLayout(self.list_widget)
        self.apps_layout.setContentsMargins(0, 0, 0, 0)
        self.apps_layout.setSpacing(7)
        self.apps_layout.addStretch()
        scroll.setWidget(self.list_widget)
        layout.addWidget(scroll, 1)

        self.service.state_changed.connect(self.refresh)
        self.refresh()

    def refresh(self):
        if self._drag_in_progress:
            self._refresh_pending = True
            return
        # The monitoring timer keeps running while the popup is closed. Do not
        # rebuild its widgets in the background on every tick.
        if self._has_rendered and not self.isVisible():
            return
        context = self.service.current_context
        if context.is_afk:
            status = "En pause — ordinateur inactif"
        elif context.app_name:
            status = f"Actif : {_clean_name(context.app_name)}"
        else:
            status = "En attente d’une application active"
        self.status_label.setText(status)

        usage = (
            self.service.usage.usage_for_day(date.today())
            if self.period.currentData() == "today"
            else self.service.usage.total_usage()
        )
        entries = self.service.usage.presentation(usage)
        passive_usage = (
            self.service.usage.passive_usage_for_day(date.today())
            if self.period.currentData() == "today"
            else self.service.usage.total_passive_usage()
        )
        system_usage = (
            self.service.usage.system_usage_for_day(date.today())
            if self.period.currentData() == "today"
            else self.service.usage.total_system_usage()
        )
        self.system_on_label.setText(_format_seconds(system_usage["on"]))
        self.system_foreground_label.setText(_format_seconds(system_usage["foreground"]))
        self.system_with_passive_label.setText(
            _format_seconds(sum(passive_usage.values()))
        )
        self._replace_rows(entries, passive_usage)
        self._has_rendered = True

    def showEvent(self, event):
        super().showEvent(event)
        self.refresh()

    def _replace_rows(self, entries, passive_usage):
        while self.apps_layout.count() > 1:
            item = self.apps_layout.takeAt(0)
            widget = item.widget()
            if widget is not None:
                # Removing a layout item does not hide it immediately. Without
                # this, rapid refreshes leave old labels painted underneath the
                # new rows.
                widget.setParent(None)
                widget.deleteLater()
        if not entries and not passive_usage:
            empty = QLabel("Aucune activité enregistrée pour cette période.")
            empty.setStyleSheet("color: #99999f; padding: 18px 4px;")
            empty.setWordWrap(True)
            self.apps_layout.insertWidget(0, empty)
            return
        grouped = {}
        for entry in entries:
            grouped.setdefault(entry.category, []).append(entry)

        index = 0
        for category, category_entries in sorted(
            grouped.items(),
            key=lambda item: sum(entry.seconds for entry in item[1]),
            reverse=True,
        ):
            category_total = sum(entry.seconds for entry in category_entries)
            header = CategoryHeader(
                category, category_total, [entry.key for entry in category_entries]
            )
            header.target_dropped.connect(
                lambda target, destination=category: self._move_to_category(target, destination)
            )
            header.drag_started.connect(self._begin_drag)
            header.drag_finished.connect(self._end_drag)
            header.setContextMenuPolicy(Qt.CustomContextMenu)
            header.customContextMenuRequested.connect(
                lambda position, group=category, group_entries=category_entries, widget=header:
                self._show_category_menu(
                    widget.mapToGlobal(position), group, [entry.key for entry in group_entries]
                )
            )
            self.apps_layout.insertWidget(index, header)
            index += 1

            brave_entries = [entry for entry in category_entries if _is_brave_entry(entry)]
            other_entries = [entry for entry in category_entries if entry not in brave_entries]
            if brave_entries:
                if category.lower() != "brave":
                    brave_total = sum(entry.seconds for entry in brave_entries)
                    brave_header = CategoryHeader(
                        "Brave", brave_total, [entry.key for entry in brave_entries], nested=True
                    )
                    brave_header.target_dropped.connect(
                        lambda target, destination=category: self._move_to_category(target, destination)
                    )
                    brave_header.drag_started.connect(self._begin_drag)
                    brave_header.drag_finished.connect(self._end_drag)
                    self.apps_layout.insertWidget(index, brave_header)
                    index += 1
                for entry in sorted(brave_entries, key=lambda item: item.seconds, reverse=True):
                    if _clean_name(entry.label).lower() != "brave":
                        self.apps_layout.insertWidget(index, self._usage_row(entry, indent_level=2))
                        index += 1
            for entry in sorted(other_entries, key=lambda item: item.seconds, reverse=True):
                # Every application is a child of its category. The explicit
                # indentation makes a moved browser visibly belong to
                # "Internet" instead of looking like another root entry.
                row = self._usage_row(entry, indent_level=1)
                self.apps_layout.insertWidget(index, row)
                index += 1

        if passive_usage:
            passive_total = sum(passive_usage.values())
            header = QLabel(f"Lecture passive    {_format_seconds(passive_total)}")
            header.setStyleSheet(
                "color: #cbb8ff; font-size: 12px; font-weight: bold; padding: 12px 4px 1px;"
            )
            self.apps_layout.insertWidget(index, header)
            index += 1
            for media_name, seconds in sorted(
                passive_usage.items(), key=lambda item: item[1], reverse=True
            ):
                self.apps_layout.insertWidget(index, self._passive_row(media_name, seconds))
                index += 1

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

    def _usage_row(self, entry, indent_level=0):
        row = UsageRow(entry.key)
        row.setStyleSheet("background: rgba(55, 55, 60, 190); border-radius: 6px;")
        row_layout = QHBoxLayout(row)
        row_layout.setContentsMargins(10 + indent_level * 16, 8, 10, 8)
        name = QLabel(_clean_name(entry.label))
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
        row.drag_started.connect(self._begin_drag)
        row.drag_finished.connect(self._end_drag)
        return row

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
        if target_key.startswith("group:"):
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
        move_action = menu.addAction(f"Déplacer « {category} » dans une catégorie…")
        if menu.exec(position) != move_action:
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
            self.service.usage.set_category_for_keys(target_keys, parent.strip())
            self.refresh()

    def _show_entry_menu(self, position, target_key):
        menu = QMenu(self)
        category_action = menu.addAction("Ajouter à une catégorie…")
        remove_category_action = menu.addAction("Retirer de la catégorie")
        menu.addSeparator()
        exclude_action = menu.addAction("Ne pas comptabiliser")
        selected = menu.exec(position)
        if selected == category_action:
            self._choose_category(target_key)
        elif selected == remove_category_action:
            self.service.usage.set_category(target_key, "")
            self.refresh()
        elif selected == exclude_action:
            self.service.usage.exclude(target_key)
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
    key = entry.key.lower()
    return key == "app:brave" or key.startswith("site:brave.exe:")


def _format_seconds(seconds):
    total = max(0, int(seconds))
    hours, remainder = divmod(total, 3600)
    minutes, secs = divmod(remainder, 60)
    if hours:
        return f"{hours} h {minutes:02d} min"
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
