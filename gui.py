from datetime import date

from PySide6.QtCore import QDate, QMimeData, QPoint, QTimer, Qt, QSize, Signal
from PySide6.QtGui import QAction, QColor, QDrag, QIcon, QPainter, QPixmap
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
    QScrollArea,
    QSystemTrayIcon,
    QTreeWidget,
    QTreeWidgetItem,
    QVBoxLayout,
    QWidget,
)

from usage_guard import computer_on_seconds_today, config


_DURATION_SECONDS_ROLE = Qt.UserRole + 3


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
        drag.exec(Qt.MoveAction)
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

    def __init__(self, parent=None):
        super().__init__(parent)
        self._dragged_target_key = None

    def dragEnterEvent(self, event):
        event.acceptProposedAction()

    def dragMoveEvent(self, event):
        event.acceptProposedAction()

    def startDrag(self, supported_actions):
        item = self.currentItem()
        self._dragged_target_key = (
            item.data(0, Qt.UserRole + 1)
            if item is not None and item.data(0, Qt.UserRole) == "target"
            else None
        )
        super().startDrag(supported_actions)
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
            category = self._parent_category(destination)
            if category is not None:
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
    icon.show()

    # At logon, Explorer (which owns the notification area) may still be
    # starting.  A single immediate retry is often still too early.  Retry for
    # the first minute so the icon is eventually registered without requiring
    # the user to restart Usage Monitor.
    retry_delays_ms = (500, 1_500, 5_000, 15_000, 45_000)
    for delay_ms in retry_delays_ms:
        QTimer.singleShot(delay_ms, icon.show)
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
        self.setWindowTitle("Usage Monitor")
        self.setWindowIcon(create_usage_icon(True))
        self.setAttribute(Qt.WA_TranslucentBackground, False)
        self.resize(
            int(getattr(config, "WINDOW_WIDTH", 420)),
            int(getattr(config, "WINDOW_HEIGHT", 520)),
        )

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
        self.period.addItem("Aujourd’hui", "today")
        self.period.addItem("Choisir un jour…", "date")
        self.period.addItem("Depuis le début", "all")
        self.period.setStyleSheet(_combo_style())
        self.period.currentIndexChanged.connect(self._period_changed)
        self.day_picker = QDateEdit(QDate.currentDate().addDays(-1))
        self.day_picker.setCalendarPopup(True)
        self.day_picker.setDisplayFormat("dd/MM/yyyy")
        self.day_picker.setMaximumDate(QDate.currentDate())
        self.day_picker.setToolTip("Choisir le jour à afficher")
        self.day_picker.setStyleSheet(_combo_style())
        self.day_picker.dateChanged.connect(self.refresh)
        self.day_picker.hide()
        status_row.addWidget(self.status_label, 1)
        status_row.addWidget(self.period)
        status_row.addWidget(self.day_picker)
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
        self.system_on_label = self._system_duration_row(system_layout, "Session Windows")
        self.system_foreground_label = self._system_duration_row(
            system_layout, "Utilisation active"
        )
        self.system_with_passive_label = self._system_duration_row(
            system_layout, "Usage passif"
        )
        layout.addWidget(self.system_widget)

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
        layout.addWidget(self.tree, 1)

        self.excluded_apps_button = QPushButton("Applications exclues…")
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
        context = self.service.current_context
        if context.is_afk:
            status = "En pause — ordinateur inactif"
        elif context.app_name:
            target = self.service.usage.target_for_context(context)
            status = f"Actif : {_clean_name(target.label)}"
        else:
            status = "En attente d’une application active"
        self.status_label.setText(status)

        selected_day = self._selected_day()
        usage = (
            self.service.usage.usage_for_day(selected_day)
            if selected_day is not None
            else self.service.usage.total_usage()
        )
        entries = self.service.usage.presentation(usage)
        passive_usage = (
            self.service.usage.passive_usage_for_day(selected_day)
            if selected_day is not None
            else self.service.usage.total_passive_usage()
        )
        system_usage = (
            self.service.usage.system_usage_for_day(selected_day)
            if selected_day is not None
            else self.service.usage.total_system_usage()
        )
        system_on_seconds = system_usage["on"]
        if selected_day == date.today():
            system_on_seconds = computer_on_seconds_today() or system_on_seconds
        self.system_on_label.setText(_format_seconds(system_on_seconds))
        # The active total must match the activities shown below exactly.
        self.system_foreground_label.setText(
            _format_seconds(sum(entry.seconds for entry in entries))
        )
        self.system_with_passive_label.setText(
            _format_seconds(sum(passive_usage.values()))
        )
        self._replace_rows(entries, passive_usage)
        self._has_rendered = True

    def _period_changed(self):
        self.day_picker.setVisible(self.period.currentData() == "date")
        self.refresh()

    def _selected_day(self):
        """Return the displayed day, or None for the all-time view."""
        period = self.period.currentData()
        if period == "all":
            return None
        if period == "today":
            return date.today()
        selected = self.day_picker.date()
        return date(selected.year(), selected.month(), selected.day())

    def showEvent(self, event):
        super().showEvent(event)
        self.refresh()

    def _replace_rows(self, entries, passive_usage):
        self.tree.blockSignals(True)
        self.tree.clear()
        grouped = {}
        for entry in entries:
            grouped.setdefault(entry.category, []).append(entry)
        brave_displayed = False
        for category, category_entries in sorted(grouped.items(), key=lambda item: sum(x.seconds for x in item[1]), reverse=True):
            if category == "__root__":
                brave_entries = [entry for entry in category_entries if _is_brave_entry(entry)]
                for entry in sorted(
                    (entry for entry in category_entries if entry not in brave_entries),
                    key=lambda x: x.seconds, reverse=True,
                ):
                    self._tree_item(None, entry.label, entry.seconds, "target", entry.key)
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
                    for entry in sorted(direct, key=lambda x: x.seconds, reverse=True):
                        self._tree_item(browser, entry.label, entry.seconds, "target", entry.key)
                    for name in sorted(set(grouped_sites) | set(self.service.usage.site_categories())):
                        site_entries = grouped_sites.get(name, [])
                        node = self._tree_item(browser, name, sum(x.seconds for x in site_entries), "site-category", (name, [x.key for x in site_entries]))
                        for entry in sorted(site_entries, key=lambda x: x.seconds, reverse=True):
                            self._tree_item(node, entry.label, entry.seconds, "target", entry.key)
                    for entry in other_sites:
                        node = self._tree_item(browser, "Autres sites", entry.seconds, "other-sites", entry.key)
                        for host, seconds in sorted(self._other_sites_for_display("brave.exe").items(), key=lambda x: x[1], reverse=True):
                            self._tree_item(node, host, seconds, "other-site", ("brave.exe", host))
                continue
            root = self._tree_item(None, category, sum(x.seconds for x in category_entries), "category", [x.key for x in category_entries])
            brave = [x for x in category_entries if _is_brave_entry(x)]
            for entry in sorted((x for x in category_entries if x not in brave), key=lambda x: x.seconds, reverse=True):
                self._tree_item(root, entry.label, entry.seconds, "target", entry.key)
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
                for entry in sorted(direct_sites, key=lambda x: x.seconds, reverse=True):
                    self._tree_item(browser, entry.label, entry.seconds, "target", entry.key)
                for site_category in sorted(
                    set(site_groups) | set(self.service.usage.site_categories())
                ):
                    site_entries = site_groups.get(site_category, [])
                    parent = self._tree_item(
                        browser, site_category, sum(x.seconds for x in site_entries),
                        "site-category", (site_category, [x.key for x in site_entries])
                    )
                    for entry in sorted(site_entries, key=lambda x: x.seconds, reverse=True):
                        self._tree_item(parent, entry.label, entry.seconds, "target", entry.key)
                for entry in sorted(other_sites, key=lambda x: x.seconds, reverse=True):
                    node = self._tree_item(browser, "Autres sites", entry.seconds, "other-sites", entry.key)
                    for host, seconds in sorted(self._other_sites_for_display("brave.exe").items(), key=lambda x: x[1], reverse=True):
                        self._tree_item(node, host, seconds, "other-site", ("brave.exe", host))
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
            passive = self._tree_item(None, "Lecture passive", sum(passive_usage.values()), "passive", None)
            for name, seconds in passive_usage.items():
                self._tree_item(passive, name, seconds, "passive-item", name)
        for root_index in range(self.tree.topLevelItemCount()):
            root = self.tree.topLevelItem(root_index)
            self._reconcile_duration_totals(root)
            self._restore_tree_state(root)
        self.tree.blockSignals(False)

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
        if kind == "target":
            item.setFlags(item.flags() | Qt.ItemIsDragEnabled)
        item.setForeground(1, QColor("#27d17f"))
        if kind in {"category", "browser", "site-category", "other-sites", "passive", "excluded"}:
            item.setForeground(0, QColor("#8fcaff"))
        return item

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
        self.service.usage.make_root(target_key)
        self.refresh()

    def _move_target_to_category(self, target_key, category):
        self.service.usage.set_category(target_key, category)
        self.refresh()

    def _move_target_to_browser(self, target_key):
        # A specific site dropped directly on its browser remains a browser
        # site; only its optional site sub-category must be removed.
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
        row.setToolTip("Clic droit : rendre ce site spécifique")
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
        if menu.exec(position) == make_specific:
            self.service.usage.make_browser_site_specific(browser, host)
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
            self.service.usage.clear_site_category_for_keys(target_keys)
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
        rename_action = menu.addAction("Renommer la catégorie…")
        move_action = menu.addAction(f"Déplacer « {category} » dans une catégorie…")
        remove_action = menu.addAction("Retirer de la catégorie")
        selected = menu.exec(position)
        if selected == rename_action:
            self._rename_category(category)
            return
        if selected == remove_action:
            self.service.usage.set_category_for_keys(target_keys, "")
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
            self.service.usage.set_category_for_keys(target_keys, parent.strip())
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
    key = entry.key.lower()
    return key == "app:brave" or key.startswith("site:brave.exe:")


def _other_sites_browser(target_key):
    key = str(target_key).lower()
    if not key.startswith("site:") or not key.endswith(":other-sites"):
        return ""
    return key.removeprefix("site:").removesuffix(":other-sites")


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
