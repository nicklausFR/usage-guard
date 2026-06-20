from datetime import datetime

from PySide6.QtCore import Qt, QSize, QTimer
from PySide6.QtGui import QAction, QColor, QIcon, QPainter, QPalette, QPixmap
from PySide6.QtWidgets import (
    QApplication,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMenu,
    QMessageBox,
    QInputDialog,
    QPushButton,
    QProgressBar,
    QSystemTrayIcon,
    QVBoxLayout,
    QWidget,
)

from usage_guard import config


def _windows_uses_light_taskbar():
    try:
        import platform
        import winreg

        if platform.system() != "Windows":
            return None
        key_path = r"Software\Microsoft\Windows\CurrentVersion\Themes\Personalize"
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, key_path) as key:
            value, _ = winreg.QueryValueEx(key, "SystemUsesLightTheme")
            return bool(value)
    except OSError:
        return None


def create_usage_guard_icon(active=False):
    pixmap = QPixmap(64, 64)
    pixmap.fill(Qt.transparent)
    painter = QPainter(pixmap)
    painter.setRenderHint(QPainter.Antialiasing)

    base = QColor("#00aaff" if not active else "#ff5c5c")
    painter.setBrush(base)
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
    icon = QSystemTrayIcon(create_usage_guard_icon(), app)
    icon.setToolTip("Usage-Guard")

    menu = QMenu()
    open_action = QAction("Open Usage-Guard", icon)
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
    icon._menu = menu
    icon._open_action = open_action
    icon._quit_action = quit_action
    icon.activated.connect(
        lambda reason: toggle_callback()
        if reason == QSystemTrayIcon.ActivationReason.Trigger
        else None
    )

    def refresh_icon(violation=""):
        icon.setIcon(create_usage_guard_icon(active=bool(violation)))
        icon.setToolTip(violation or "Usage-Guard")

    service.violation_changed.connect(refresh_icon)
    icon.show()
    return icon


class PopupPanel(QWidget):
    def __init__(self, service):
        super().__init__()
        self.service = service
        self._activity_phase = 0
        self._rule_widgets = {}
        self.setWindowFlags(Qt.Tool | Qt.FramelessWindowHint | Qt.WindowStaysOnTopHint)
        self.setAttribute(Qt.WA_TranslucentBackground)
        self.setFixedSize(
            int(getattr(config, "WINDOW_WIDTH", 360)),
            int(getattr(config, "WINDOW_HEIGHT", 420)),
        )

        self.bg = QWidget(self)
        self.bg.setStyleSheet("background-color: rgba(45, 45, 45, 230); border-radius: 12px;")
        self.bg.setGeometry(0, 0, self.width(), self.height())

        layout = QVBoxLayout(self.bg)
        layout.setContentsMargins(16, 16, 16, 16)
        layout.setSpacing(12)

        title_row = QHBoxLayout()
        title_icon = QLabel()
        title_icon.setPixmap(create_usage_guard_icon().pixmap(QSize(16, 16)))
        title = QLabel("Usage-Guard")
        title.setStyleSheet("color: white; font-weight: bold;")
        title_row.addWidget(title_icon)
        title_row.addSpacing(6)
        title_row.addWidget(title)
        title_row.addStretch()

        close_button = QPushButton("x")
        close_button.setFixedSize(24, 24)
        close_button.setStyleSheet("""
            QPushButton {
                background: transparent;
                color: white;
                border: none;
                font-size: 14px;
            }
            QPushButton:hover {
                color: #ff5c5c;
            }
        """)
        close_button.clicked.connect(self.close)
        title_row.addWidget(close_button)
        layout.addLayout(title_row)

        self.violation_label = QLabel()
        self.violation_label.setStyleSheet("color: #ffd166; font-weight: bold;")
        self.violation_label.setWordWrap(True)
        layout.addWidget(self.violation_label)

        self.rules_layout = QVBoxLayout()
        self.rules_layout.setSpacing(10)
        layout.addLayout(self.rules_layout)

        self.reset_label = QLabel()
        self.reset_label.setStyleSheet("color: #ff8a8a;")
        self.reset_label.setWordWrap(True)
        layout.addWidget(self.reset_label)

        bottom_row = QHBoxLayout()
        reload_button = QPushButton("Reload")
        reload_button.setFixedHeight(26)
        reload_button.setStyleSheet(_button_style())
        reload_button.clicked.connect(self.reload_rules)
        unlock_button = QPushButton("Unlock")
        unlock_button.setFixedHeight(26)
        unlock_button.setStyleSheet(_button_style())
        unlock_button.clicked.connect(self.unlock)
        joker_button = QPushButton("Joker +10m")
        joker_button.setFixedHeight(26)
        joker_button.setStyleSheet(_button_style())
        joker_button.clicked.connect(lambda: self.grant_joker(10))
        bottom_row.addWidget(reload_button)
        bottom_row.addWidget(unlock_button)
        bottom_row.addWidget(joker_button)
        bottom_row.addStretch()
        layout.addLayout(bottom_row)

        self._rebuild_rule_list()
        self.service.state_changed.connect(self.refresh)
        self.activity_timer = QTimer(self)
        self.activity_timer.timeout.connect(self._advance_activity_phase)
        self.activity_timer.start(1000)
        QTimer.singleShot(0, self.refresh)

    def _rebuild_rule_list(self):
        while self.rules_layout.count():
            item = self.rules_layout.takeAt(0)
            widget = item.widget()
            if widget is not None:
                widget.deleteLater()
        self._rule_widgets = {}
        for rule in self.service.rules.rules:
            self._rule_widgets[rule.name] = self._create_rule_row(rule)

    def reload_rules(self):
        self.service.rules.load()
        self._rebuild_rule_list()
        self.refresh()

    def unlock(self):
        password, ok = QInputDialog.getText(
            self,
            "Usage-Guard",
            "Master password",
            echo=QLineEdit.EchoMode.Password,
        )
        if not ok:
            return
        if not self.service.unlock_with_master_password(password):
            QMessageBox.warning(self, "Usage-Guard", "Invalid master password.")

    def grant_joker(self, minutes):
        rule = self._first_active_rule() or self._first_rule()
        if rule is None:
            return
        self.service.grant_joker(rule, minutes)
        self.refresh()

    def toggle_rule(self, rule):
        rule.enabled = not rule.enabled
        self.service.rules.save()
        self.refresh()

    def _advance_activity_phase(self):
        self._activity_phase = (self._activity_phase + 1) % 2
        if self.isVisible():
            self.refresh(light=True)

    def refresh(self, light=False):
        now = datetime.now().astimezone()
        context = self.service.current_context
        if not light:
            self.violation_label.setText(self.service.current_violation or "No active limit reached")
            self.reset_label.setText(
                "Usage storage was missing at startup. Master password required."
                if self.service.locked
                else ""
            )
        for rule in self.service.rules.rules:
            self._update_rule_row(rule, context, now)

    def _create_rule_row(self, rule):
        row = QWidget()
        row.setStyleSheet("background: rgba(35, 35, 35, 180); border-radius: 6px;")
        outer = QVBoxLayout(row)
        outer.setContentsMargins(8, 8, 8, 8)
        outer.setSpacing(6)

        header = QHBoxLayout()
        name_label = QLabel(rule.name)
        name_label.setStyleSheet("color: white; font-weight: bold;")
        toggle = QPushButton("On" if rule.enabled else "Off")
        toggle.setCheckable(True)
        toggle.setChecked(rule.enabled)
        toggle.setFixedSize(42, 24)
        toggle.setStyleSheet(_toggle_style(rule.enabled))
        toggle.clicked.connect(lambda _checked=False, r=rule: self.toggle_rule(r))
        header.addWidget(name_label, 1)
        header.addWidget(toggle)
        outer.addLayout(header)

        quota_layout = QVBoxLayout()
        quota_layout.setSpacing(5)
        outer.addLayout(quota_layout)
        widgets = {
            "row": row,
            "toggle": toggle,
            "quotas": {},
        }
        if rule.quotas:
            for quota in rule.quotas:
                widgets["quotas"][quota.period] = self._create_quota_widgets(quota_layout)
        else:
            label = QLabel("No quota")
            label.setStyleSheet("color: #d6d6d6;")
            quota_layout.addWidget(label)
        self.rules_layout.addWidget(row)
        return widgets

    def _create_quota_widgets(self, layout):
        label = QLabel()
        label.setStyleSheet("color: #e6e6e6;")
        layout.addWidget(label)

        bar = QProgressBar()
        bar.setRange(0, 1000)
        bar.setTextVisible(True)
        bar.setFixedHeight(14)
        bar.setStyleSheet(_progress_style("idle"))
        layout.addWidget(bar)
        return {"label": label, "bar": bar}

    def _update_rule_row(self, rule, context, now):
        widgets = self._rule_widgets.get(rule.name)
        if widgets is None:
            return
        rule_active = (
            rule.enabled
            and self.service._rule_matches(rule, context)
            and self.service.is_activity_countable(context)
            and not self.service.locked
        )
        widgets["toggle"].setChecked(rule.enabled)
        widgets["toggle"].setText("On" if rule.enabled else "Off")
        widgets["toggle"].setStyleSheet(_toggle_style(rule.enabled, active=rule_active))
        quota_exceeded = False
        for quota in rule.quotas:
            quota_widgets = widgets["quotas"].get(quota.period)
            if quota_widgets is None:
                continue
            used = self.service.usage.seconds_for(rule.target_type, rule.target, quota.period, now)
            limit = max(1, quota.limit_minutes * 60)
            percent = min(100.0, used / limit * 100)
            progress_value = min(1000, max(0, round(percent * 10)))
            quota_exceeded = quota_exceeded or used >= limit
            quota_widgets["label"].setText(f"{quota.period}: {_format_seconds(used)} / {_format_seconds(limit)}")
            quota_widgets["bar"].setValue(progress_value)
            quota_widgets["bar"].setFormat(_format_percent(percent))
            bar_state = "exceeded" if used >= limit else ("active" if rule_active else "idle")
            quota_widgets["bar"].setStyleSheet(_progress_style(bar_state))

    def _first_active_rule(self):
        context = self.service.current_context
        for rule in self.service.rules.rules:
            if (
                rule.enabled
                and self.service._rule_matches(rule, context)
                and self.service.is_activity_countable(context)
                and not self.service.locked
            ):
                return rule
        return None

    def _first_rule(self):
        return self.service.rules.rules[0] if self.service.rules.rules else None


def _progress_style(state="idle"):
    if state == "exceeded":
        chunk = "#ff5c5c"
    elif state == "active":
        chunk = "#ffd166"
    else:
        chunk = "#27d17f"
    return f"""
            QProgressBar {{
                background: #5a5a5a;
                border: 1px solid #3f3f3f;
                border-radius: 6px;
                color: white;
                font-size: 9px;
                text-align: center;
            }}
            QProgressBar::chunk {{
                background: {chunk};
                border-radius: 6px;
                margin: 1px;
            }}
        """


def _format_seconds(seconds):
    minutes = int(seconds // 60)
    hours = minutes // 60
    remaining = minutes % 60
    if hours:
        return f"{hours}h{remaining:02d}"
    return f"{remaining}m"


def _format_percent(percent):
    if 0 < percent < 0.1:
        return "<0.1%"
    if percent < 10:
        return f"{percent:.1f}%"
    return f"{round(percent)}%"


def _button_style():
    return """
        QPushButton {
            color: white;
            background: #333;
            border: none;
            border-radius: 4px;
            padding: 2px 8px;
        }
        QPushButton:pressed {
            background-color: #2d8cf0;
        }
    """


def _toggle_style(enabled, active=False):
    if active:
        bg = "#ffd166"
        hover = "#ffe08a"
        text = "#111"
    else:
        bg = "#27d17f"
        hover = "#34e892"
        text = "#111"
    return f"""
        QPushButton {{
            color: {text};
            background: {bg};
            border: none;
            border-radius: 4px;
            font-weight: bold;
        }}
        QPushButton:hover {{
            background: {hover};
        }}
    """
