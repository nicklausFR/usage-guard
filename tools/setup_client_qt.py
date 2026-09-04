"""PySide6 enrollment wizard used by the elevated Windows installer."""

from __future__ import annotations

import argparse
import socket
import sys
import threading
from pathlib import Path
from urllib.parse import quote

from PySide6.QtCore import Qt, Signal
from PySide6.QtWidgets import (
    QApplication, QComboBox, QDialog, QFormLayout, QFrame, QHBoxLayout,
    QHeaderView, QLabel, QLineEdit, QMessageBox, QPushButton, QTableWidget,
    QTableWidgetItem, QVBoxLayout,
)

from i18n import _

from setup_client import (
    AdminApi, DEFAULT_BASE_URL, atomic_json, protect_secret,
    validate_windows_identity_mappings, windows_identity_mapping,
)
from windows_identity import (
    current_windows_session_identity, enumerate_windows_accounts,
)


STYLE = """
QDialog { background:#111715; color:#eef5f1; }
QLabel { color:#d7e2dc; }
QLabel#title { color:#f5fbf8; font-size:22px; font-weight:700; }
QLabel#subtitle, QLabel#status { color:#aebdb5; }
QFrame#panel { background:#18231f; border:1px solid #385047; border-radius:10px; }
QLineEdit, QComboBox { background:#111715; border:1px solid #53645c; border-radius:6px;
  color:#f5fbf8; padding:8px; min-height:20px; }
QLineEdit:focus, QComboBox:focus { border-color:#28c9b7; }
QPushButton { background:#26332e; border:1px solid #53645c; border-radius:7px;
  color:#eef5f1; padding:9px 16px; }
QPushButton#primary { background:#08776d; border-color:#20bbaa; font-weight:700; }
QPushButton#primary:hover { background:#0a8b7e; }
QPushButton:disabled { color:#6f7d76; background:#1a211e; border-color:#354139; }
"""


class SetupDialog(QDialog):
    operation_done = Signal(object)
    operation_failed = Signal(str)

    def __init__(self, output, default_base_url, existing_device_id=""):
        super().__init__()
        self.output = Path(output)
        self.existing_device_id = str(existing_device_id or "").strip()
        self.api = None
        self.devices = []
        self.trackable_users = []
        self.current_windows_identity = current_windows_session_identity() or {}
        current_sid = str(
            self.current_windows_identity.get("windows_sid") or ""
        ).upper()
        self.windows_accounts = sorted(
            enumerate_windows_accounts(),
            key=lambda account: (
                str(account.get("windows_sid") or "").upper() != current_sid,
                str(account.get("windows_username") or "").casefold(),
            ),
        )
        self._success_callback = None
        self.setWindowTitle(_("Installation de Usage Guard"))
        self.setMinimumWidth(880)
        self.setWindowFlag(Qt.WindowContextHelpButtonHint, False)
        self.setStyleSheet(STYLE)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(26, 24, 26, 24)
        layout.setSpacing(16)
        title = QLabel(_("Configurer cet ordinateur"))
        title.setObjectName("title")
        layout.addWidget(title)
        subtitle = QLabel(_(
            "Connectez-vous avec un compte administrateur Usage Guard. "
            "Le mot de passe ne sera jamais enregistré."
        ))
        subtitle.setObjectName("subtitle")
        subtitle.setWordWrap(True)
        layout.addWidget(subtitle)

        self.profile_panel = self.panel()
        profile_form = QFormLayout(self.profile_panel)
        self.profile_choice = QComboBox()
        self.profile_choice.addItem(_("Local — un seul ordinateur"), "local")
        self.profile_choice.addItem(_("Connecté à un serveur"), "server")
        self.profile_choice.setCurrentIndex(1)
        if self.existing_device_id:
            self.profile_choice.setEnabled(False)
        self.profile_choice.currentIndexChanged.connect(self.profile_changed)
        profile_form.addRow(_("Profil d’installation"), self.profile_choice)
        layout.addWidget(self.profile_panel)

        self.local_panel = self.panel()
        local_form = QFormLayout(self.local_panel)
        self.local_display_name = QLineEdit(socket.gethostname())
        self.local_admin_username = QLineEdit("admin")
        self.local_admin_email = QLineEdit()
        self.local_admin_password = QLineEdit()
        self.local_admin_password.setEchoMode(QLineEdit.Password)
        self.local_admin_confirmation = QLineEdit()
        self.local_admin_confirmation.setEchoMode(QLineEdit.Password)
        local_form.addRow(_("Nom de l’ordinateur"), self.local_display_name)
        local_form.addRow(_("Administrateur Usage Guard"), self.local_admin_username)
        local_form.addRow(_("E-mail administrateur"), self.local_admin_email)
        local_form.addRow(_("Mot de passe"), self.local_admin_password)
        local_form.addRow(_("Confirmer le mot de passe"), self.local_admin_confirmation)
        self.local_identity_table = QTableWidget(len(self.windows_accounts), 3)
        self.local_identity_table.setHorizontalHeaderLabels([
            _("Compte Windows existant"), _("Identifiant Usage Guard"), _("Rôle"),
        ])
        self.local_identity_table.horizontalHeader().setSectionResizeMode(
            0, QHeaderView.Stretch
        )
        self.local_identity_table.horizontalHeader().setSectionResizeMode(
            1, QHeaderView.ResizeToContents
        )
        self.local_identity_table.horizontalHeader().setSectionResizeMode(
            2, QHeaderView.ResizeToContents
        )
        self.local_identity_table.verticalHeader().setVisible(False)
        for row, account in enumerate(self.windows_accounts):
            account_item = QTableWidgetItem(self.account_choice_label(account))
            account_item.setToolTip(self.account_choice_detail(account))
            account_item.setData(Qt.UserRole, dict(account))
            account_item.setFlags(account_item.flags() & ~Qt.ItemIsEditable)
            self.local_identity_table.setItem(row, 0, account_item)
            suggested = str(account.get("windows_username") or "")
            if not (
                3 <= len(suggested) <= 32
                and suggested[0].isalnum()
                and all(character.isalnum() or character in ".-_" for character in suggested)
            ):
                suggested = ""
            self.local_identity_table.setCellWidget(row, 1, QLineEdit(suggested))
            role = QComboBox()
            role.addItem(_("Non suivi"), "")
            role.addItem(_("Utilisateur à limiter"), "limited")
            self.local_identity_table.setCellWidget(row, 2, role)
        local_form.addRow(_("Sessions Windows"), self.local_identity_table)
        self.local_install_button = QPushButton(_("Installer en mode local"))
        self.local_install_button.setObjectName("primary")
        self.local_install_button.clicked.connect(self.configure_local)
        local_form.addRow("", self.local_install_button)
        self.local_panel.setVisible(False)
        layout.addWidget(self.local_panel)

        self.login_panel = self.panel()
        login_form = QFormLayout(self.login_panel)
        self.base_url = QLineEdit(default_base_url)
        self.username = QLineEdit()
        self.password = QLineEdit()
        self.password.setEchoMode(QLineEdit.Password)
        self.password.returnPressed.connect(self.connect_server)
        login_form.addRow(_("Adresse du serveur"), self.base_url)
        login_form.addRow(_("Identifiant administrateur"), self.username)
        login_form.addRow(_("Mot de passe"), self.password)
        self.connect_button = QPushButton(_("Se connecter"))
        self.connect_button.setObjectName("primary")
        self.connect_button.clicked.connect(self.connect_server)
        login_form.addRow("", self.connect_button)
        layout.addWidget(self.login_panel)

        self.device_panel = self.panel()
        device_form = QFormLayout(self.device_panel)
        self.device_choice = QComboBox()
        self.device_choice.currentIndexChanged.connect(self.refresh_name)
        self.display_name = QLineEdit(socket.gethostname())
        device_form.addRow(_("Type d’installation"), self.device_choice)
        device_form.addRow(_("Nom de l’ordinateur"), self.display_name)
        self.identity_table = QTableWidget(0, 2)
        self.identity_table.setHorizontalHeaderLabels([
            _("Utilisateur Usage Guard"), _("Compte Windows existant"),
        ])
        self.identity_table.horizontalHeader().setSectionResizeMode(
            0, QHeaderView.ResizeToContents
        )
        self.identity_table.horizontalHeader().setSectionResizeMode(
            1, QHeaderView.Stretch
        )
        self.identity_table.verticalHeader().setVisible(False)
        device_form.addRow(_("Associations de session"), self.identity_table)
        self.install_button = QPushButton(_("Installer Usage Guard"))
        self.install_button.setObjectName("primary")
        self.install_button.clicked.connect(self.enroll)
        device_form.addRow("", self.install_button)
        self.device_panel.setEnabled(False)
        layout.addWidget(self.device_panel)

        footer = QHBoxLayout()
        self.status = QLabel(_("En attente de connexion."))
        self.status.setObjectName("status")
        self.status.setWordWrap(True)
        footer.addWidget(self.status, 1)
        cancel = QPushButton(_("Annuler"))
        cancel.clicked.connect(self.reject)
        footer.addWidget(cancel)
        layout.addLayout(footer)

        self.operation_done.connect(self._operation_succeeded)
        self.operation_failed.connect(self._operation_failed)
        self.username.setFocus()

    def profile_changed(self):
        local = self.profile_choice.currentData() == "local"
        self.local_panel.setVisible(local)
        self.login_panel.setEnabled(not local)
        self.login_panel.setVisible(not local)
        self.device_panel.setEnabled(not local and self.api is not None)
        self.device_panel.setVisible(not local)
        if local:
            self.status.setText(_(
                "Choisissez les sessions Windows suivies. Le mot de passe "
                "administrateur est propre à Usage Guard et n’est jamais celui de Windows."
            ))
        else:
            self.status.setText(_(
                "En attente de connexion au serveur."
                if self.api is None else
                "Connexion réussie. Vérifiez les associations avant installation."
            ))

    def configure_local(self):
        display_name = self.local_display_name.text().strip()
        admin_username = self.local_admin_username.text().strip()
        admin_email = self.local_admin_email.text().strip()
        password = self.local_admin_password.text()
        confirmation = self.local_admin_confirmation.text()
        if not 1 <= len(display_name) <= 80:
            QMessageBox.warning(self, "Usage Guard", _("Nom d’ordinateur invalide."))
            return
        if not (
            3 <= len(admin_username) <= 32
            and admin_username[0].isalnum()
            and all(character.isalnum() or character in ".-_" for character in admin_username)
        ):
            QMessageBox.warning(self, "Usage Guard", _("Identifiant administrateur invalide."))
            return
        if len(password) < 10 or password != confirmation:
            QMessageBox.warning(
                self, "Usage Guard",
                _("Le mot de passe doit contenir au moins 10 caractères et les deux saisies doivent correspondre."),
            )
            return
        users, mappings = [], []
        default_permissions = {
            "view_activity": True, "view_analysis": True,
            "view_limits": True, "view_notifications": True,
            "manage_activity": False, "manage_limits": False,
            "manage_notifications": False,
        }
        for row in range(self.local_identity_table.rowCount()):
            role = self.local_identity_table.cellWidget(row, 2).currentData()
            if not role:
                continue
            account = self.local_identity_table.item(row, 0).data(Qt.UserRole)
            username = self.local_identity_table.cellWidget(row, 1).text().strip()
            permissions = dict(default_permissions)
            if role == "limited":
                permissions.update({
                    "manage_activity": True,
                    "manage_notifications": True,
                })
            users.append({
                "username": username, "role": role,
                "permissions": permissions,
            })
            mappings.append(windows_identity_mapping(account, username))
        try:
            mappings = validate_windows_identity_mappings(mappings)
        except ValueError as error:
            QMessageBox.warning(self, "Usage Guard", str(error))
            return
        usernames = [item["username"].casefold() for item in users]
        if len(usernames) != len(set(usernames)) or admin_username.casefold() in usernames:
            QMessageBox.warning(
                self, "Usage Guard",
                _("Chaque identifiant Usage Guard doit être unique et distinct de l’administrateur."),
            )
            return
        try:
            protected_password = protect_secret(password)
            atomic_json(self.output, {
                "installation_profile": "local",
                "display_name": display_name,
                "administrator": {
                    "username": admin_username,
                    "email": admin_email,
                    "protected_password": protected_password,
                },
                "users": users,
                "windows_identities": mappings,
            })
        except Exception as error:
            QMessageBox.critical(self, "Usage Guard", str(error))
            return
        finally:
            password = None
            confirmation = None
            self.local_admin_password.clear()
            self.local_admin_confirmation.clear()
        self.accept()

    @staticmethod
    def panel():
        panel = QFrame()
        panel.setObjectName("panel")
        return panel

    def account_choice_label(self, account):
        username = str(account.get("windows_username") or "")
        domain = str(account.get("windows_domain") or "")
        sid = str(account.get("windows_sid") or "").upper()
        labels = []
        if sid and sid == str(
            self.current_windows_identity.get("windows_sid") or ""
        ).upper():
            labels.append(_("session active"))
        if account.get("is_windows_admin"):
            labels.append(_("administrateur Windows"))
        suffix = " — " + " — ".join(labels) if labels else ""
        return f"{username} ({domain}){suffix}" if domain else f"{username}{suffix}"

    def account_choice_detail(self, account):
        return (
            self.account_choice_label(account)
            + f"\nSID : {str(account.get('windows_sid') or '').upper()}"
        )

    def set_busy(self, busy, message):
        self.connect_button.setEnabled(not busy)
        self.install_button.setEnabled(not busy and self.device_panel.isEnabled())
        self.status.setText(message)
        QApplication.setOverrideCursor(Qt.WaitCursor) if busy else QApplication.restoreOverrideCursor()

    def background(self, operation, success):
        self._success_callback = success

        def run():
            try:
                result = operation()
            except Exception as error:
                self.operation_failed.emit(str(error))
            else:
                self.operation_done.emit(result)

        threading.Thread(target=run, daemon=True).start()

    def _operation_succeeded(self, result):
        QApplication.restoreOverrideCursor()
        callback, self._success_callback = self._success_callback, None
        if callback:
            callback(result)

    def _operation_failed(self, detail):
        QApplication.restoreOverrideCursor()
        self._success_callback = None
        self.connect_button.setEnabled(True)
        self.install_button.setEnabled(self.device_panel.isEnabled())
        self.status.setText(_("La configuration n’a pas abouti."))
        QMessageBox.critical(self, "Usage Guard", detail)

    def connect_server(self):
        base_url = self.base_url.text().strip()
        username = self.username.text().strip()
        password = self.password.text()
        if not all((base_url, username, password)):
            QMessageBox.warning(
                self, "Usage Guard",
                _("Renseignez le serveur, l’identifiant et le mot de passe."),
            )
            return
        self.password.clear()
        self.set_busy(True, _("Connexion sécurisée au serveur…"))

        def operation():
            api = AdminApi(base_url)
            try:
                api.login(username, password)
                inventory = api.request("/api/v1/admin/users")
            except Exception:
                api.logout()
                raise
            return api, inventory

        self.background(operation, self.connected)

    def connected(self, result):
        if self.api:
            self.api.logout()
        self.api, inventory = result
        self.trackable_users = [
            user for user in inventory.get("users", [])
            if str(user.get("role") or "") == "limited"
        ]
        self.devices = [
            device for device in inventory.get("devices", [])
            if not device.get("revoked_at")
        ]
        if not self.trackable_users:
            self.api.logout()
            self.api = None
            return self._operation_failed(
                _("Aucun utilisateur à associer n’existe. Créez-le d’abord dans la PWA.")
            )
        if not self.windows_accounts:
            self.api.logout()
            self.api = None
            return self._operation_failed(
                _("Aucun compte Windows local ou de domaine existant n’a été détecté.")
            )
        self.identity_table.setRowCount(len(self.trackable_users))
        for row, user in enumerate(self.trackable_users):
            username = str(user["username"])
            role = str(user.get("role") or "user")
            label = QTableWidgetItem(f"{username} ({role})")
            label.setData(Qt.UserRole, username)
            label.setFlags(label.flags() & ~Qt.ItemIsEditable)
            self.identity_table.setItem(row, 0, label)
            choices = QComboBox()
            choices.addItem(_("— Non associé —"), None)
            for account in self.windows_accounts:
                label = self.account_choice_label(account)
                choices.addItem(label, dict(account))
                choices.setItemData(
                    choices.count() - 1,
                    self.account_choice_detail(account),
                    Qt.ToolTipRole,
                )
            self.identity_table.setCellWidget(row, 1, choices)
        self.device_choice.blockSignals(True)
        self.device_choice.clear()
        self.device_choice.addItem(_("Nouvel ordinateur"))
        self.device_choice.addItems([
            _("Réinstaller {name}").format(
                name=str(device.get("label") or device.get("device_id"))
            )
            for device in self.devices
        ])
        if self.existing_device_id:
            matching_index = next((
                index for index, device in enumerate(self.devices, 1)
                if str(device.get("device_id") or "") == self.existing_device_id
            ), -1)
            if matching_index < 1:
                self.api.logout()
                self.api = None
                return self._operation_failed(
                    _("L’appareil déjà installé est absent ou révoqué sur le serveur. "
                      "Aucune nouvelle identité ne sera créée automatiquement.")
                )
            self.device_choice.setCurrentIndex(matching_index)
            self.device_choice.setEnabled(False)
        self.device_choice.blockSignals(False)
        self.device_panel.setEnabled(True)
        # The current network hostname is always the proposed visible name,
        # including during migration. The administrator can still edit it.
        self.display_name.setText(socket.gethostname())
        self.connect_button.setEnabled(True)
        self.install_button.setEnabled(True)
        self.status.setText(_("Connexion réussie. Vérifiez l’affectation avant installation."))

    def refresh_name(self, index):
        if index >= 0:
            # The installer runs on the machine being enrolled: its current
            # Windows network hostname is therefore the safest default for a
            # new installation as well as a reinstallation.
            self.display_name.setText(socket.gethostname())

    def enroll(self):
        if not self.api:
            return
        device_index = self.device_choice.currentIndex()
        name = self.display_name.text().strip()
        if device_index < 0 or not 1 <= len(name) <= 80:
            QMessageBox.warning(
                self, "Usage Guard",
                _("Vérifiez l’utilisateur, le type d’installation et le nom."),
            )
            return
        mappings = []
        for row in range(self.identity_table.rowCount()):
            account = self.identity_table.cellWidget(row, 1).currentData()
            if account is None:
                continue
            username = self.identity_table.item(row, 0).data(Qt.UserRole)
            mappings.append(windows_identity_mapping(account, username))
        try:
            mappings = validate_windows_identity_mappings(mappings)
        except ValueError as error:
            QMessageBox.warning(self, "Usage Guard", str(error))
            return
        administrators = [
            item for item in mappings if item.get("is_windows_admin")
        ]
        if administrators and QMessageBox.question(
            self, _("Compte Windows administrateur"),
            _("Au moins un compte associé est administrateur Windows. Il pourra "
              "altérer ou désinstaller la protection locale. Continuer ?"),
            QMessageBox.Yes | QMessageBox.No, QMessageBox.No,
        ) != QMessageBox.Yes:
            return
        primary_username = mappings[0]["usage_guard_username"]
        selected = self.devices[device_index - 1] if device_index > 0 else None
        self.set_busy(True, _("Création de l’enrôlement à usage unique…"))

        def operation():
            if self.existing_device_id:
                if not selected or str(selected.get("device_id") or "") != self.existing_device_id:
                    raise RuntimeError(_("L’identité de l’appareil existant a changé."))
                device_path = quote(self.existing_device_id, safe="")
                self.api.request(
                    f"/api/v1/admin/devices/{device_path}/windows-identities",
                    {"windows_identities": mappings},
                    "POST",
                )
                if name != str(selected.get("label") or ""):
                    self.api.request(
                        f"/api/v1/admin/devices/{device_path}/rename",
                        {"label": name},
                        "POST",
                    )
                atomic_json(self.output, {
                    "base_url": self.api.base_url,
                    "display_name": name,
                    "device_id": self.existing_device_id,
                    "limited_username": primary_username,
                    "installation_profile": "server",
                    "windows_identities": mappings,
                    "reuse_existing_credentials": True,
                })
                self.api.logout()
                return name, [item["usage_guard_username"] for item in mappings]
            result = self.api.request(
                "/api/v1/admin/device-enrollments",
                {
                    "device_id": str(selected.get("device_id") or "") if selected else "",
                    "username": primary_username,
                    "display_name": name,
                    "windows_identities": mappings,
                },
                "POST",
            )
            enrollment = result.get("enrollment") or {}
            code = str(enrollment.get("code") or "")
            if len(code) < 16:
                raise RuntimeError(_("Code d’enrôlement serveur invalide."))
            atomic_json(self.output, {
                "base_url": self.api.base_url,
                "enrollment_code": code,
                "display_name": name,
                "device_id": str(enrollment.get("device_id") or ""),
                "limited_username": primary_username,
                "installation_profile": "server",
                "windows_identities": mappings,
            })
            self.api.logout()
            return name, [item["usage_guard_username"] for item in mappings]

        self.background(operation, self.enrolled)

    def enrolled(self, result):
        QApplication.restoreOverrideCursor()
        name, usernames = result
        QMessageBox.information(
            self, "Usage Guard",
            _("L’ordinateur « {name} » est rattaché à {users}.\n\n"
              "L’installation du service va maintenant se poursuivre.").format(
                  name=name, users=", ".join(usernames)
              ),
        )
        self.accept()

    def reject(self):
        if self.api:
            threading.Thread(target=self.api.logout, daemon=True).start()
            self.api = None
        super().reject()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--default-base-url", default=DEFAULT_BASE_URL)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--existing-device-id", default="")
    args = parser.parse_args()
    app = QApplication.instance() or QApplication(sys.argv[:1])
    dialog = SetupDialog(
        args.output, args.default_base_url, args.existing_device_id
    )
    result = dialog.exec()
    return 0 if result == QDialog.Accepted and args.output.is_file() else 1


if __name__ == "__main__":
    raise SystemExit(main())
