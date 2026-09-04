"""Runtime profiles used to isolate production, development, and tests."""

from __future__ import annotations

import os
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Mapping, MutableSequence


PROFILE_ENVIRONMENT_VARIABLE = "USAGE_GUARD_PROFILE"


@dataclass(frozen=True)
class RuntimeProfile:
    name: str
    data_directory_name: str
    mutex_name: str
    browser_bridge_port: int
    remote_api_port: int
    allow_backend: bool
    allow_autostart_changes: bool

    @property
    def production(self) -> bool:
        return self.name == "production"

    @property
    def decision_pipe_name(self) -> str:
        suffix = "Production" if self.production else self.name.title()
        return rf"\\.\pipe\UsageGuardDecision{suffix}"

    def local_data_directory(
        self,
        environment: Mapping[str, str] | None = None,
    ) -> Path:
        environment = os.environ if environment is None else environment
        base = Path(
            environment.get(
                "LOCALAPPDATA",
                str(Path.home() / "AppData" / "Local"),
            )
        )
        return base / self.data_directory_name


PROFILES = {
    "production": RuntimeProfile(
        name="production",
        data_directory_name="Usage Guard",
        mutex_name="Local\\UsageGuardSingleInstance",
        browser_bridge_port=8765,
        remote_api_port=8766,
        allow_backend=True,
        allow_autostart_changes=True,
    ),
    "dev": RuntimeProfile(
        name="dev",
        data_directory_name="Usage Guard Dev",
        mutex_name="Local\\UsageGuardDevelopmentSingleInstance",
        browser_bridge_port=18765,
        remote_api_port=18766,
        allow_backend=False,
        allow_autostart_changes=False,
    ),
    "test": RuntimeProfile(
        name="test",
        data_directory_name="Usage Guard Test",
        mutex_name="Local\\UsageGuardTestSingleInstance",
        browser_bridge_port=0,
        remote_api_port=0,
        allow_backend=False,
        allow_autostart_changes=False,
    ),
}


_active_profile: RuntimeProfile | None = None


def profile_named(name: str) -> RuntimeProfile:
    normalized = str(name or "production").strip().lower()
    try:
        return PROFILES[normalized]
    except KeyError as error:
        choices = ", ".join(PROFILES)
        raise ValueError(
            f"Profil Usage Guard inconnu : {name!r}. Choix possibles : {choices}."
        ) from error


def resolve_profile(
    arguments: list[str] | tuple[str, ...] | None = None,
    environment: Mapping[str, str] | None = None,
) -> RuntimeProfile:
    arguments = list(sys.argv[1:] if arguments is None else arguments)
    environment = os.environ if environment is None else environment
    # `python -m unittest discover -s tests` imports files as top-level
    # modules, so tests/__init__.py is never executed.  Direct test files have
    # the same property.  Default those genuine runner processes to the test
    # profile unless the caller deliberately supplied an explicit profile.
    running_tests = "unittest" in sys.modules or "pytest" in sys.modules
    selected = str(environment.get(
        PROFILE_ENVIRONMENT_VARIABLE,
        "test" if running_tests else "production",
    ))
    index = 0
    while index < len(arguments):
        argument = arguments[index]
        if argument == "--profile":
            if index + 1 >= len(arguments):
                raise ValueError("L’option --profile exige une valeur.")
            selected = arguments[index + 1]
            index += 2
            continue
        if argument.startswith("--profile="):
            selected = argument.split("=", 1)[1]
        index += 1
    return profile_named(selected)


def configure_from_argv(
    arguments: MutableSequence[str] | None = None,
    environment: Mapping[str, str] | None = None,
) -> RuntimeProfile:
    """Select the active profile and remove our option before Qt sees it."""
    global _active_profile
    arguments = sys.argv if arguments is None else arguments
    selected = resolve_profile(list(arguments)[1:], environment)
    cleaned = [arguments[0]]
    index = 1
    while index < len(arguments):
        argument = arguments[index]
        if argument == "--profile":
            index += 2
            continue
        if argument.startswith("--profile="):
            index += 1
            continue
        cleaned.append(argument)
        index += 1
    arguments[:] = cleaned
    _active_profile = selected
    return selected


def current_profile() -> RuntimeProfile:
    global _active_profile
    if _active_profile is None:
        _active_profile = resolve_profile()
    return _active_profile


def _set_active_profile_for_tests(profile: RuntimeProfile | None) -> None:
    global _active_profile
    _active_profile = profile
