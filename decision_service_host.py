"""Source launcher for the Usage Guard decision-service prototype."""

from runtime_profile import configure_from_argv


profile = configure_from_argv()

from decision_service import DecisionServiceHost, load_or_create_authkey


def main() -> int:
    authkey = load_or_create_authkey(profile.local_data_directory())
    state_path = profile.local_data_directory() / "decision-service-controls.json"
    DecisionServiceHost(
        profile.decision_pipe_name, authkey, state_path=state_path
    ).serve_forever()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
