# Testing Usage Guard with the development profile

The development profile can run alongside an installed production client. It
uses a separate mutex, ports, and data directory. It does not connect to the
configured production backend or change Windows autostart settings.

## Prepare the development extension

From the repository root:

```powershell
python tools\build_dev_extension.py
```

In Brave, open `brave://extensions`, enable **Developer mode**, select **Load
unpacked**, and choose:

```text
build\browser-extension-dev
```

It appears as **Usage Guard DEV — Browser Bridge** and contacts only
`127.0.0.1:18765`. The production extension continues to use port `8765`. Keep
only the extension corresponding to the instance under test enabled when you
need unambiguous results.

## Start the development instance

```powershell
python main.py --profile dev
```

Expected indicators:

- the window label and notification-area tooltip contain `DEV`;
- the local PWA is available at `http://127.0.0.1:18766` and displays its core,
  service, and authority status;
- data is written under `%LOCALAPPDATA%\Usage Guard Dev`;
- the production installation keeps ports `8765` and `8766`.

Closing the development instance is enough to return to production operation.
No production build, installation, or data migration is required.

## Automated checks

From the repository root:

```powershell
python -B -m unittest discover -s tests
```

The suite checks, among other boundaries, that a local API command cannot
impersonate the backend or modify a backend-managed rule in the development
profile. It also verifies that the decision process preserves protected-rule
ownership after reloading its registry. Locally created development rules
remain locally manageable.

## Install the development Windows service

This optional step requires administrator elevation. Close the development
instance, then run from an elevated PowerShell window:

```powershell
& .\tools\install_dev_service.ps1
```

Start `python main.py --profile dev` again. The status should now report the
SCM-hosted development service. Closing the desktop process must not stop the
`UsageGuardDecisionDev` service.

To return to the child-process development service without deleting its
protected test data:

```powershell
& .\tools\uninstall_dev_service.ps1
```
