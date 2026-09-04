"""Global safety boundary for the Usage Guard test suite.

This module is imported before every ``tests.test_*`` module by unittest and
pytest.  Selecting the isolated runtime profile here is deliberately done
before application modules can cache paths, ports or backend settings.
"""

from __future__ import annotations

import os


# A test command must never inherit the implicit production default from the
# developer workstation.  Individual tests remain free to exercise another
# profile explicitly through runtime_profile's test helper or a subprocess
# environment, without exposing the rest of the suite to production state.
os.environ["USAGE_GUARD_PROFILE"] = "test"
