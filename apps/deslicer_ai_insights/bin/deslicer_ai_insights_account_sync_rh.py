# Custom REST handler for account management.
# Credentials are stored in Splunk's encrypted credential store and read at
# runtime by the modular input supervisor (deslicer_insights_helper.py).
# ruff: noqa: I001 — import_declare_test must precede third-party imports (sys.path side-effect)

import import_declare_test  # noqa: F401 (side-effect: configures sys.path)
from splunktaucclib.rest_handler.admin_external import AdminExternalHandler

_MASKED = "********"


class CustomAccountSyncHandler(AdminExternalHandler):
    """Account handler with empty-token guard.

    Prevents an edit that submits an empty or masked enrollment_token
    from clearing the stored secret.
    """

    def handleEdit(self, confInfo):  # noqa: N802
        field = "enrollment_token"
        if hasattr(self, "callerArgs") and field in self.callerArgs.data:
            vals = self.callerArgs.data[field]
            value = vals[0] if isinstance(vals, list) else vals
            if not value or value == _MASKED:
                del self.callerArgs.data[field]
        return super().handleEdit(confInfo)
