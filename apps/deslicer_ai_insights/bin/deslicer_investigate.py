# encoding = utf-8
# Always put this line at the beginning of this file
import import_declare_test

import os
import sys

from splunktaucclib.alert_actions_base import ModularAlertBase
import deslicer_investigate_logic

class AlertActionWorkerdeslicer_investigate(ModularAlertBase):

    def __init__(self, ta_name, alert_name):
        super(AlertActionWorkerdeslicer_investigate, self).__init__(ta_name, alert_name)

    def validate_params(self):


        if not self.get_param("endpoint_url"):
            self.log_error('endpoint_url is a mandatory parameter, but its value is None.')
            return False

        if not self.get_param("api_token"):
            self.log_error('api_token is a mandatory parameter, but its value is None.')
            return False
        return True

    def process_event(self, *args, **kwargs):
        status = 0
        try:
            if not self.validate_params():
                return 3
            status = deslicer_investigate_logic.process_event(self, *args, **kwargs)
        except Exception as e:
            msg = "Unexpected error: {}."
            if str(e):
                self.log_error(msg.format(str(e)))
            else:
                import traceback
                self.log_error(msg.format(traceback.format_exc()))
            return 5
        return status

if __name__ == "__main__":
    exitcode = AlertActionWorkerdeslicer_investigate("deslicer_ai_insights", "deslicer_investigate").run(sys.argv)
    sys.exit(exitcode)
