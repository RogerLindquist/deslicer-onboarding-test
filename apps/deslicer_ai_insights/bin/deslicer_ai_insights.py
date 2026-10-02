import import_declare_test

import sys

from splunklib import modularinput as smi
from deslicer_ai_insights_helper import stream_events, validate_input


class DESLICER_AI_INSIGHTS(smi.Script):
    def __init__(self):
        super(DESLICER_AI_INSIGHTS, self).__init__()

    def get_scheme(self):
        scheme = smi.Scheme('deslicer_ai_insights')
        scheme.description = 'Deslicer AI Insights Collector'
        scheme.use_external_validation = True
        scheme.streaming_mode_xml = True
        scheme.use_single_instance = False

        scheme.add_argument(
            smi.Argument(
                'name',
                title='Name',
                description='Name',
                required_on_create=True
            )
        )
        scheme.add_argument(
            smi.Argument(
                'account',
                required_on_create=True,
            )
        )
        scheme.add_argument(
            smi.Argument(
                'log_level',
                required_on_create=False,
            )
        )
        scheme.add_argument(
            smi.Argument(
                'exclude_apps',
                required_on_create=False,
            )
        )
        scheme.add_argument(
            smi.Argument(
                'exclude_path_glob',
                required_on_create=False,
            )
        )
        return scheme

    def validate_input(self, definition: smi.ValidationDefinition):
        return validate_input(definition)

    def stream_events(self, inputs: smi.InputDefinition, ew: smi.EventWriter):
        return stream_events(inputs, ew)


if __name__ == '__main__':
    exit_code = DESLICER_AI_INSIGHTS().run(sys.argv)
    sys.exit(exit_code)