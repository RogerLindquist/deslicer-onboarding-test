
import import_declare_test

from splunktaucclib.rest_handler.endpoint import (
    field,
    validator,
    RestModel,
    SingleModel,
)
from splunktaucclib.rest_handler import admin_external, util
from deslicer_ai_insights_account_sync_rh import CustomAccountSyncHandler
import logging


util.remove_http_proxy_env_vars()


special_fields = [
    field.RestField(
        'name',
        required=True,
        encrypted=False,
        default=None,
        validator=validator.AllOf(
            validator.Pattern(
                regex=r"""^[a-zA-Z]\w*$""", 
            ), 
            validator.String(
                max_len=100, 
                min_len=1, 
            )
        )
    )
]

fields = [
    field.RestField(
        'enrollment_token',
        required=False,
        encrypted=True,
        default=None,
        validator=validator.String(
            max_len=2048, 
            min_len=10, 
        )
    ), 
    field.RestField(
        'observer_api_url',
        required=True,
        encrypted=False,
        default='https://dap-eu-s1t8vn.deslicer.ai',
        validator=validator.Pattern(
            regex=r"""^https://.+""", 
        )
    )
]
model = RestModel(fields, name=None, special_fields=special_fields)


endpoint = SingleModel(
    'deslicer_ai_insights_account',
    model,
    config_name='account',
    need_reload=False,
)


if __name__ == '__main__':
    logging.getLogger().addHandler(logging.NullHandler())
    admin_external.handle(
        endpoint,
        handler=CustomAccountSyncHandler,
    )
