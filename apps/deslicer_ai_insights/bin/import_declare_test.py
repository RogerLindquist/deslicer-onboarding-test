import os
import re
import sys
from os.path import dirname

# Pre-load Splunk's bundled OpenSSL so _ssl.cpython can resolve RAND_egd.
# Required on containers where the system OpenSSL 3.x dropped the symbol.
_splunk_lib = os.path.join(os.environ.get("SPLUNK_HOME", "/opt/splunk"), "lib")
if os.path.isdir(_splunk_lib):
    try:
        import ctypes

        ctypes.CDLL(
            os.path.join(_splunk_lib, "libcrypto.so.3"), mode=ctypes.RTLD_GLOBAL
        )
        ctypes.CDLL(os.path.join(_splunk_lib, "libssl.so.3"), mode=ctypes.RTLD_GLOBAL)
    except OSError:
        pass

ta_name = "deslicer_ai_insights"
pattern = re.compile(r"[\\/]etc[\\/]apps[\\/][^\\/]+[\\/]bin[\\/]?$")
new_paths = [path for path in sys.path if not pattern.search(path) or ta_name in path]
new_paths.insert(0, os.path.join(dirname(dirname(__file__)), "lib"))
new_paths.insert(0, os.path.sep.join([os.path.dirname(__file__), ta_name]))
sys.path = new_paths
