import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from reportcard.config import Config  # noqa: E402


@pytest.fixture
def cfg(tmp_path):
    """A config file in a temp folder; tests add sections with cfg.write(...)."""
    path = tmp_path / "config.ini"
    path.write_text("[report]\ndata_dir = %s\nserver_name = Test server\n" % (tmp_path / "data"))

    class C:
        def write(self, text):
            with open(path, "a") as fh:
                fh.write("\n" + text + "\n")
            return Config(str(path))

    c = C()
    c.path = path
    c.data = tmp_path / "data"
    return c
