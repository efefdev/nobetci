import importlib.util
import os
import unittest
from unittest import mock

from tests.helpers import TempDirMixin

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
spec = importlib.util.spec_from_file_location("installer", os.path.join(ROOT, "install.py"))
installer = importlib.util.module_from_spec(spec)
spec.loader.exec_module(installer)


class InstallConfigTest(TempDirMixin, unittest.TestCase):
    def setUp(self):
        super().setUp()
        self.dir = os.path.join(self.tmp, "etc")
        for name, value in (("CONFIG_DIR", self.dir), ("CONFIG", os.path.join(self.dir, "config.env")),
                            ("LEGACY_CONFIG", os.path.join(self.tmp, "soc.env"))):
            p = mock.patch.object(installer, name, value)
            p.start()
            self.addCleanup(p.stop)
        p = mock.patch("os.chown")
        p.start()
        self.addCleanup(p.stop)

    def test_existing_config_is_kept_and_extended(self):
        os.makedirs(self.dir)
        with open(installer.CONFIG, "w") as f:
            f.write('TELEGRAM_BOT_TOKEN="real"\nGROQ_API_KEY="gsk"\n')
        installer.install_config()
        with open(installer.CONFIG) as f:
            text = f.read()
        self.assertTrue(text.startswith('TELEGRAM_BOT_TOKEN="real"\nGROQ_API_KEY="gsk"\n'))
        self.assertIn("TRAP_PATHS=", text)
        self.assertNotIn("AI_API_KEY=", text)  # the 1.x GROQ_API_KEY already covers it
        self.assertEqual(os.stat(installer.CONFIG).st_mode & 0o777, 0o600)
        installer.install_config()
        with open(installer.CONFIG) as f:
            self.assertEqual(f.read(), text)  # idempotent

    def test_legacy_config_is_migrated(self):
        with open(installer.LEGACY_CONFIG, "w") as f:
            f.write('TELEGRAM_BOT_TOKEN="old"\n')
        installer.install_config()
        with open(installer.CONFIG) as f:
            self.assertIn('TELEGRAM_BOT_TOKEN="old"', f.read())
        self.assertEqual(os.stat(self.dir).st_mode & 0o777, 0o700)


if __name__ == "__main__":
    unittest.main()
