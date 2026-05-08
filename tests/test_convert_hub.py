import unittest

from scripts.convert_hub import (
    HubPlugin,
    extract_plugin_url,
    iter_hub_plugins,
    make_download_url,
    safe_output_name,
    sanitize_filename,
)


class ConvertHubTests(unittest.TestCase):
    def test_extracts_loon_import_plugin_url(self):
        self.assertEqual(
            extract_plugin_url(
                "loon://import?plugin=https%3A%2F%2Fkelee.one%2FTool%2FLoon%2FLpx%2FDemo.lpx"
            ),
            "https://kelee.one/Tool/Loon/Lpx/Demo.lpx",
        )

    def test_iter_hub_plugins_skips_non_plugin_items(self):
        data = {
            "lists": [
                {"name": "Demo", "url": "loon://import?plugin=https://kelee.one/Tool/Loon/Lpx/Demo.lpx", "index": 5},
                {"name": "Bad", "url": "loon://open?url=https://example.com"},
            ]
        }

        plugins = list(iter_hub_plugins(data))

        self.assertEqual(len(plugins), 1)
        self.assertEqual(plugins[0].name, "Demo")
        self.assertEqual(plugins[0].index, 5)
        self.assertEqual(plugins[0].url, "https://kelee.one/Tool/Loon/Lpx/Demo.lpx")

    def test_safe_output_name_uses_url_stem_and_dedupes(self):
        used = set()
        first = HubPlugin(0, "Demo A", "https://kelee.one/Tool/Loon/Lpx/Demo.lpx", "")
        second = HubPlugin(1, "Demo B", "https://kelee.one/Tool/Loon/Lpx/Demo.lpx", "")

        self.assertEqual(safe_output_name(first, used), "Demo.sgmodule")
        self.assertEqual(safe_output_name(second, used), "Demo_2.sgmodule")

    def test_sanitize_filename_handles_windows_reserved_names(self):
        self.assertEqual(sanitize_filename('CON: demo'), "CON_demo")
        self.assertEqual(sanitize_filename("CON"), "CON_plugin")

    def test_make_download_url_uses_github_raw_path(self):
        self.assertEqual(
            make_download_url("https://github.com/Oranjekop/Module.git", "main", "Demo File.sgmodule"),
            "https://github.com/Oranjekop/Module/raw/refs/heads/main/Module/Demo%20File.sgmodule",
        )


if __name__ == "__main__":
    unittest.main()
