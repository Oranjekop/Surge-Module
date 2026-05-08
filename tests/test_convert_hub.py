import unittest

from scripts.convert_hub import (
    HubPlugin,
    display_index,
    extract_plugin_url,
    iter_hub_plugins,
    make_download_url,
    make_install_url,
    make_page_base_url,
    make_page_copy_url,
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
                {
                    "name": "Demo",
                    "desc": "Demo desc",
                    "tag": ["去广告", "依赖"],
                    "url": "loon://import?plugin=https://kelee.one/Tool/Loon/Lpx/Demo.lpx",
                    "index": 5,
                },
                {"name": "Bad", "url": "loon://open?url=https://example.com"},
            ]
        }

        plugins = list(iter_hub_plugins(data))

        self.assertEqual(len(plugins), 1)
        self.assertEqual(plugins[0].name, "Demo")
        self.assertEqual(plugins[0].desc, "Demo desc")
        self.assertEqual(plugins[0].categories, ("去广告", "依赖"))
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
            make_download_url("https://github.com/Oranjekop/Surge-Module.git", "main", "Demo File.sgmodule"),
            "https://github.com/Oranjekop/Surge-Module/raw/refs/heads/main/Module/Demo%20File.sgmodule",
        )

    def test_make_install_url_uses_surge_scheme(self):
        download_url = make_download_url(
            "https://github.com/Oranjekop/Surge-Module.git",
            "main",
            "Demo File.sgmodule",
        )

        self.assertEqual(
            make_install_url(download_url),
            "surge:///install-module?url=https%3A%2F%2Fgithub.com%2FOranjekop%2FSurge-Module%2Fraw%2Frefs%2Fheads%2Fmain%2FModule%2FDemo%2520File.sgmodule",
        )

    def test_make_page_urls(self):
        page_base_url = make_page_base_url("https://github.com/Oranjekop/Surge-Module.git")

        self.assertEqual(page_base_url, "https://oranjekop.github.io/Surge-Module/")
        self.assertEqual(
            make_page_copy_url(page_base_url, "Demo File.sgmodule"),
            "https://oranjekop.github.io/Surge-Module/?module=Demo+File.sgmodule&copy=1",
        )

    def test_display_index_is_one_based(self):
        self.assertEqual(display_index(0), "1")
        self.assertEqual(display_index("9"), "10")
        self.assertEqual(display_index(""), "")


if __name__ == "__main__":
    unittest.main()
