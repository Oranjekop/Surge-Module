import unittest
from pathlib import Path
from unittest.mock import patch

from scripts.loon2surge import ConvertOptions, Converter, Source, USER_AGENT, load_source


SAMPLE = """#!name=Example
#!desc=Example plugin
#!tag=去广告
#!arguments=foo:"bar",flag:true

[Argument]
host = input,api.example.com, tag=host, desc=host

[General]
skip-proxy = example.com

[Rule]
HOST,ads.example.com,REJECT
IP6-CIDR,2001:db8::/32,DIRECT
DOMAIN-SUFFIX,example.org,Proxy

[Rewrite]
^https?://ads\\.example\\.com reject
^http://old\\.example\\.com/(.*) http://new.example.com/$1 302
^http://legacy\\.example\\.com url 302 https://new.example.com
http-request ^https://api\\.example\\.com header-add X-Test 1
^https://api\\.example\\.com/header response-header-add X-Res v1 X-Other v2
^https://api\\.example\\.com/del header-del X-A X-B
^https://api\\.example\\.com/body response-body-json-del ads
http-response ^https://api\\.example\\.com/prefixed response-body-json-del foo bar
^https://api\\.example\\.com/jq response-body-json-jq '.items |= map(del(.ad))'
^https://api\\.example\\.com/alias url jsonjq-response-body '.data |= del(.ad)'
^https://api\\.example\\.com/mock mock-response-body data-type=json data="{}" status-code=200
^https://api\\.example\\.com/empty reject-dict
^https://api\\.example\\.com/array url reject-array
^https://api\\.example\\.com/img - reject-img

[Script]
http-response ^https://api\\.example\\.com/v1 script-path=https://example.com/patch.js, requires-body=true, tag=patch
http-request ^https?:\\/\\/script\\.hub\\/file\\/.+type=loon-plugin script-path=https://example.com/hub.js, tag=hub
cron "0 8 * * *" script-path=https://example.com/daily.js, tag=daily

[MITM]
hostname = api.example.com
"""


class LoonToSurgeTests(unittest.TestCase):
    def test_convert_common_sections(self):
        source = Source("sample", SAMPLE, "memory", "sha")
        result = Converter(ConvertOptions(module_name="Merged", rule_policy="DIRECT")).convert([source])

        self.assertIn("#!name=Example", result.text)
        self.assertIn("#!desc=Example plugin", result.text)
        self.assertIn("#!category=去广告", result.text)
        self.assertIn('#!arguments=foo:"bar",flag:true,host:api.example.com', result.text)
        self.assertIn("[General]\nskip-proxy = %APPEND% example.com", result.text)
        self.assertIn("DOMAIN,ads.example.com,REJECT", result.text)
        self.assertIn("IP-CIDR6,2001:db8::/32,DIRECT", result.text)
        self.assertIn("DOMAIN-SUFFIX,example.org,DIRECT", result.text)
        self.assertIn("^https?://ads\\.example\\.com - reject", result.text)
        self.assertIn("^http://legacy\\.example\\.com https://new.example.com 302", result.text)
        self.assertIn("http-request ^https://api\\.example\\.com header-add X-Test 1", result.text)
        self.assertIn("http-response ^https://api\\.example\\.com/header header-add 'X-Res' 'v1'", result.text)
        self.assertIn("http-response ^https://api\\.example\\.com/header header-add 'X-Other' 'v2'", result.text)
        self.assertIn("http-request ^https://api\\.example\\.com/del header-del 'X-A'", result.text)
        self.assertIn("http-request ^https://api\\.example\\.com/del header-del 'X-B'", result.text)
        self.assertIn("#!requirement=CORE_VERSION>=20", result.text)
        self.assertIn("[Body Rewrite]", result.text)
        self.assertIn("http-response-jq ^https://api\\.example\\.com/body 'delpaths([[\"ads\"]])'", result.text)
        self.assertIn("http-response-jq ^https://api\\.example\\.com/prefixed 'delpaths([[\"foo\"],[\"bar\"]])'", result.text)
        self.assertIn("http-response-jq ^https://api\\.example\\.com/jq '.items |= map(del(.ad))'", result.text)
        self.assertIn("http-response-jq ^https://api\\.example\\.com/alias '.data |= del(.ad)'", result.text)
        self.assertIn("[Map Local]", result.text)
        self.assertIn(
            '^https://api\\.example\\.com/mock data-type=text data="{}" status-code=200 header="Content-Type:application/json"',
            result.text,
        )
        self.assertIn(
            '^https://api\\.example\\.com/empty data-type=text data="{}" status-code=200 header="Content-Type:application/json"',
            result.text,
        )
        self.assertIn(
            '^https://api\\.example\\.com/array data-type=text data="[]" status-code=200',
            result.text,
        )
        self.assertIn(
            "^https://api\\.example\\.com/img data-type=tiny-gif status-code=200",
            result.text,
        )
        self.assertIn(
            "patch = type=http-response,pattern=^https://api\\.example\\.com/v1,script-path=https://example.com/patch.js,requires-body=true",
            result.text,
        )
        self.assertIn(
            "hub = type=http-request,pattern=^https?:\\/\\/script\\.hub\\/file\\/.+type=loon-plugin,script-path=https://example.com/hub.js",
            result.text,
        )
        self.assertIn(
            'daily = type=cron,cronexp="0 8 * * *",script-path=https://example.com/daily.js',
            result.text,
        )
        self.assertIn("[MITM]\nhostname = %APPEND% api.example.com", result.text)
        self.assertTrue(result.warnings)

    def test_merge_dedupes_duplicate_lines(self):
        source = Source("a", SAMPLE, "memory", "sha")
        result = Converter(ConvertOptions(module_name="Merged")).convert([source, source])

        self.assertEqual(result.text.count("DOMAIN,ads.example.com,REJECT"), 1)
        self.assertIn("patch_2 = ", result.text)

    def test_module_name_falls_back_to_option_without_loon_name(self):
        source = Source("unnamed", "[Rule]\nDOMAIN,example.com,REJECT\n", "memory", "sha")
        result = Converter(ConvertOptions(module_name="Fallback")).convert([source])

        self.assertIn("#!name=Fallback", result.text)
        self.assertIn("#!desc=Converted from Loon plugins for Surge.", result.text)
        self.assertIn("# Converted sources: unnamed", result.text)

    def test_remote_sources_use_scripthub_user_agent(self):
        captured = {}

        class FakeResponse:
            def __enter__(self):
                return self

            def __exit__(self, exc_type, exc, tb):
                return False

            def read(self):
                return b"#!name=Remote\n"

        def fake_urlopen(request, timeout):
            captured["user_agent"] = request.get_header("User-agent")
            captured["timeout"] = timeout
            return FakeResponse()

        with patch("scripts.loon2surge.urllib.request.urlopen", fake_urlopen):
            source = load_source(
                {"name": "remote", "url": "https://example.com/remote.plugin"},
                Path("."),
            )

        self.assertEqual(USER_AGENT, "script-hub/1.0.0")
        self.assertEqual(captured["user_agent"], "script-hub/1.0.0")
        self.assertEqual(captured["timeout"], 30)
        self.assertEqual(source.text, "#!name=Remote\n")


if __name__ == "__main__":
    unittest.main()
