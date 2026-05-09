#!/usr/bin/env python3
"""Convert Loon plugins listed by hub.kelee.one into Surge modules."""

from __future__ import annotations

import argparse
import json
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from scripts.loon2surge import (
    USER_AGENT,
    ConversionError,
    ConvertOptions,
    Converter,
    load_source,
)


DEFAULT_HUB_LIST_URL = "https://hub.kelee.one/list.json"
DEFAULT_REPO_URL = "https://github.com/Oranjekop/Surge-Module.git"
DEFAULT_BRANCH = "main"
SURGE_INSTALL_BASE_URL = "surge:///install-module"
INVALID_FILENAME_RE = re.compile(r'[<>:"/\\|?*\x00-\x1f]+')
WINDOWS_RESERVED_NAMES = {
    "CON",
    "PRN",
    "AUX",
    "NUL",
    *(f"COM{index}" for index in range(1, 10)),
    *(f"LPT{index}" for index in range(1, 10)),
}


@dataclass
class HubPlugin:
    index: int
    name: str
    url: str
    source_url: str
    desc: str = ""
    categories: tuple[str, ...] = ()


def fetch_json(url: str, timeout: int) -> object:
    request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            return json.loads(response.read().decode("utf-8-sig"))
    except (urllib.error.URLError, json.JSONDecodeError) as exc:
        raise ConversionError(f"failed to fetch hub list {url}: {exc}") from exc


def extract_plugin_url(value: str) -> str | None:
    value = value.strip()
    if not value:
        return None

    parsed = urllib.parse.urlparse(value)
    if parsed.scheme in {"http", "https"}:
        return value

    if parsed.scheme != "loon":
        return None

    query = urllib.parse.parse_qs(parsed.query)
    for key in ("plugin", "url"):
        values = query.get(key)
        if values and values[0].strip():
            return values[0].strip()
    return None


def iter_hub_plugins(data: object) -> Iterable[HubPlugin]:
    if not isinstance(data, dict):
        raise ConversionError("hub list root must be an object")
    items = data.get("lists")
    if not isinstance(items, list):
        raise ConversionError("hub list must contain a lists array")

    for position, item in enumerate(items):
        if not isinstance(item, dict):
            continue
        raw_url = str(item.get("url") or "")
        plugin_url = extract_plugin_url(raw_url)
        if not plugin_url:
            continue
        plugin_path = urllib.parse.urlparse(plugin_url).path.lower()
        if not plugin_path.endswith(".lpx"):
            continue
        name = str(item.get("name") or "").strip() or derive_name_from_url(plugin_url)
        desc = str(item.get("desc") or "").strip()
        categories = parse_categories(item.get("category", item.get("tag")))
        index_value = item.get("index")
        index = int(index_value) if isinstance(index_value, int) else position
        yield HubPlugin(
            index=index,
            name=name,
            url=plugin_url,
            source_url=raw_url,
            desc=desc,
            categories=categories,
        )


def parse_categories(value: object) -> tuple[str, ...]:
    if isinstance(value, list):
        items = value
    elif isinstance(value, str):
        items = [value]
    else:
        return ()
    result: list[str] = []
    seen: set[str] = set()
    for item in items:
        category = str(item).strip()
        if not category or category in seen:
            continue
        seen.add(category)
        result.append(category)
    return tuple(result)


def derive_name_from_url(url: str) -> str:
    path = urllib.parse.unquote(urllib.parse.urlparse(url).path)
    stem = Path(path).stem
    return stem or "plugin"


def safe_output_name(plugin: HubPlugin, used_names: set[str]) -> str:
    stem = derive_name_from_url(plugin.url)
    stem = sanitize_filename(stem or plugin.name or f"plugin_{plugin.index}")
    candidate = stem
    suffix = 2
    while candidate.lower() in used_names:
        candidate = f"{stem}_{suffix}"
        suffix += 1
    used_names.add(candidate.lower())
    return f"{candidate}.sgmodule"


def sanitize_filename(value: str) -> str:
    value = INVALID_FILENAME_RE.sub("_", value.strip())
    value = re.sub(r"\s+", "_", value)
    value = re.sub(r"_+", "_", value)
    value = value.strip(" ._") or "plugin"
    if value.upper() in WINDOWS_RESERVED_NAMES:
        value = f"{value}_plugin"
    return value


def convert_hub(args: argparse.Namespace) -> tuple[int, int, int]:
    base_dir = Path.cwd()
    output_dir = Path(args.output_dir)
    if not output_dir.is_absolute():
        output_dir = base_dir / output_dir
    output_dir.mkdir(parents=True, exist_ok=True)

    data = fetch_json(args.hub_list_url, args.timeout)
    plugins = list(iter_hub_plugins(data))
    if args.limit is not None:
        plugins = plugins[: args.limit]
    if not plugins:
        raise ConversionError("no Loon plugin URLs found in hub list")

    manifest: list[dict[str, object]] = []
    failures: list[dict[str, str]] = []
    warning_count = 0
    used_names: set[str] = set()

    for plugin in plugins:
        output_name = safe_output_name(plugin, used_names)
        output_path = output_dir / output_name
        converted = False
        for attempt in range(args.retries + 1):
            try:
                source = load_source(
                    {"name": plugin.name, "url": plugin.url, "timeout": args.timeout},
                    base_dir,
                )
                options = ConvertOptions(
                    module_name=plugin.name,
                    module_desc=plugin.desc or f"Converted from {plugin.url}",
                    module_category=format_categories(plugin.categories),
                    rule_policy=args.rule_policy,
                    strict=args.strict,
                )
                result = Converter(options).convert([source])
                output_path.write_text(result.text, encoding="utf-8", newline="\n")
                warning_count += len(result.warnings)
                download_url = make_download_url(args.repo_url, args.branch, output_name)
                manifest.append(
                    {
                        "index": plugin.index,
                        "name": plugin.name,
                        "desc": plugin.desc,
                        "category": format_categories(plugin.categories),
                        "url": plugin.url,
                        "output": output_name,
                        "download_url": download_url,
                        "install_url": make_install_url(download_url),
                        "sha256": source.sha256,
                        "warnings": result.warnings,
                    }
                )
                print(f"converted: {plugin.name} -> {output_path}")
                converted = True
                break
            except (OSError, ConversionError) as exc:
                if attempt < args.retries:
                    retry_no = attempt + 1
                    print(
                        f"retrying: {plugin.name} ({retry_no}/{args.retries}): {exc}",
                        file=sys.stderr,
                    )
                    time.sleep(args.retry_delay)
                    continue
                failure = {"name": plugin.name, "url": plugin.url, "error": str(exc)}
                failures.append(failure)
                print(f"failed: {plugin.name}: {exc}", file=sys.stderr)
                if args.fail_fast:
                    break
        if not converted and args.fail_fast:
            break

    manifest_path = output_dir / "manifest.json"
    manifest_doc = {
        "hub_list_url": args.hub_list_url,
        "total": len(plugins),
        "converted": len(manifest),
        "failed": len(failures),
        "failures": failures,
        "items": manifest,
    }
    manifest_path.write_text(
        json.dumps(manifest_doc, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
        newline="\n",
    )
    if args.readme:
        readme_path = Path(args.readme)
        if not readme_path.is_absolute():
            readme_path = base_dir / readme_path
        write_readme(readme_path, manifest_doc, args.repo_url, args.branch)

    return len(plugins), len(manifest), len(failures)


def make_download_url(repo_url: str, branch: str, output_name: str) -> str:
    repo_url = normalize_github_repo_url(repo_url)
    quoted_path = urllib.parse.quote(f"Module/{output_name}", safe="/")
    return f"{repo_url}/raw/refs/heads/{urllib.parse.quote(branch, safe='')}/{quoted_path}"


def make_install_url(download_url: str) -> str:
    encoded_url = urllib.parse.quote(download_url, safe="")
    return f"{SURGE_INSTALL_BASE_URL}?url={encoded_url}"


def make_page_base_url(repo_url: str) -> str:
    repo_url = normalize_github_repo_url(repo_url)
    parsed = urllib.parse.urlparse(repo_url)
    parts = [part for part in parsed.path.strip("/").split("/") if part]
    if len(parts) < 2 or parsed.netloc.lower() != "github.com":
        raise ConversionError(f"unsupported GitHub repo URL for Pages: {repo_url}")
    owner, repo = parts[0], parts[1]
    return f"https://{owner.lower()}.github.io/{urllib.parse.quote(repo, safe='')}/"


def make_page_module_url(page_base_url: str, output_name: str) -> str:
    return page_base_url + "?" + urllib.parse.urlencode({"module": output_name})


def display_index(value: object) -> str:
    try:
        return str(int(value) + 1)
    except (TypeError, ValueError):
        return str(value or "")


def format_categories(categories: Iterable[str]) -> str:
    return ", ".join(category.strip() for category in categories if category.strip())


def normalize_github_repo_url(repo_url: str) -> str:
    repo_url = repo_url.rstrip("/")
    if repo_url.endswith(".git"):
        repo_url = repo_url[:-4]
    return repo_url


def write_readme(path: Path, manifest_doc: dict[str, object], repo_url: str, branch: str) -> None:
    repo_url = normalize_github_repo_url(repo_url)
    page_base_url = make_page_base_url(repo_url)
    items = manifest_doc.get("items", [])
    if not isinstance(items, list):
        items = []
    lines: list[str] = [
        "# Surge-Module",
        "",
        "自动从 [Kelee 插件中心](https://hub.kelee.one/) 获取 Loon 插件地址，并转换为 Surge 可用的 `.sgmodule`。",
        "",
        "GitHub Actions 会定时重新拉取 `https://hub.kelee.one/list.json`，解析其中的 `loon://import?plugin=...`，并更新 `Module/` 目录。",
        "",
        "特别感谢 [Kelee 项目](https://github.com/luestr/ProxyResource) 及维护者长期整理、维护和分享这些插件资源，本项目的自动转换流程基于 Kelee 插件中心提供的公开列表与原始 Loon 插件链接。",
        "",
        "## 本地生成",
        "",
        "```powershell",
        "python scripts/convert_hub.py --output-dir Module --readme README.md",
        "```",
        "",
        "## 下载地址",
        "",
        f"- 项目地址：[{repo_url}]({repo_url})",
        f"- 分支：`{branch}`",
        f"- 插件数量：`{manifest_doc.get('converted', 0)}`",
        f"- 失败数量：`{manifest_doc.get('failed', 0)}`",
        f"- GitHub Pages：[{page_base_url}]({page_base_url})",
        "- README 中的源地址会打开模块 raw 文件；如需一键安装，请进入 GitHub Pages 页面操作。",
        "",
        "| 序号 | 插件 | 文件 | 源地址 |",
        "| ---: | --- | --- | --- |",
    ]

    for item in items:
        if not isinstance(item, dict):
            continue
        name = escape_markdown(str(item.get("name") or ""))
        output = str(item.get("output") or "")
        download_url = str(item.get("download_url") or make_download_url(repo_url, branch, output))
        index = display_index(item.get("index", ""))
        lines.append(
            f"| {index} | {name} | {escape_markdown(output)} | [点击打开源地址]({download_url}) |"
        )

    failures = manifest_doc.get("failures", [])
    if isinstance(failures, list) and failures:
        lines.extend(["", "## 转换失败", "", "| 插件 | 地址 | 错误 |", "| --- | --- | --- |"])
        for failure in failures:
            if not isinstance(failure, dict):
                continue
            lines.append(
                "| "
                + escape_markdown(str(failure.get("name") or ""))
                + " | "
                + escape_markdown(str(failure.get("url") or ""))
                + " | "
                + escape_markdown(str(failure.get("error") or ""))
                + " |"
            )

    path.write_text("\n".join(lines).rstrip() + "\n", encoding="utf-8", newline="\n")


def escape_markdown(value: str) -> str:
    return value.replace("|", "\\|")


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--hub-list-url", default=DEFAULT_HUB_LIST_URL)
    parser.add_argument("--output-dir", default="Module")
    parser.add_argument("--readme", default="README.md")
    parser.add_argument("--repo-url", default=DEFAULT_REPO_URL)
    parser.add_argument("--branch", default=DEFAULT_BRANCH)
    parser.add_argument("--timeout", type=int, default=30)
    parser.add_argument(
        "--rule-policy",
        default="DIRECT",
        choices=["DIRECT", "REJECT", "REJECT-TINYGIF"],
    )
    parser.add_argument("--strict", action="store_true")
    parser.add_argument("--fail-fast", action="store_true")
    parser.add_argument("--allow-failures", action="store_true")
    parser.add_argument("--retries", type=int, default=3)
    parser.add_argument("--retry-delay", type=float, default=1.0)
    parser.add_argument("--limit", type=int, help="Convert only the first N entries")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv or sys.argv[1:])
    try:
        total, converted, failed = convert_hub(args)
    except ConversionError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    print(f"hub plugins: {total}, converted: {converted}, failed: {failed}")
    if failed and not args.allow_failures:
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
