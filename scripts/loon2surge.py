#!/usr/bin/env python3
"""Convert Loon plugins to Surge modules.

The converter is intentionally dependency-free so it can run locally and in
GitHub Actions with only Python installed.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable


USER_AGENT = "script-hub/1.0.0"

SECTION_ORDER = (
    "General",
    "Rule",
    "URL Rewrite",
    "Header Rewrite",
    "Body Rewrite",
    "Map Local",
    "Script",
    "Host",
    "MITM",
)

SECTION_ALIASES = {
    "general": "general",
    "argument": "argument",
    "arguments": "argument",
    "rule": "rule",
    "rules": "rule",
    "rewrite": "rewrite",
    "url rewrite": "url-rewrite",
    "header rewrite": "header-rewrite",
    "body rewrite": "body-rewrite",
    "map local": "map-local",
    "script": "script",
    "mitm": "mitm",
    "host": "host",
}

SCRIPT_PARAM_KEYS = (
    "script-path",
    "pattern",
    "cronexp",
    "cron",
    "timeout",
    "argument",
    "script-update-interval",
    "requires-body",
    "max-size",
    "ability",
    "binary-body-mode",
    "cronexpr",
    "wake-system",
    "enabled",
    "enable",
    "engine",
    "tag",
    "type",
    "img-url",
    "debug",
    "event-name",
    "desc",
)

SCRIPT_PARAM_START_RE = re.compile(
    r"(?<![A-Za-z0-9_-])("
    + "|".join(re.escape(key) for key in SCRIPT_PARAM_KEYS)
    + r")\s*=",
    re.IGNORECASE,
)

INTERNAL_POLICIES = {"DIRECT", "REJECT", "REJECT-TINYGIF"}

RULE_TYPE_MAP = {
    "HOST": "DOMAIN",
    "HOST-SUFFIX": "DOMAIN-SUFFIX",
    "HOST-KEYWORD": "DOMAIN-KEYWORD",
    "HOST-WILDCARD": "DOMAIN-WILDCARD",
    "IP6-CIDR": "IP-CIDR6",
    "DST-PORT": "DEST-PORT",
    "PROCESS": "PROCESS-NAME",
}

REJECT_POLICY_MAP = {
    "REJECT-IMG": "REJECT-TINYGIF",
    "REJECT-TINYGIF": "REJECT-TINYGIF",
    "REJECT-DICT": "REJECT",
    "REJECT-ARRAY": "REJECT",
    "REJECT-DROP": "REJECT",
    "REJECT-NO-DROP": "REJECT",
    "REJECT-200": "REJECT",
    "REJECT-VIDEO": "REJECT",
}

REJECT_MAP_LOCAL_ACTIONS = {
    "reject-dict",
    "reject-array",
    "reject-200",
    "reject-img",
    "reject-tinygif",
    "reject-video",
}

GENERAL_APPEND_KEYS = {
    "skip-proxy",
    "always-real-ip",
    "real-ip",
    "force-http-engine-hosts",
}

MITM_APPEND_KEYS = {
    "hostname",
    "skip-server-cert-verify",
    "tcp-connection",
}


@dataclass
class Source:
    name: str
    text: str
    origin: str
    sha256: str


@dataclass
class ParsedPlugin:
    name: str
    origin: str
    metadata: dict[str, str] = field(default_factory=dict)
    metadata_lines: list[str] = field(default_factory=list)
    sections: dict[str, list[str]] = field(default_factory=dict)


@dataclass
class ConvertOptions:
    module_name: str = "Converted Loon Plugins"
    module_desc: str = "Converted from Loon plugins for Surge."
    rule_policy: str = "DIRECT"
    strict: bool = False


@dataclass
class ConvertOutput:
    text: str
    warnings: list[str]
    sources: list[Source]


class ConversionError(RuntimeError):
    pass


class Converter:
    def __init__(self, options: ConvertOptions) -> None:
        self.options = options
        self.warnings: list[str] = []
        self.used_script_names: set[str] = set()

    def warn(self, source: str, message: str) -> None:
        item = f"{source}: {message}"
        if self.options.strict:
            raise ConversionError(item)
        self.warnings.append(item)

    def convert(self, sources: list[Source]) -> ConvertOutput:
        parsed = [parse_plugin(source) for source in sources]
        out: dict[str, list[str]] = {section: [] for section in SECTION_ORDER}
        arg_lines: list[str] = []
        source_names: list[str] = []
        module_names: list[str] = []

        for plugin in parsed:
            metadata_name = plugin.metadata.get("name")
            if metadata_name:
                module_names.append(metadata_name)
            source_names.append(metadata_name or plugin.name)

            for line in plugin.metadata_lines:
                if re.match(r"^#!\s*arguments\s*=", line, re.IGNORECASE):
                    arg_lines.append(line)

            for line in plugin.sections.get("argument", []):
                cleaned = clean_line(line)
                if cleaned:
                    arg_lines.append(cleaned)

            for line in plugin.sections.get("general", []):
                self.convert_general_line(plugin, line, out)

            for line in plugin.sections.get("rule", []):
                converted = self.convert_rule_line(plugin, line)
                if converted:
                    out["Rule"].append(converted)

            for line in plugin.sections.get("rewrite", []):
                self.convert_rewrite_line(plugin, line, out)

            for line in plugin.sections.get("url-rewrite", []):
                self.convert_rewrite_line(plugin, line, out)

            for line in plugin.sections.get("header-rewrite", []):
                out["Header Rewrite"].extend(self.convert_header_rewrite_lines(plugin, line))

            for line in plugin.sections.get("body-rewrite", []):
                converted = self.convert_body_rewrite_line(plugin, line)
                if converted:
                    out["Body Rewrite"].append(converted)

            for line in plugin.sections.get("map-local", []):
                converted = self.convert_map_local_line(plugin, line)
                if converted:
                    out["Map Local"].append(converted)

            for line in plugin.sections.get("script", []):
                converted = self.convert_script_line(plugin, line)
                if converted:
                    out["Script"].append(converted)

            for line in plugin.sections.get("host", []):
                converted = clean_line(line)
                if converted:
                    out["Host"].append(converted)

            for line in plugin.sections.get("mitm", []):
                self.convert_mitm_line(plugin, line, out)

        for section_name in out:
            out[section_name] = dedupe(out[section_name])

        return ConvertOutput(
            text=self.render_module(out, arg_lines, source_names, module_names),
            warnings=self.warnings,
            sources=sources,
        )

    def render_module(
        self,
        sections: dict[str, list[str]],
        arg_lines: list[str],
        source_names: list[str],
        module_names: list[str],
    ) -> str:
        source_names = dedupe_names(source_names)
        module_names = dedupe_names(module_names)
        module_name = " + ".join(module_names) if module_names else self.options.module_name
        lines: list[str] = [
            f"#!name={module_name}",
            f"#!desc={self.options.module_desc}",
        ]
        if sections.get("Body Rewrite") or sections.get("Map Local"):
            lines.append("#!requirement=CORE_VERSION>=20")

        argument_text = build_arguments(arg_lines)
        if argument_text:
            lines.append(f"#!arguments={argument_text}")

        if source_names:
            lines.append(f"# Converted sources: {', '.join(source_names)}")
        lines.append("# Generated by scripts/loon2surge.py")

        for section in SECTION_ORDER:
            items = sections[section]
            if not items:
                continue
            lines.append("")
            lines.append(f"[{section}]")
            lines.extend(items)

        return "\n".join(lines).rstrip() + "\n"

    def convert_general_line(
        self, plugin: ParsedPlugin, raw_line: str, out: dict[str, list[str]]
    ) -> None:
        line = clean_line(raw_line)
        if not line:
            return
        parsed = parse_key_value(line)
        if not parsed:
            self.warn(plugin.name, f"ignored unsupported [General] line: {line}")
            return
        key, value = parsed
        lower = key.lower()
        if lower in MITM_APPEND_KEYS:
            out["MITM"].append(format_append_line(lower, value))
        elif lower in GENERAL_APPEND_KEYS:
            out["General"].append(format_append_line(lower, value))
        else:
            self.warn(plugin.name, f"ignored unsupported [General] key: {key}")

    def convert_mitm_line(
        self, plugin: ParsedPlugin, raw_line: str, out: dict[str, list[str]]
    ) -> None:
        line = clean_line(raw_line)
        if not line:
            return
        parsed = parse_key_value(line)
        if not parsed:
            self.warn(plugin.name, f"ignored unsupported [MITM] line: {line}")
            return
        key, value = parsed
        lower = key.lower()
        if lower in MITM_APPEND_KEYS:
            out["MITM"].append(format_append_line(lower, value))
        else:
            self.warn(plugin.name, f"ignored unsupported [MITM] key: {key}")

    def convert_rule_line(self, plugin: ParsedPlugin, raw_line: str) -> str | None:
        line = clean_line(raw_line)
        if not line:
            return None

        parts = split_top_level(line, ",")
        if len(parts) == 1:
            value = parts[0].strip()
            if not value:
                return None
            return f"DOMAIN,{value},{self.options.rule_policy}"

        rule_type = parts[0].strip().upper()
        if rule_type == "FINAL":
            self.warn(plugin.name, "ignored FINAL rule because Surge modules insert rules at top")
            return None

        rule_type = RULE_TYPE_MAP.get(rule_type, rule_type)
        if len(parts) < 3:
            return ",".join([rule_type, *parts[1:], self.options.rule_policy])

        policy = normalize_policy(parts[2].strip())
        if policy not in INTERNAL_POLICIES:
            self.warn(
                plugin.name,
                f"replaced unsupported module policy {parts[2].strip()} with {self.options.rule_policy}",
            )
            policy = self.options.rule_policy

        return ",".join([rule_type, parts[1].strip(), policy, *[p.strip() for p in parts[3:]]])

    def convert_rewrite_line(
        self, plugin: ParsedPlugin, raw_line: str, out: dict[str, list[str]]
    ) -> None:
        line = clean_line(raw_line)
        if not line:
            return
        if is_header_rewrite_line(line):
            out["Header Rewrite"].extend(self.convert_header_rewrite_lines(plugin, line))
            return
        converted_map_local = self.convert_reject_map_local_line(line)
        if converted_map_local:
            out["Map Local"].append(converted_map_local)
            return
        if is_map_local_line(line):
            converted = self.convert_map_local_line(plugin, line)
            if converted:
                out["Map Local"].append(converted)
            return
        if is_body_rewrite_line(line):
            converted = self.convert_body_rewrite_line(plugin, line)
            if converted:
                out["Body Rewrite"].append(converted)
            return

        converted = self.convert_url_rewrite_line(plugin, line)
        if converted:
            out["URL Rewrite"].append(converted)

    def convert_reject_map_local_line(self, line: str) -> str | None:
        tokens = split_shellish(line)
        if len(tokens) < 2:
            return None
        pattern = tokens[0]
        action = normalize_token(tokens[-1])
        if action not in REJECT_MAP_LOCAL_ACTIONS:
            return None
        return reject_action_to_map_local(pattern, action)

    def convert_body_rewrite_line(self, plugin: ParsedPlugin, raw_line: str) -> str | None:
        line = clean_line(raw_line)
        if not line:
            return None
        tokens = split_shellish(line)
        if len(tokens) < 2:
            self.warn(plugin.name, f"ignored unsupported body rewrite line: {line}")
            return None

        first = normalize_token(tokens[0])
        if first in {"http-request-jq", "http-response-jq"}:
            return line

        if first in {"http-request", "http-response"}:
            if len(tokens) < 3:
                return line
            pattern = tokens[1]
            action = normalize_token(tokens[2])
            args = tokens[3:]
            body_type = body_action_type(action)
            if not body_type:
                return line
        else:
            pattern = tokens[0]
            action = normalize_token(tokens[1])
            args = tokens[2:]
            body_type = body_action_type(action)

        if action == "url" and len(tokens) >= 4:
            alias = normalize_token(tokens[2])
            if alias in {"jsonjq-request-body", "jsonjq-response-body"}:
                expression = join_shellish(tokens[3:])
                if not expression:
                    self.warn(plugin.name, f"ignored body jq rule without expression: {line}")
                    return None
                body_type = "http-request" if "request" in alias else "http-response"
                return f"{body_type}-jq {pattern} {quote_jq(expression)}"

        if not body_type:
            self.warn(plugin.name, f"ignored unsupported body rewrite action {tokens[1]}: {line}")
            return None

        if action.endswith("-body-json-jq"):
            if not args:
                self.warn(plugin.name, f"ignored body jq rule without expression: {line}")
                return None
            return f"{body_type}-jq {pattern} {quote_jq(join_shellish(args))}"

        if action.endswith("-body-json-del"):
            paths = [parse_json_path(arg) for arg in args if arg]
            if not paths:
                self.warn(plugin.name, f"ignored body json-del rule without paths: {line}")
                return None
            return f"{body_type}-jq {pattern} {quote_jq(jq_delpaths(paths))}"

        if action.endswith("-body-json-add") or action.endswith("-body-json-replace"):
            if len(args) < 2 or len(args) % 2:
                self.warn(plugin.name, f"ignored body json set rule with invalid pairs: {line}")
                return None
            expressions: list[str] = []
            for index in range(0, len(args), 2):
                path = parse_json_path(args[index])
                value = parse_loon_value(args[index + 1])
                if action.endswith("-body-json-replace"):
                    expressions.append(jq_replace_path(path, value))
                else:
                    expressions.append(jq_set_path(path, value))
            return f"{body_type}-jq {pattern} {quote_jq(' | '.join(expressions))}"

        if action.endswith("-body-replace-regex"):
            if len(args) < 2:
                self.warn(plugin.name, f"ignored body regex rule without replacement: {line}")
                return None
            return f"{body_type} {pattern} {join_shellish(args)}"

        self.warn(plugin.name, f"ignored unsupported body rewrite action {tokens[1]}: {line}")
        return None

    def convert_map_local_line(self, plugin: ParsedPlugin, raw_line: str) -> str | None:
        line = clean_line(raw_line)
        if not line:
            return None
        tokens = split_shellish(line)
        if len(tokens) < 2:
            self.warn(plugin.name, f"ignored unsupported map local line: {line}")
            return None

        pattern = tokens[0]
        second = normalize_token(tokens[1])
        if second == "url" and len(tokens) >= 5 and normalize_token(tokens[2]) == "echo-response":
            content_type = unquote_wrapped(tokens[3])
            data = unquote_wrapped(tokens[4])
            return format_map_local(
                pattern,
                {
                    "data-type": "file",
                    "data": data,
                    "header": f"Content-Type:{content_type}",
                },
            )

        if second == "mock-response-body":
            params = parse_space_params(tokens[2:])
            return format_map_local(pattern, normalize_map_local_params(params))

        params = parse_space_params(tokens[1:])
        if params:
            return format_map_local(pattern, normalize_map_local_params(params))

        self.warn(plugin.name, f"ignored unsupported map local line: {line}")
        return None

    def convert_url_rewrite_line(self, plugin: ParsedPlugin, raw_line: str) -> str | None:
        line = clean_line(raw_line)
        if not line:
            return None
        tokens = split_shellish(line)
        if len(tokens) < 2:
            self.warn(plugin.name, f"ignored unsupported rewrite line: {line}")
            return None

        pattern = tokens[0]
        second = normalize_token(tokens[1])

        if second.startswith("reject"):
            return f"{pattern} - reject"

        if second == "url" and len(tokens) >= 4 and normalize_token(tokens[2]) in {"302", "307", "header"}:
            return f"{pattern} {tokens[3]} {normalize_token(tokens[2])}"

        if second in {"302", "307", "header"}:
            replacement = tokens[2] if len(tokens) >= 3 else "_"
            return f"{pattern} {replacement} {second}"

        last = normalize_token(tokens[-1])
        if last.startswith("reject"):
            return f"{pattern} - reject"

        if last in {"302", "307", "header"} and len(tokens) >= 3:
            replacement = " ".join(tokens[1:-1]).strip() or "_"
            return f"{pattern} {replacement} {last}"

        if "mock-response" in line or "echo-response" in line:
            self.warn(plugin.name, f"mock response may need manual review: {line}")
        return line

    def convert_header_rewrite_lines(self, plugin: ParsedPlugin, raw_line: str) -> list[str]:
        line = clean_line(raw_line)
        if not line:
            return []
        tokens = split_shellish(line)
        if len(tokens) >= 4 and normalize_token(tokens[0]) in {"http-request", "http-response"}:
            return [line]
        if len(tokens) < 3:
            self.warn(plugin.name, f"ignored unsupported header rewrite line: {line}")
            return []

        pattern = tokens[0]
        raw_action = normalize_token(tokens[1])
        if raw_action.startswith("response-header-"):
            http_type = "http-response"
            action = raw_action.removeprefix("response-")
        elif raw_action.startswith("header-"):
            http_type = "http-request"
            action = raw_action
        else:
            self.warn(plugin.name, f"ignored unsupported header rewrite line: {line}")
            return []

        suffix = tokens[2:]
        converted: list[str] = []
        if action == "header-del":
            for key in suffix:
                converted.append(f"{http_type} {pattern} {action} {quote_header_value(key)}")
            return converted

        step = 3 if action == "header-replace-regex" else 2
        if len(suffix) % step:
            self.warn(plugin.name, f"ignored incomplete header rewrite values: {line}")
        for index in range(0, len(suffix) - (len(suffix) % step), step):
            values = " ".join(quote_header_value(value) for value in suffix[index : index + step])
            converted.append(f"{http_type} {pattern} {action} {values}")
        if converted:
            return converted
        self.warn(plugin.name, f"ignored unsupported header rewrite line: {line}")
        return []

    def convert_header_rewrite_line(self, plugin: ParsedPlugin, raw_line: str) -> str | None:
        lines = self.convert_header_rewrite_lines(plugin, raw_line)
        return lines[0] if lines else None

    def convert_script_line(self, plugin: ParsedPlugin, raw_line: str) -> str | None:
        line = clean_line(raw_line)
        if not line:
            return None

        existing = parse_existing_surge_script(line)
        if existing:
            name, params = existing
            unique = self.unique_script_name(name)
            return f"{unique} = {params}"

        kind_match = re.match(r"^([A-Za-z-]+)\s*(.*)$", line)
        if not kind_match:
            self.warn(plugin.name, f"ignored unsupported script line: {line}")
            return None

        kind = kind_match.group(1).lower()
        rest = kind_match.group(2).strip()
        params: dict[str, str] = {}
        pattern: str | None = None
        cronexp: str | None = None

        if kind in {"http-request", "http-response"}:
            pattern, params_text = split_pattern_and_params(rest)
            if params_text:
                params = parse_params(params_text)
            else:
                items = split_shellish(rest)
                if len(items) >= 2:
                    pattern = items[0]
                    params = {"script-path": items[1]}
                    if len(items) > 2:
                        params.update(parse_params(" ".join(items[2:])))
            if not pattern or "script-path" not in params:
                self.warn(plugin.name, f"ignored incomplete HTTP script line: {line}")
                return None
            params["type"] = kind
            params["pattern"] = pattern

        elif kind == "cron":
            cronexp, params_text = split_leading_value(rest)
            params = parse_params(params_text)
            if "script-path" not in params:
                self.warn(plugin.name, f"ignored incomplete cron script line: {line}")
                return None
            params["type"] = "cron"
            params["cronexp"] = quote_if_needed(cronexp)

        elif kind in {"network-changed", "system", "event"}:
            params = parse_params(rest)
            if "script-path" not in params:
                self.warn(plugin.name, f"ignored incomplete event script line: {line}")
                return None
            params["type"] = "event"
            params.setdefault("event-name", "network-changed" if kind == "network-changed" else kind)

        elif kind in {"generic", "dns", "rule"}:
            params = parse_params(rest)
            if "script-path" not in params:
                self.warn(plugin.name, f"ignored incomplete {kind} script line: {line}")
                return None
            params["type"] = kind

        else:
            self.warn(plugin.name, f"ignored unsupported script type {kind}: {line}")
            return None

        normalize_script_params(params)
        script_name = params.pop("tag", "") or derive_script_name(plugin.name, params)
        script_name = self.unique_script_name(script_name)
        return f"{script_name} = {format_script_params(params)}"

    def unique_script_name(self, name: str) -> str:
        base = sanitize_script_name(name)
        candidate = base
        index = 2
        while candidate in self.used_script_names:
            candidate = f"{base}_{index}"
            index += 1
        self.used_script_names.add(candidate)
        return candidate


def parse_plugin(source: Source) -> ParsedPlugin:
    plugin = ParsedPlugin(name=source.name, origin=source.origin)
    current_section = "preamble"
    plugin.sections[current_section] = []

    for raw_line in source.text.splitlines():
        line = raw_line.strip().lstrip("\ufeff")
        if line.startswith("#!"):
            plugin.metadata_lines.append(line)
            parsed = parse_metadata(line)
            if parsed:
                key, value = parsed
                plugin.metadata[key.lower()] = value
            continue

        section_match = re.match(r"^\[([^\]]+)\]\s*$", line)
        if section_match:
            section_name = section_match.group(1).strip().lower()
            current_section = SECTION_ALIASES.get(section_name, section_name)
            plugin.sections.setdefault(current_section, [])
            continue

        plugin.sections.setdefault(current_section, []).append(raw_line)

    return plugin


def parse_metadata(line: str) -> tuple[str, str] | None:
    match = re.match(r"^#!\s*([^=\s]+)\s*=\s*(.*)$", line)
    if not match:
        return None
    return match.group(1).strip(), match.group(2).strip()


def clean_line(raw_line: str) -> str:
    line = raw_line.strip()
    if not line:
        return ""
    if line.startswith("#") or line.startswith(";") or line.startswith("//"):
        return ""
    return strip_inline_comment(line).strip()


def strip_inline_comment(line: str) -> str:
    in_quote: str | None = None
    escaped = False
    for index, char in enumerate(line):
        if escaped:
            escaped = False
            continue
        if char == "\\":
            escaped = True
            continue
        if char in {"'", '"'}:
            if in_quote == char:
                in_quote = None
            elif in_quote is None:
                in_quote = char
            continue
        if in_quote is None and char.isspace():
            rest = line[index:].lstrip()
            if rest.startswith("//") or rest.startswith("#") or rest.startswith(";"):
                return line[:index]
    return line


def parse_key_value(line: str) -> tuple[str, str] | None:
    if "=" not in line:
        return None
    key, value = line.split("=", 1)
    key = key.strip()
    value = value.strip()
    if not key:
        return None
    return key, value


def format_append_line(key: str, value: str) -> str:
    if value.startswith("%APPEND%") or value.startswith("%INSERT%"):
        return f"{key} = {value}"
    return f"{key} = %APPEND% {value}"


def split_top_level(text: str, delimiter: str) -> list[str]:
    parts: list[str] = []
    current: list[str] = []
    quote: str | None = None
    escaped = False
    depth = 0
    pairs = {"(": ")", "[": "]", "{": "}"}
    closers = set(pairs.values())

    for char in text:
        if escaped:
            current.append(char)
            escaped = False
            continue
        if char == "\\":
            current.append(char)
            escaped = True
            continue
        if quote:
            current.append(char)
            if char == quote:
                quote = None
            continue
        if char in {"'", '"'}:
            quote = char
            current.append(char)
            continue
        if char in pairs:
            depth += 1
            current.append(char)
            continue
        if char in closers and depth > 0:
            depth -= 1
            current.append(char)
            continue
        if char == delimiter and depth == 0:
            parts.append("".join(current).strip())
            current = []
            continue
        current.append(char)

    parts.append("".join(current).strip())
    return [part for part in parts if part]


def split_shellish(text: str) -> list[str]:
    tokens: list[str] = []
    current: list[str] = []
    quote: str | None = None
    escaped = False

    for char in text:
        if escaped:
            current.append(char)
            escaped = False
            continue
        if char == "\\":
            current.append(char)
            escaped = True
            continue
        if quote:
            current.append(char)
            if char == quote:
                quote = None
            continue
        if char in {"'", '"'}:
            quote = char
            current.append(char)
            continue
        if char.isspace():
            if current:
                tokens.append("".join(current))
                current = []
            continue
        current.append(char)

    if current:
        tokens.append("".join(current))
    return tokens


def normalize_token(token: str) -> str:
    return token.strip().lower()


def normalize_policy(policy: str) -> str:
    upper = policy.upper()
    return REJECT_POLICY_MAP.get(upper, upper)


def is_header_rewrite_line(line: str) -> bool:
    return bool(
        re.search(
            r"\b(?:http-request|http-response)\s+\S+\s+header-(?:add|del|replace|replace-regex)\b"
            r"|\s(?:response-)?header-(?:add|del|replace|replace-regex)\b",
            line,
            re.IGNORECASE,
        )
    )


def is_body_rewrite_line(line: str) -> bool:
    return bool(
        re.search(
            r"\b(?:request|response)-body\b|\bbody-(?:replace|append|json-jq)\b"
            r"|\burl\s+jsonjq-(?:request|response)-body\b",
            line,
            re.I,
        )
    )


def is_map_local_line(line: str) -> bool:
    return bool(re.search(r"\b(?:map-local|mock-response|echo-response)\b", line, re.I))


def body_action_type(action: str) -> str | None:
    if action.startswith("request-"):
        return "http-request"
    if action.startswith("response-"):
        return "http-response"
    return None


def join_shellish(tokens: list[str]) -> str:
    return " ".join(tokens).strip()


def parse_json_path(value: str) -> list[object]:
    value = unquote_wrapped(value).replace("\\x20", " ").strip()
    if not value:
        return []

    parts: list[object] = []
    current: list[str] = []
    bracket: list[str] | None = None

    def append_part(raw: str) -> None:
        raw = raw.strip()
        if not raw:
            return
        raw = unquote_wrapped(raw)
        parts.append(int(raw) if re.fullmatch(r"\d+", raw) else raw)

    for char in value:
        if bracket is not None:
            if char == "]":
                append_part("".join(bracket))
                bracket = None
            else:
                bracket.append(char)
            continue
        if char == ".":
            append_part("".join(current))
            current = []
            continue
        if char == "[":
            append_part("".join(current))
            current = []
            bracket = []
            continue
        current.append(char)

    append_part("".join(current))
    return parts


def parse_loon_value(value: str) -> object:
    value = value.replace("\\x20", " ").strip()
    if len(value) >= 2 and value[0] == value[-1] and value[0] in {"'", '"'}:
        return value[1:-1]
    try:
        return json.loads(value)
    except json.JSONDecodeError:
        return value


def compact_json(value: object) -> str:
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"))


def jq_path(path: list[object]) -> str:
    return compact_json(path)


def jq_value(value: object) -> str:
    return compact_json(value)


def jq_delpaths(paths: list[list[object]]) -> str:
    return f"delpaths({compact_json(paths)})"


def jq_set_path(path: list[object], value: object) -> str:
    return f"setpath({jq_path(path)}; {jq_value(value)})"


def jq_replace_path(path: list[object], value: object) -> str:
    if not path:
        return "."
    parent = path[:-1]
    last = path[-1]
    has_arg = last if isinstance(last, int) else compact_json(last)
    return (
        f"if (getpath({jq_path(parent)}) | has({has_arg})) "
        f"then ({jq_set_path(path, value)}) else . end"
    )


def quote_jq(expression: str) -> str:
    if len(expression) >= 2 and expression[0] == expression[-1] and expression[0] in {"'", '"'}:
        return expression
    return "'" + expression.replace("\\", "\\\\").replace("'", "\\'") + "'"


def parse_loon_key(value: str) -> str:
    return unquote_wrapped(value).replace("\\x20", " ")


def quote_header_value(value: str) -> str:
    value = parse_loon_key(value)
    return "'" + value.replace("\\", "\\\\").replace("'", "\\'") + "'"


def parse_space_params(tokens: list[str]) -> dict[str, str]:
    params: dict[str, str] = {}
    for token in tokens:
        if "=" not in token:
            continue
        key, value = token.split("=", 1)
        key = key.strip().lower()
        if key:
            params[key] = unquote_wrapped(value.strip())
    return params


def normalize_map_local_params(params: dict[str, str]) -> dict[str, str]:
    data_type = params.get("data-type", "file").lower()
    data = params.get("data", params.get("data-path", ""))
    header = params.get("header", "")
    status_code = params.get("status-code", "")
    is_base64 = params.get("mock-data-is-base64", "").lower() == "true"

    content_types = {
        "json": "application/json",
        "text": "text/plain",
        "plain": "text/plain",
        "css": "text/css",
        "html": "text/html",
        "javascript": "application/javascript",
        "svg": "image/svg+xml",
        "png": "image/png",
        "jpeg": "image/jpeg",
        "jpg": "image/jpeg",
        "gif": "image/gif",
        "tiff": "image/tiff",
        "mp4": "video/mp4",
        "form-data": "multipart/form-data",
    }

    if is_base64:
        surge_type = "base64"
    elif data_type in {"tiny-gif", "tinygif"}:
        surge_type = "tiny-gif"
    elif data_type == "file":
        surge_type = "file"
    elif data_type == "base64":
        surge_type = "base64"
    else:
        surge_type = "text"

    result: dict[str, str] = {"data-type": surge_type}
    if data and surge_type != "tiny-gif":
        result["data"] = data
    if status_code:
        result["status-code"] = status_code

    content_type = content_types.get(data_type)
    if content_type:
        header = merge_header(header, f"Content-Type:{content_type}")
    if header:
        result["header"] = header
    return result


def merge_header(existing: str, header: str) -> str:
    if not existing:
        return header
    existing_keys = {item.split(":", 1)[0].strip().lower() for item in existing.split("|") if ":" in item}
    key = header.split(":", 1)[0].strip().lower()
    if key in existing_keys:
        return existing
    return f"{existing}|{header}"


def format_map_local(pattern: str, params: dict[str, str]) -> str:
    order = ["data-type", "data", "status-code", "header"]
    pieces = [pattern]
    for key in order:
        value = params.get(key)
        if value is None or value == "":
            continue
        pieces.append(f"{key}={format_map_value(key, value)}")
    for key in sorted(k for k in params if k not in order):
        value = params[key]
        if value:
            pieces.append(f"{key}={format_map_value(key, value)}")
    return " ".join(pieces)


def format_map_value(key: str, value: str) -> str:
    if key in {"data", "header"}:
        return '"' + value.replace("\\", "\\\\").replace('"', '\\"') + '"'
    return value


def reject_action_to_map_local(pattern: str, action: str) -> str:
    if action == "reject-dict":
        return format_map_local(
            pattern,
            {
                "data-type": "text",
                "data": "{}",
                "status-code": "200",
                "header": "Content-Type:application/json",
            },
        )
    if action == "reject-array":
        return format_map_local(
            pattern,
            {
                "data-type": "text",
                "data": "[]",
                "status-code": "200",
            },
        )
    if action == "reject-200":
        return format_map_local(pattern, {"data-type": "text", "data": " ", "status-code": "200"})
    return format_map_local(pattern, {"data-type": "tiny-gif", "status-code": "200"})


def parse_existing_surge_script(line: str) -> tuple[str, str] | None:
    match = re.match(r"^([^=]+?)\s*=\s*(type\s*=.*)$", line, re.IGNORECASE)
    if not match:
        return None
    return match.group(1).strip(), match.group(2).strip()


def split_pattern_and_params(text: str) -> tuple[str | None, str]:
    matches = list(SCRIPT_PARAM_START_RE.finditer(text))
    if not matches:
        return None, ""
    match = next((item for item in matches if item.group(1).lower() == "script-path"), matches[0])
    pattern = text[: match.start()].strip()
    params_text = text[match.start() :].strip()
    return pattern, params_text


def split_leading_value(text: str) -> tuple[str, str]:
    text = text.strip()
    if not text:
        return "", ""
    if text[0] in {"'", '"'}:
        quote = text[0]
        escaped = False
        for index in range(1, len(text)):
            char = text[index]
            if escaped:
                escaped = False
                continue
            if char == "\\":
                escaped = True
                continue
            if char == quote:
                return text[: index + 1], text[index + 1 :].strip()
        return text, ""
    parts = text.split(None, 1)
    if len(parts) == 1:
        return parts[0], ""
    return parts[0], parts[1].strip()


def parse_params(text: str) -> dict[str, str]:
    params: dict[str, str] = {}
    if not text:
        return params

    normalized = text.strip()
    if "," not in normalized and SCRIPT_PARAM_START_RE.search(normalized):
        # Support a small subset of space-separated key=value parameters.
        matches = list(SCRIPT_PARAM_START_RE.finditer(normalized))
        for index, match in enumerate(matches):
            key = match.group(1).lower()
            start = match.end()
            end = matches[index + 1].start() if index + 1 < len(matches) else len(normalized)
            params[key] = normalized[start:end].strip().strip(",")
        return params

    for part in split_top_level(normalized, ","):
        if "=" not in part:
            continue
        key, value = part.split("=", 1)
        key = key.strip().lower()
        value = value.strip()
        if key:
            params[key] = value
    return params


def normalize_script_params(params: dict[str, str]) -> None:
    if "enable" in params and "enabled" not in params:
        params["enabled"] = params.pop("enable")
    if "cron" in params and "cronexp" not in params:
        params["cronexp"] = params.pop("cron")
    if "cronexpr" in params and "cronexp" not in params:
        params["cronexp"] = params.pop("cronexpr")


def derive_script_name(plugin_name: str, params: dict[str, str]) -> str:
    path = params.get("script-path", "")
    if path:
        stem = re.sub(r"[?#].*$", "", path.rstrip("/")).rsplit("/", 1)[-1]
        stem = re.sub(r"\.[A-Za-z0-9]+$", "", stem)
        if stem:
            return stem
    return plugin_name


def sanitize_script_name(name: str) -> str:
    name = unquote_wrapped(name).strip()
    name = re.sub(r"\s+", "_", name)
    name = re.sub(r"[^A-Za-z0-9_.-]+", "_", name)
    name = name.strip("._-")
    return name or "script"


def unquote_wrapped(value: str) -> str:
    value = value.strip()
    if len(value) >= 2 and value[0] == value[-1] and value[0] in {"'", '"'}:
        return value[1:-1]
    return value


def quote_if_needed(value: str) -> str:
    value = value.strip()
    if len(value) >= 2 and value[0] == value[-1] and value[0] in {"'", '"'}:
        return value
    if any(char.isspace() for char in value):
        escaped = value.replace('"', '\\"')
        return f'"{escaped}"'
    return value


def format_script_params(params: dict[str, str]) -> str:
    order = [
        "type",
        "pattern",
        "cronexp",
        "event-name",
        "script-path",
        "requires-body",
        "max-size",
        "timeout",
        "argument",
        "script-update-interval",
        "binary-body-mode",
        "debug",
        "engine",
        "ability",
        "enabled",
        "wake-system",
        "img-url",
        "desc",
    ]
    pieces: list[str] = []
    for key in order:
        if key in params:
            pieces.append(f"{key}={params[key]}")
    for key in sorted(k for k in params if k not in order):
        pieces.append(f"{key}={params[key]}")
    return ",".join(pieces)


def build_arguments(lines: list[str]) -> str:
    pairs: list[str] = []
    for line in lines:
        if re.match(r"^#!\s*arguments\s*=", line, re.IGNORECASE):
            _, value = line.split("=", 1)
            pairs.append(value.strip())
            continue
        parsed = parse_key_value(line)
        if parsed:
            key, value = parsed
            arg_type_match = re.match(r"^(?:input|select|switch)\s*,\s*([^,]*)", value.strip(), re.IGNORECASE)
            arg_value = arg_type_match.group(1).strip() if arg_type_match else value.strip()
            pairs.append(f"{key.strip()}:{arg_value}")
    return ",".join(pair for pair in pairs if pair)


def dedupe_names(names: Iterable[str]) -> list[str]:
    seen: set[str] = set()
    result: list[str] = []
    for name in names:
        normalized = name.strip()
        if not normalized or normalized in seen:
            continue
        seen.add(normalized)
        result.append(normalized)
    return result


def dedupe(lines: Iterable[str]) -> list[str]:
    seen: set[str] = set()
    result: list[str] = []
    for line in lines:
        key = re.sub(r"\s+", " ", line.strip())
        if not key or key in seen:
            continue
        seen.add(key)
        result.append(line)
    return result


def decode_bytes(raw: bytes) -> str:
    for encoding in ("utf-8-sig", "utf-8", "gb18030"):
        try:
            return raw.decode(encoding)
        except UnicodeDecodeError:
            continue
    return raw.decode("utf-8", errors="replace")


def load_source(spec: object, base_dir: Path) -> Source:
    if isinstance(spec, str):
        if re.match(r"^https?://", spec):
            spec = {"url": spec}
        else:
            spec = {"path": spec}

    if not isinstance(spec, dict):
        raise ConversionError(f"invalid source entry: {spec!r}")

    if spec.get("enabled", True) is False:
        raise ConversionError("disabled source should have been filtered before loading")

    name = str(spec.get("name") or spec.get("url") or spec.get("path") or "source")

    if "url" in spec:
        url = str(spec["url"])
        request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
        try:
            with urllib.request.urlopen(request, timeout=int(spec.get("timeout", 30))) as response:
                raw = response.read()
        except urllib.error.URLError as exc:
            raise ConversionError(f"failed to fetch {url}: {exc}") from exc
        text = decode_bytes(raw)
        return Source(name=name, text=text, origin=url, sha256=hashlib.sha256(raw).hexdigest())

    if "path" not in spec:
        raise ConversionError(f"source {name} must contain path or url")
    path = Path(str(spec["path"]))
    if not path.is_absolute():
        path = base_dir / path
    raw = path.read_bytes()
    return Source(
        name=name,
        text=decode_bytes(raw),
        origin=str(path),
        sha256=hashlib.sha256(raw).hexdigest(),
    )


def enabled_sources(items: Iterable[object]) -> list[object]:
    result = []
    for item in items:
        if isinstance(item, dict) and item.get("enabled", True) is False:
            continue
        result.append(item)
    return result


def convert_job(job: dict[str, object], base_dir: Path) -> ConvertOutput:
    sources_spec = enabled_sources(job.get("sources", []))  # type: ignore[arg-type]
    if not sources_spec:
        raise ConversionError("no enabled sources configured")

    output_path = Path(str(job.get("output", "dist/converted.sgmodule")))
    if not output_path.is_absolute():
        output_path = base_dir / output_path

    sources = [load_source(spec, base_dir) for spec in sources_spec]
    options = ConvertOptions(
        module_name=str(job.get("name", "Converted Loon Plugins")),
        module_desc=str(job.get("description", "Converted from Loon plugins for Surge.")),
        rule_policy=str(job.get("rule_policy", "DIRECT")).upper(),
        strict=bool(job.get("strict", False)),
    )
    if options.rule_policy not in INTERNAL_POLICIES:
        raise ConversionError(
            f"rule_policy must be one of {', '.join(sorted(INTERNAL_POLICIES))}"
        )

    converter = Converter(options)
    result = converter.convert(sources)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(result.text, encoding="utf-8", newline="\n")
    return result


def load_jobs_from_config(path: Path) -> list[dict[str, object]]:
    config = json.loads(path.read_text(encoding="utf-8"))
    if "outputs" in config:
        jobs = config["outputs"]
        if not isinstance(jobs, list):
            raise ConversionError("config.outputs must be a list")
        return jobs
    return [config]


def cli_jobs(args: argparse.Namespace) -> list[dict[str, object]]:
    sources: list[dict[str, str]] = []
    for path in args.input or []:
        sources.append({"path": path})
    for url in args.url or []:
        sources.append({"url": url})
    if not sources:
        raise ConversionError("provide --config, --input, or --url")
    return [
        {
            "name": args.name,
            "description": args.description,
            "output": args.output,
            "rule_policy": args.rule_policy,
            "strict": args.strict,
            "sources": sources,
        }
    ]


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", help="JSON config file, e.g. config/sources.json")
    parser.add_argument("--input", action="append", help="Local Loon plugin path")
    parser.add_argument("--url", action="append", help="Remote Loon plugin URL")
    parser.add_argument("--output", default="dist/converted.sgmodule", help="Output .sgmodule")
    parser.add_argument("--name", default="Converted Loon Plugins", help="Module name")
    parser.add_argument(
        "--description",
        default="Converted from Loon plugins for Surge.",
        help="Module description",
    )
    parser.add_argument(
        "--rule-policy",
        default="DIRECT",
        choices=sorted(INTERNAL_POLICIES),
        help="Policy used when a Loon rule uses a non-module Surge policy",
    )
    parser.add_argument("--strict", action="store_true", help="Fail on unsupported lines")
    parser.add_argument(
        "--fail-on-warning",
        action="store_true",
        help="Exit with non-zero status if warnings were emitted",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv or sys.argv[1:])
    root = Path.cwd()
    config_base = root

    try:
        if args.config:
            config_path = Path(args.config)
            if not config_path.is_absolute():
                config_path = root / config_path
            config_base = config_path.parent.parent if config_path.parent.name == "config" else config_path.parent
            jobs = load_jobs_from_config(config_path)
        else:
            jobs = cli_jobs(args)

        all_warnings: list[str] = []
        for job in jobs:
            result = convert_job(job, config_base)
            all_warnings.extend(result.warnings)

        for warning in all_warnings:
            print(f"warning: {warning}", file=sys.stderr)
        if args.fail_on_warning and all_warnings:
            return 2
        return 0
    except (OSError, json.JSONDecodeError, ConversionError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
