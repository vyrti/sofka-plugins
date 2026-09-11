#!/usr/bin/env python3
"""Validate, package, and publish the single-file sofka plugin catalog."""

from __future__ import annotations

import argparse
import datetime
import gzip
import hashlib
import io
import json
import os
import pathlib
import re
import subprocess
import sys
import tarfile
import tempfile
import tomllib

ROOT = pathlib.Path(__file__).resolve().parents[1]
PLUGINS = ROOT / "plugins"
INDEX = ROOT / "index.json"
RELEASE_ROOT = "https://github.com/nklmilojevic/sofka-plugins/releases/download/"
ID = re.compile(r"^[a-z0-9][a-z0-9-]*$")
VERSION = re.compile(r"^[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.-]+)?$")
TARGETS = {
    "x86_64-unknown-linux-gnu": "ubuntu-22.04",
    "aarch64-unknown-linux-gnu": "ubuntu-22.04-arm",
    "aarch64-apple-darwin": "macos-latest",
    "x86_64-apple-darwin": "macos-15-intel",
}


def read_json(path: pathlib.Path) -> object:
    with path.open(encoding="utf-8") as handle:
        return json.load(handle)


def plugin_ids() -> list[str]:
    return sorted(path.name for path in PLUGINS.iterdir() if path.is_dir())


def publication(plugin: str) -> dict[str, object]:
    value = read_json(PLUGINS / plugin / "publication.json")
    check(isinstance(value, dict), f"{plugin}: publication.json must be an object")
    return value


def check(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def required(value: dict[str, object], names: set[str], label: str) -> None:
    missing = sorted(names - value.keys())
    check(not missing, f"{label}: missing {', '.join(missing)}")


def exact_fields(value: dict[str, object], names: set[str], label: str) -> None:
    required(value, names, label)
    unknown = sorted(value.keys() - names)
    check(not unknown, f"{label}: unknown fields {', '.join(unknown)}")


def validate_index(index: dict[str, object]) -> None:
    check(set(index) == {"schema_version", "generated_at", "plugins"}, "index has unknown or missing fields")
    check(index["schema_version"] == 1, "index schema_version must be 1")
    check(isinstance(index["generated_at"], str), "index generated_at must be a string")
    check(isinstance(index["plugins"], list), "index plugins must be an array")
    seen_ids: set[str] = set()
    for plugin in index["plugins"]:
        check(isinstance(plugin, dict), "index plugin must be an object")
        plugin_fields = {"id", "display_name", "description", "tags", "publisher", "repository", "versions"}
        exact_fields(plugin, plugin_fields, "plugin")
        plugin_id = plugin["id"]
        check(isinstance(plugin_id, str) and ID.fullmatch(plugin_id) is not None, f"invalid plugin ID {plugin_id!r}")
        check(plugin_id not in seen_ids, f"duplicate plugin ID {plugin_id}")
        seen_ids.add(plugin_id)
        check(isinstance(plugin["versions"], list), f"{plugin_id}: versions must be an array")
        seen_versions: set[str] = set()
        for release in plugin["versions"]:
            check(isinstance(release, dict), f"{plugin_id}: version must be an object")
            release_fields = {"version", "sofka", "source_commit", "license", "readme", "requirements", "command", "target", "output", "mutating", "confirm", "dangerous", "network_load", "status", "withdrawal_reason", "artifacts"}
            required(release, release_fields - {"withdrawal_reason"}, f"{plugin_id} version")
            check(not (release.keys() - release_fields), f"{plugin_id} version: unknown fields")
            version = release["version"]
            check(isinstance(version, str) and VERSION.fullmatch(version) is not None, f"{plugin_id}: invalid version")
            check(version not in seen_versions, f"{plugin_id}: duplicate version {version}")
            seen_versions.add(version)
            check(re.fullmatch(r"[0-9a-f]{40}", str(release["source_commit"])) is not None, f"{plugin_id}@{version}: invalid source commit")
            check(release["status"] in {"active", "withdrawn"}, f"{plugin_id}@{version}: invalid status")
            if release["status"] == "withdrawn":
                check(bool(release.get("withdrawal_reason")), f"{plugin_id}@{version}: withdrawal needs a reason")
            else:
                check("withdrawal_reason" not in release, f"{plugin_id}@{version}: active version has withdrawal_reason")
            artifacts = release["artifacts"]
            check(isinstance(artifacts, list) and artifacts, f"{plugin_id}@{version}: no artifacts")
            platforms: set[str] = set()
            for artifact in artifacts:
                exact_fields(artifact, {"platform", "url", "sha256", "size"}, f"{plugin_id}@{version} artifact")
                platform = artifact["platform"]
                check(platform == "any" or platform in TARGETS, f"{plugin_id}@{version}: unsupported platform {platform}")
                check(platform not in platforms, f"{plugin_id}@{version}: duplicate platform {platform}")
                platforms.add(platform)
                check(str(artifact["url"]).startswith(RELEASE_ROOT), f"{plugin_id}@{version}: external artifact URL")
                check(re.fullmatch(r"[0-9a-f]{64}", str(artifact["sha256"])) is not None, f"{plugin_id}@{version}: invalid digest")
                check(isinstance(artifact["size"], int) and 0 < artifact["size"] <= 50 * 1024 * 1024, f"{plugin_id}@{version}: invalid size")
            for requirement in release["requirements"]:
                check(isinstance(requirement, dict), f"{plugin_id}@{version}: invalid requirement")
                exact_fields(requirement, {"name", "install"}, f"{plugin_id}@{version} requirement")
                check(bool(requirement["name"]) and bool(requirement["install"]), f"{plugin_id}@{version}: empty requirement")


def validate_sources(index: dict[str, object]) -> None:
    source_ids = set(plugin_ids())
    indexed_ids = {plugin["id"] for plugin in index["plugins"]}
    missing_sources = indexed_ids - source_ids
    check(not missing_sources, f"published plugin source is missing: {', '.join(sorted(missing_sources))}")
    for plugin in plugin_ids():
        path = PLUGINS / plugin
        check(ID.fullmatch(plugin) is not None, f"invalid plugin directory {plugin!r}")
        metadata = publication(plugin)
        publication_fields = {"id", "display_name", "description", "tags", "publisher", "repository", "version", "sofka", "license", "readme", "requirements", "command", "target", "output", "mutating", "confirm", "dangerous", "network_load", "platforms"}
        exact_fields(metadata, publication_fields, f"{plugin} publication")
        check(metadata["id"] == plugin, f"{plugin}: publication ID differs from directory")
        check(isinstance(metadata["version"], str) and VERSION.fullmatch(metadata["version"]) is not None, f"{plugin}: invalid version")
        cargo = tomllib.loads((path / "Cargo.toml").read_text(encoding="utf-8"))
        check(cargo["package"]["version"] == metadata["version"], f"{plugin}: Cargo and publication versions differ")
        cargo_license = cargo["package"].get("license")
        if isinstance(cargo_license, dict) and cargo_license.get("workspace") is True:
            workspace = tomllib.loads((ROOT / "Cargo.toml").read_text(encoding="utf-8"))
            cargo_license = workspace["workspace"]["package"]["license"]
        check(cargo_license == metadata["license"], f"{plugin}: Cargo and publication licenses differ")
        manifest = tomllib.loads((path / "plugin.toml").read_text(encoding="utf-8"))
        check(manifest.get("schema_version") == 1, f"{plugin}: plugin.toml schema must be 1")
        definition = manifest.get("plugin", {})
        for field in ("command", "target", "output", "mutating", "confirm", "dangerous", "network_load"):
            manifest_value = definition.get(field)
            if field == "target" and manifest_value is None:
                manifest_value = "selection"
            if field in {"confirm", "dangerous", "network_load"} and manifest_value is None:
                manifest_value = False
            check(manifest_value == metadata[field], f"{plugin}: {field} differs between manifest and publication")
        manifest_requirements = definition.get("requires", [])
        publication_requirements = [requirement["name"] for requirement in metadata["requirements"]]
        check(manifest_requirements == publication_requirements, f"{plugin}: runtime requirements differ between manifest and publication")
        check((path / "README.md").is_file(), f"{plugin}: missing README.md")
        check((path / "LICENSE").is_file(), f"{plugin}: missing LICENSE")
        check((path / "LICENSE").stat().st_size > 0, f"{plugin}: empty LICENSE")
        check((path / "fixtures" / "request.json").is_file(), f"{plugin}: missing request fixture")
        check((path / "fixtures" / "report.json").is_file(), f"{plugin}: missing report fixture")
        platforms = metadata["platforms"]
        check(isinstance(platforms, list) and platforms, f"{plugin}: no platforms")
        check(all(platform in TARGETS for platform in platforms), f"{plugin}: unsupported platform")


def changed_plugins(base: str, head: str, mode: str) -> list[str]:
    command = ["git", "diff", "--name-only", base, head]
    paths = subprocess.check_output(command, cwd=ROOT, text=True).splitlines()
    changed = {
        parts[1]
        for name in paths
        if len(parts := pathlib.PurePosixPath(name).parts) >= 2 and parts[0] == "plugins"
    }
    if mode == "test" and any(
        name in {"Cargo.toml", "Cargo.lock"} or name.startswith(("scripts/", ".github/workflows/"))
        for name in paths
    ):
        changed.update(plugin_ids())
    known = set(plugin_ids())
    return sorted(changed & known)


def changes(args: argparse.Namespace) -> None:
    plugins = changed_plugins(args.base, args.head, args.mode)
    include = []
    for plugin in plugins:
        metadata = publication(plugin)
        for target in metadata["platforms"]:
            include.append({"plugin": plugin, "target": target, "os": TARGETS[target]})
    print(json.dumps({"plugins": plugins, "matrix": {"include": include}}, separators=(",", ":")))


def assert_unpublished(args: argparse.Namespace) -> None:
    index = read_json(INDEX)
    published = {
        (plugin["id"], release["version"])
        for plugin in index["plugins"]
        for release in plugin["versions"]
    }
    for plugin in changed_plugins(args.base, args.head, "publish"):
        version = publication(plugin)["version"]
        check((plugin, version) not in published, f"{plugin}@{version} is already published; increment its version")


def package(args: argparse.Namespace) -> None:
    plugin = args.plugin
    metadata = publication(plugin)
    check(args.target in metadata["platforms"], f"{plugin}: unsupported target {args.target}")
    binary = pathlib.Path(args.binary)
    check(binary.is_file(), f"missing adapter binary {binary}")
    output = pathlib.Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    files = [
        (PLUGINS / plugin / "plugin.toml", "plugin.toml", 0o644),
        (PLUGINS / plugin / "README.md", "README.md", 0o644),
        (PLUGINS / plugin / "LICENSE", "LICENSE", 0o644),
        (ROOT / "LICENSE-MIT", "LICENSE-MIT", 0o644),
        (ROOT / "LICENSE-APACHE", "LICENSE-APACHE", 0o644),
        (binary, plugin, 0o755),
    ]
    with output.open("wb") as raw:
        with gzip.GzipFile(filename="", mode="wb", fileobj=raw, mtime=0) as compressed:
            with tarfile.open(fileobj=compressed, mode="w", format=tarfile.PAX_FORMAT) as archive:
                for source, name, mode in files:
                    data = source.read_bytes()
                    info = tarfile.TarInfo(name)
                    info.size = len(data)
                    info.mode = mode
                    info.mtime = 0
                    info.uid = info.gid = 0
                    info.uname = info.gname = ""
                    archive.addfile(info, io.BytesIO(data))


def update_index(args: argparse.Namespace) -> None:
    index = read_json(INDEX)
    by_id = {plugin["id"]: plugin for plugin in index["plugins"]}
    assets = pathlib.Path(args.assets)
    for plugin_id in args.plugins:
        metadata = publication(plugin_id)
        version = metadata["version"]
        tag = f"{plugin_id}-v{version}"
        artifacts = []
        for platform in metadata.pop("platforms"):
            name = f"{plugin_id}-{version}-{platform}.tar.gz"
            path = assets / name
            check(path.is_file(), f"missing published asset {name}")
            data = path.read_bytes()
            artifacts.append({
                "platform": platform,
                "url": f"{RELEASE_ROOT}{tag}/{name}",
                "sha256": hashlib.sha256(data).hexdigest(),
                "size": len(data),
            })
        identity = {key: metadata.pop(key) for key in ("id", "display_name", "description", "tags", "publisher", "repository")}
        release = dict(metadata)
        release.update({
            "source_commit": args.commit,
            "status": "active",
            "artifacts": artifacts,
        })
        release["readme"] = release["readme"].replace("/blob/main/", f"/blob/{args.commit}/")
        plugin = by_id.get(plugin_id)
        if plugin is None:
            plugin = {**identity, "versions": []}
            index["plugins"].append(plugin)
            by_id[plugin_id] = plugin
        else:
            for key, value in identity.items():
                plugin[key] = value
        existing = next((item for item in plugin["versions"] if item["version"] == version), None)
        if existing is not None:
            check(existing == release, f"{plugin_id}@{version} already exists with different bytes")
        else:
            plugin["versions"].append(release)
    index["plugins"].sort(key=lambda plugin: plugin["id"])
    index["generated_at"] = datetime.datetime.now(datetime.UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")
    validate_index(index)
    temporary = INDEX.with_suffix(".json.tmp")
    temporary.write_text(json.dumps(index, indent=2) + "\n", encoding="utf-8")
    os.replace(temporary, INDEX)


def main() -> None:
    parser = argparse.ArgumentParser()
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("validate")
    change = commands.add_parser("changes")
    change.add_argument("--base", required=True)
    change.add_argument("--head", required=True)
    change.add_argument("--mode", choices=("test", "publish"), required=True)
    unpublished = commands.add_parser("assert-unpublished")
    unpublished.add_argument("--base", required=True)
    unpublished.add_argument("--head", required=True)
    packaging = commands.add_parser("package")
    packaging.add_argument("--plugin", required=True)
    packaging.add_argument("--target", required=True)
    packaging.add_argument("--binary", required=True)
    packaging.add_argument("--output", required=True)
    update = commands.add_parser("update-index")
    update.add_argument("--commit", required=True)
    update.add_argument("--assets", required=True)
    update.add_argument("plugins", nargs="+")
    args = parser.parse_args()
    try:
        if args.command == "validate":
            index = read_json(INDEX)
            check(isinstance(index, dict), "index must be an object")
            validate_index(index)
            example = read_json(ROOT / "fixtures" / "index.json")
            check(isinstance(example, dict), "index fixture must be an object")
            validate_index(example)
            check(isinstance(read_json(ROOT / "index.schema.json"), dict), "schema must be an object")
            validate_sources(index)
        elif args.command == "changes":
            changes(args)
        elif args.command == "assert-unpublished":
            assert_unpublished(args)
        elif args.command == "package":
            package(args)
        elif args.command == "update-index":
            update_index(args)
    except (KeyError, OSError, subprocess.CalledProcessError, tomllib.TOMLDecodeError, ValueError) as error:
        sys.exit(str(error))


if __name__ == "__main__":
    main()
