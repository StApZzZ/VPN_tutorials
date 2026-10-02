#!/usr/bin/env python3
"""Publish an already validated release from GitHub Actions without rewriting refs."""
import json
import hashlib
import os
from pathlib import Path
import urllib.error
import urllib.request

repository = os.environ["GITHUB_REPOSITORY"]
sha = os.environ["GITHUB_SHA"]
api = "https://api.github.com/repos/" + repository
token = os.environ["GITHUB_TOKEN"]
headers = {"Authorization": "Bearer " + token, "Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28"}


def call(url, data=None, content_type="application/json"):
    body = json.dumps(data).encode() if isinstance(data, dict) else data
    request = urllib.request.Request(url, data=body, headers={**headers, "Content-Type": content_type})
    with urllib.request.urlopen(request, timeout=60) as response:
        return json.load(response)


for tag, target in [("init", "518fb5dab6a30fae43c14f1b7ad3177bc925eeb3"), ("v2", sha)]:
    try:
        existing = call(api + "/git/ref/tags/" + tag)
    except urllib.error.HTTPError as exc:
        if exc.code != 404:raise
        call(api + "/git/refs", {"ref": "refs/tags/" + tag, "sha": target})
    else:
        if existing["object"]["sha"] != target:raise SystemExit("Tag already points to a different commit: " + tag)
try:
    release = call(api + "/releases/tags/v2")
except urllib.error.HTTPError as exc:
    if exc.code != 404:raise
    release = call(api + "/releases", {"tag_name": "v2", "name": "CorpVPN 2.0.0", "body": "Single IPv4 gateway, optional site connector and SQLite. See the attached test report, SBOM and checksums for the validated release.", "draft": False, "prerelease": False})
artifacts = Path(os.environ["RELEASE_DIR"])
existing_assets = {asset["name"]: asset for asset in release["assets"]}
for path in sorted(artifacts.iterdir()):
    if not path.is_file():continue
    if path.name in existing_assets:
        asset = existing_assets[path.name]
        request = urllib.request.Request(asset["url"], headers={**headers, "Accept": "application/octet-stream"})
        with urllib.request.urlopen(request, timeout=60) as response:
            digest = hashlib.sha256(response.read()).hexdigest()
        if digest != hashlib.sha256(path.read_bytes()).hexdigest():
            raise SystemExit("Refusing to overwrite a different published asset: " + path.name)
        continue
    url = release["upload_url"].split("{", 1)[0] + "?name=" + path.name
    call(url, path.read_bytes(), "application/octet-stream")
print("Published " + repository + " v2 at " + sha)
