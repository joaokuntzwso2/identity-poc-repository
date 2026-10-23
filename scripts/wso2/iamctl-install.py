#!/usr/bin/env python3
"""Install pinned WSO2 IAM-CTL into an ignored private directory.

No sudo, Homebrew, shell-piped installer, disable-TLS, or config import.
Trust: official release v3.0.0 and GitHub-supplied asset digest, or an
operator-pinned checksum. IAM-CTL is not the authentication bootstrap.
"""
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import platform
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile
import urllib.parse
import urllib.request
import zipfile

REPO = 'wso2-extensions/identity-tools-cli'
VERSION = 'v3.0.0'   # Official stable release compatible with WSO2 IS 7.3.0
RELEASE_API = f'https://api.github.com/repos/{REPO}/releases/tags/{VERSION}'
ROOT = Path(__file__).resolve().parents[2]
PRIVATE = ROOT / 'var/wso2'
TOOLS = PRIVATE / 'tools/iamctl'
CONFIG = PRIVATE / 'iamctl-local'
MAX_ARCHIVE_BYTES = 120 * 1024 * 1024
MAX_BINARY_BYTES = 100 * 1024 * 1024
# Published on the official v3.0.0 GitHub release page (2026-06-02).
# v3.0.0 has no native macOS ARM64 asset; its x64 binary requires Rosetta.
PINNED_ASSETS = {
    'iamctl-3.0.0-macosx-x64.tar.gz':'fce80e096732eb09b7eaab76755b7f85351f33254a3c1dfd7448c2cf8b4d9d54',
    'iamctl-3.0.0-linux-x64.tar.gz':'6788de4e5c99cd1daec71555b68e04ac80ebaddc8e86a5e2769e145d0bae3eab',
}

class InstallError(RuntimeError):
    pass

def platform_key():
    system = platform.system().lower()
    machine = platform.machine().lower()
    if system not in ('darwin', 'linux'):
        raise InstallError(f'IAMCTL_UNSUPPORTED_PLATFORM: {system}; use a Darwin or Linux runner')
    arch = {'arm64':'arm64', 'aarch64':'arm64', 'x86_64':'x64', 'amd64':'x64'}.get(machine)
    if not arch:
        raise InstallError(f'IAMCTL_UNSUPPORTED_ARCH: {machine}')
    return system, arch

def installation_path():
    system, arch = platform_key()
    return TOOLS / VERSION / f'{system}-{arch}' / 'bin/iamctl'

def _hostname(url):
    p = urllib.parse.urlsplit(url)
    return p.hostname if p.scheme == 'https' and not (p.username or p.password or p.fragment) else None

def read_https(url, allowed_hosts, maximum=MAX_ARCHIVE_BYTES):
    if _hostname(url) not in allowed_hosts:
        raise InstallError('IAMCTL_UNTRUSTED_DOWNLOAD_ORIGIN')
    req = urllib.request.Request(url, headers={'User-Agent':'identity-lab-iamctl-installer/1.0','Accept':'application/vnd.github+json'})
    try:
        with urllib.request.urlopen(req, timeout=45) as response:
            # Verify destination after every redirect chain; official release
            # assets are delivered on GitHub-controlled content hosts.
            if _hostname(response.geturl()) not in allowed_hosts:
                raise InstallError('IAMCTL_UNTRUSTED_REDIRECT_ORIGIN')
            data = response.read(maximum + 1)
    except (OSError, ValueError) as exc:
        raise InstallError(f'IAMCTL_DOWNLOAD_FAILED: {type(exc).__name__}: {exc}') from exc
    if not data or len(data) > maximum:
        raise InstallError('IAMCTL_DOWNLOAD_EMPTY_OR_EXCEEDS_LIMIT')
    return data

def select_asset(assets, system, arch, allow_rosetta=False):
    """Select an official versioned archive for the exact OS and CPU."""
    if system == 'darwin':
        os_pat = r'(darwin|macos|mac-os|mac)'
    else:
        os_pat = r'linux'
    for target_arch in ([arch, 'x64'] if system == 'darwin' and arch == 'arm64' and allow_rosetta else [arch]):
        arch_pat = r'(arm64|aarch64|a64)' if target_arch == 'arm64' else r'(x64|amd64|x86_64)'
        matches = []
        for asset in assets:
            name = str(asset.get('name', '')).lower()
            if not (name.endswith('.tar.gz') or name.endswith('.tgz') or name.endswith('.zip')):
                continue
            if not re.search(r'^iamctl[-_]?3\.0\.0', name):
                continue
            if re.search(os_pat, name) and re.search(arch_pat, name):
                matches.append(asset)
        if len(matches) == 1:
            return matches[0], target_arch
        if len(matches) > 1:
            raise InstallError('IAMCTL_AMBIGUOUS_RELEASE_ASSET')
    raise InstallError(
        f'IAMCTL_NO_COMPATIBLE_RELEASE_ARCHIVE: {system}/{arch}; '
        'this pinned release only provides macOS-x64 and Linux-x64 binaries'
    )

def expected_digest(asset):
    pinned = os.environ.get('IAMCTL_SHA256','').strip().lower()
    asset_name = str(asset.get('name',''))
    official = PINNED_ASSETS.get(asset_name)
    if official is None:
        raise InstallError('IAMCTL_ASSET_NOT_PINNED_IN_INSTALLER')
    if pinned and pinned != official:
        raise InstallError('IAMCTL_OPERATOR_DIGEST_CONFLICT')
    supplied = str(asset.get('digest') or '').strip().lower()
    if supplied:
        if not re.fullmatch(r'sha256:[0-9a-f]{64}', supplied):
            raise InstallError('IAMCTL_INVALID_GITHUB_RELEASE_DIGEST')
        digest = supplied.split(':', 1)[1]
        if digest != official:
            raise InstallError('IAMCTL_GITHUB_DIGEST_DISAGREES_WITH_PIN')
    return official

def _archive_entries(data, filename):
    """Return only one executable; do not extract untrusted paths or links."""
    if filename.endswith('.zip'):
        with zipfile.ZipFile(io.BytesIO(data)) as archive:
            members = [i for i in archive.infolist() if (i.filename.rstrip('/') == 'bin/iamctl' or i.filename.rstrip('/').endswith('/bin/iamctl'))]
            if len(members) != 1 or members[0].file_size > MAX_BINARY_BYTES:
                raise InstallError('IAMCTL_ARCHIVE_EXECUTABLE_MISSING_OR_DUPLICATED')
            member = members[0]
            if member.is_dir() or ((member.external_attr >> 16) & 0o170000) == 0o120000:
                raise InstallError('IAMCTL_ARCHIVE_UNSAFE_EXECUTABLE')
            content = archive.read(member)
    else:
        with tarfile.open(fileobj=io.BytesIO(data), mode='r:gz') as archive:
            members = [i for i in archive.getmembers() if (i.name.rstrip('/') == 'bin/iamctl' or i.name.rstrip('/').endswith('/bin/iamctl'))]
            if len(members) != 1 or not members[0].isfile() or members[0].size > MAX_BINARY_BYTES:
                raise InstallError('IAMCTL_ARCHIVE_EXECUTABLE_MISSING_OR_UNSAFE')
            stream = archive.extractfile(members[0])
            if stream is None:
                raise InstallError('IAMCTL_ARCHIVE_EXECUTABLE_UNREADABLE')
            content = stream.read(MAX_BINARY_BYTES + 1)
    if not content or len(content) > MAX_BINARY_BYTES:
        raise InstallError('IAMCTL_ARCHIVE_EXECUTABLE_SIZE_INVALID')
    return content

def _check_installed(path):
    marker = path.parent.parent / 'install-manifest.json'
    if not path.is_file() or not marker.is_file():
        return False
    try:
        info = json.loads(marker.read_text())
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        return info.get('release') == VERSION and info.get('binarySha256') == digest
    except (OSError, ValueError, TypeError):
        return False

def install():
    path = installation_path()
    if _check_installed(path):
        print('IAMCTL_INSTALLED:', path)
        return path
    if path.exists():
        raise InstallError('IAMCTL_UNEXPECTED_EXISTING_BINARY; refuse overwrite; review private tool directory')
    system, arch = platform_key()
    meta = json.loads(read_https(RELEASE_API, {'api.github.com'}, maximum=2_000_000).decode())
    if meta.get('tag_name') != VERSION or meta.get('draft') or meta.get('prerelease'):
        raise InstallError('IAMCTL_RELEASE_NOT_STABLE_PINNED_VERSION')
    asset, selected_arch = select_asset(meta.get('assets') or [],system,arch,True)
    if system == 'darwin' and arch == 'arm64' and selected_arch == 'x64':
        # Apple Silicon cannot run the official 7.3-compatible macOS release
        # without Rosetta. Never attempt a privileged unattended install.
        try:
            probe=subprocess.run(['arch','-x86_64','/usr/bin/true'],
                                 stdin=subprocess.DEVNULL,capture_output=True,timeout=10)
            if probe.returncode:
                raise InstallError('IAMCTL_ROSETTA_REQUIRED: run softwareupdate --install-rosetta --agree-to-license, then retry')
        except (OSError,subprocess.TimeoutExpired) as exc:
            raise InstallError('IAMCTL_ROSETTA_REQUIRED: run softwareupdate --install-rosetta --agree-to-license, then retry') from exc

    url = str(asset.get('browser_download_url') or '')
    if _hostname(url) != 'github.com' or not url.startswith(f'https://github.com/{REPO}/releases/download/{VERSION}/'):
        raise InstallError('IAMCTL_RELEASE_ASSET_URL_UNTRUSTED')
    digest = expected_digest(asset)
    raw = read_https(url, {'github.com','release-assets.githubusercontent.com','objects.githubusercontent.com'})
    actual = hashlib.sha256(raw).hexdigest()
    if actual != digest:
        raise InstallError('IAMCTL_ARCHIVE_CHECKSUM_MISMATCH')
    binary = _archive_entries(raw,asset['name'].lower())
    path.parent.mkdir(parents=True,exist_ok=True,mode=0o700)
    fd, name = tempfile.mkstemp(prefix='.iamctl-',dir=path.parent)
    try:
        with os.fdopen(fd,'wb') as stream:
            stream.write(binary)
        os.chmod(name,0o700)
        os.replace(name,path)
        marker = path.parent.parent/'install-manifest.json'
        marker.write_text(json.dumps({'release':VERSION,'assetName':asset['name'],
            'assetSha256':actual,'binarySha256':hashlib.sha256(binary).hexdigest(),
            'os':system,'arch':selected_arch},indent=2)+'\n')
        os.chmod(marker,0o600)
    finally:
        if os.path.exists(name):
            os.unlink(name)
    # Check that it starts before declaring it installed.
    try:
        result=subprocess.run([str(path),'-h'],stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,
                              stderr=subprocess.PIPE,text=True,timeout=20)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise InstallError(f'IAMCTL_BINARY_START_FAILED: {exc}') from exc
    if result.returncode != 0:
        raise InstallError(f'IAMCTL_BINARY_HELP_FAILED exit={result.returncode}')
    print('IAMCTL_INSTALLED:',path)
    return path

def initialize():
    binary=install()
    names=['serverConfig.json','toolConfig.json','keywordConfig.json']
    env=CONFIG/'configs/env'
    if all((env/n).is_file() for n in names):
        print('IAMCTL_CONFIG_ALREADY_PRESENT:',env)
        return
    if any((env/n).exists() for n in names):
        raise InstallError('IAMCTL_PARTIAL_CONFIG_REFUSE_OVERWRITE')
    CONFIG.mkdir(parents=True,exist_ok=True,mode=0o700)
    oldmask=os.umask(0o077)
    try:
        subprocess.run([str(binary),'setupCLI'],cwd=CONFIG,check=True,
                       stdin=subprocess.DEVNULL,timeout=90)
    except (OSError,subprocess.CalledProcessError,subprocess.TimeoutExpired) as exc:
        raise InstallError(f'IAMCTL_SETUP_FAILED: {type(exc).__name__}') from exc
    finally:
        os.umask(oldmask)
    if not all((env/n).is_file() for n in names):
        raise InstallError('IAMCTL_SETUP_MISSING_EXPECTED_CONFIG_FILES')
    for n in names:
        os.chmod(env/n,0o600)
    print('IAMCTL_PRIVATE_CONFIG_INITIALIZED:',env)

def main():
    action=sys.argv[1] if len(sys.argv)>1 else 'install'
    if action == 'install': install()
    elif action == 'init': initialize()
    elif action == 'path':
        path=installation_path()
        if not _check_installed(path):
            raise InstallError('IAMCTL_NOT_INSTALLED: run ./wso2-lab.sh iamctl-install')
        print(path)
    else:
        raise InstallError(f'IAMCTL_UNKNOWN_ACTION_{action}')

if __name__=='__main__':
    try:
        main()
    except (InstallError,json.JSONDecodeError) as exc:
        print(f'LAB_ERROR: {exc}',file=sys.stderr)
        sys.exit(1)
