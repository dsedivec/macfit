#!/usr/bin/env python

from __future__ import (
    absolute_import,
    division,
    print_function,
    unicode_literals,
)

import argparse
import cgi
import logging as _logging
import os.path
import plistlib
import posixpath
import pwd
import re
import shutil
import subprocess
import sys
import tempfile
import urllib2
import urlparse
import zipfile

logger = _logging.getLogger("macfit")


def is_url(path):
    return re.search(r"(?i)^[a-z]+://", path)


class InstallOperation(object):
    def __init__(
        self,
        cache_dir=None,
        download_name=None,
        app_names=None,
        dst_dir=None,
        owner=None,
    ):
        self.cache_dir = cache_dir
        self.download_name = download_name
        self.app_names = app_names or []
        if dst_dir is None:
            if os.getuid() == 0:
                dst_dir = "/Applications"
            else:
                dst_dir = os.path.expanduser("~/Applications")
        logger.debug("Destination directory is %r", dst_dir)
        self.dst_dir = dst_dir
        if owner:
            pwent = pwd.getpwnam(owner)
            self.owner_uid = pwent.pw_uid
            self.owner_gid = pwent.pw_gid
        else:
            self.owner_uid = None
            self.owner_gid = None
        self.software_path = None
        self._clean_ups = []
        self.dev_null = open(os.devnull, "wb")
        self.add_clean_up(self.dev_null.close)
        self.temp_dir = tempfile.mkdtemp()
        logger.debug("Temp directory is %r", self.temp_dir)
        self.add_clean_up(shutil.rmtree, self.temp_dir, ignore_errors=True)

    @property
    def should_set_owner(self):
        return self.owner_uid is not None

    def add_clean_up(self, func, *args, **kwargs):
        self._clean_ups.append((func, args, kwargs))

    def add_hdiutil_detach_clean_up(self, path):
        self.add_clean_up(
            subprocess.check_call,
            ["hdiutil", "detach", path],
            stdout=self.dev_null,
        )

    def run_clean_ups(self):
        for elem in reversed(self._clean_ups):
            try:
                func, args, kwargs = elem
                func(*args, **kwargs)
            except Exception:
                logger.exception("Ignoring exception from clean-up %r", elem)
        self._clean_ups = []


def create_file(path):
    fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY)
    return os.fdopen(fd, "wb")


def get_url_path_base_name(url):
    return posixpath.basename(urlparse.urlparse(url).path)


def maybe_download_software_from_url(install_op, url):
    assert not install_op.software_path
    if install_op.cache_dir:
        cache_file_name = install_op.download_name or get_url_path_base_name(
            url
        )
        if cache_file_name:
            cache_path = os.path.join(install_op.cache_dir, cache_file_name)
            if os.path.exists(cache_path):
                logger.debug("Using cached %r", cache_path)
                install_op.software_path = cache_path
                return
    logger.debug("Downloading %r", url)
    # I preferred urllib2 to urllib here because it raises a
    # nice error on e.g. HTTP 404.
    response = urllib2.urlopen(url)
    if not install_op.download_name:
        # Code for reading Content-Disposition courtesy
        # https://stackoverflow.com/a/11783319.
        _, params = cgi.parse_header(
            response.headers.get("Content-Disposition", "")
        )
        install_op.download_name = params.get("filename")
    if not install_op.download_name:
        install_op.download_name = get_url_path_base_name(url)
    if not install_op.download_name:
        raise Exception("Can't figure out a file name for %r" % (url,))
    install_op.software_path = os.path.join(
        install_op.cache_dir or install_op.temp_dir, install_op.download_name
    )
    logger.debug("Will download to %r", install_op.software_path)
    with create_file(install_op.software_path) as download:
        shutil.copyfileobj(response, download)
    response.close()
    if install_op.cache_dir and install_op.should_set_owner:
        logger.debug(
            "Chowning cached download to %d:%d",
            install_op.owner_uid,
            install_op.owner_gid,
        )
        os.chown(
            install_op.software_path, install_op.owner_uid, install_op.owner_gid
        )


def copy_with_tar(item, src_dir, dst_dir):
    src_tar = subprocess.Popen(
        ["/usr/bin/tar", "-cf", "-", "-C", src_dir, "--", item],
        stdout=subprocess.PIPE,
    )
    dst_tar = subprocess.Popen(
        # Copying this command line exactly as Backup Bouncer has it.
        # "-xpf" would probably work just fine, I bet.  "-k" is added,
        # though, to prevent tar from overwriting anything---that
        # should never happen.
        ["/usr/bin/tar", "-xk", "--preserve", "-f", "-", "-C", dst_dir],
        stdin=src_tar.stdout,
    )
    dst_tar.wait()
    src_tar.wait()
    if dst_tar.returncode != 0 or src_tar.returncode != 0:
        raise Exception(
            "tar failed (src=%r dst=%r)"
            % (src_tar.returncode, dst_tar.returncode)
        )


def mount_dmg(install_op, dmg_path=None):
    if dmg_path is None:
        dmg_path = install_op.software_path
    logger.debug("Mounting DMG %r", dmg_path)
    plist = plistlib.readPlistFromString(
        subprocess.check_output(
            # IDME seems to be something that could happen
            # automatically when mounting a disk image.  I don't think
            # anyone uses it, and it's been disabled by default since
            # forever.  Still, for security reasons, and because
            # Homebrew does it, I explicitly disable it here.
            ["hdiutil", "attach", "-plist", "-readonly", "-noidme", dmg_path]
        )
    )
    any_device = None
    mount_point = None
    for entity in plist["system-entities"]:
        if "mount-point" in entity:
            if mount_point:
                raise Exception(
                    (
                        "I don't know what to do with DMG that has"
                        " multiple mount points"
                    )
                )
            mount_point = entity["mount-point"]
            # Note that, on any recent macOS, detaching one mount
            # point should detach the whole DMG, if I'm reading
            # hdiutil(1) correctly.
            install_op.add_hdiutil_detach_clean_up(mount_point)
        elif not any_device:
            any_device = entity.get("dev-entry")
    if not mount_point:
        if any_device:
            install_op.add_hdiutil_detach_clean_up(mount_point)
        raise Exception(
            (
                "Attached disk image but found no mount point"
                " (image may still be attached in some form)"
            )
        )
    logger.debug("Mounted DMG at %r", mount_point)
    return mount_point


def copy_app_bundle(app_name, src_dir, dst_dir):
    dst_app = os.path.join(dst_dir, app_name)
    logger.debug("Destination for app bundle is %r", dst_app)
    # Homebrew uses ditto (and mkbom and ugh) to copy apps.  rsync
    # from MacPorts is the only utility tested by Backup
    # Bouncer[1] that passes all tests (ditto fails two; I was
    # testing on macOS 10.13), but I don't want to depend on
    # MacPorts.  macOS's built-in rsync fails more tests than its
    # built-in tar.  tar and ditto both fail the same two tests
    # (one of which is file creation time BTW).  tar is easier to
    # use.
    #
    # [1]: https://github.com/n8gray/Backup-Bouncer
    if not os.path.isdir(dst_dir):
        logger.debug("Making application directory %r", dst_dir)
        os.mkdir(dst_dir)
    logger.debug("Copying %r from %r to %r", app_name, src_dir, dst_dir)
    copy_with_tar(app_name, src_dir, dst_dir)
    return dst_app


def change_owner(path, uid, gid):
    logger.debug("Setting ownership of %r to %d:%d", path, uid, gid)
    subprocess.check_call(["chown", "-R", "%d:%d" % (uid, gid), path])


def chmod_recursive(path, mode="u+rwX,og+rX,og-w"):
    logger.debug("Calling chmod -R %r %r", path, mode)
    subprocess.check_call(["chmod", "-R", mode, path])


def is_app_bundle(path):
    # This is just meant to be a "good enough" test for whether
    # something looks like a macOS app bundle.
    path = path.rstrip("/")
    if path.lower().endswith(".app") and os.path.isdir(path):
        contents_dir = os.path.join(path, "Contents")
        return os.path.isdir(contents_dir) and os.path.exists(
            os.path.join(contents_dir, "Info.plist")
        )
    return False


def find_app_bundles_in_dir(install_op, path):
    if install_op.app_names:
        missing_apps = []
        for name in install_op.app_names:
            if not os.path.exists(os.path.join(path, name)):
                missing_apps.append(name)
        if missing_apps:
            raise Exception("Missing app bundles: %r" % (missing_apps,))
        apps = install_op.app_names
    else:
        apps = []
        for item in os.listdir(path):
            if is_app_bundle(os.path.join(path, item)):
                apps.append(item)
    return apps


def ensure_apps_dont_exist(dst_dir, apps):
    existing_apps = []
    for app in apps:
        if os.path.exists(os.path.join(dst_dir, app)):
            existing_apps.append(app)
    if existing_apps:
        raise Exception(
            "Some apps already exist in %r: %r" % (dst_dir, existing_apps)
        )


def install_apps_from_dir(install_op, src_dir, move=None):
    apps = find_app_bundles_in_dir(install_op, src_dir)
    ensure_apps_dont_exist(install_op.dst_dir, apps)
    for app in apps:
        if move:
            dst_app = os.path.join(install_op.dst_dir, app)
            shutil.move(os.path.join(src_dir, app), dst_app)
        else:
            dst_app = copy_app_bundle(app, src_dir, install_op.dst_dir)
        if install_op.should_set_owner:
            change_owner(dst_app, install_op.owner_uid, install_op.owner_gid)
        chmod_recursive(dst_app)


def install_dmg(install_op):
    mount_point = mount_dmg(install_op)
    install_apps_from_dir(install_op, mount_point, move=False)


def install_zip(install_op):
    extract_dir = tempfile.mkdtemp(dir=install_op.temp_dir)
    # We might find that it's better to shell out to /usr/bin/zip to
    # preserve permissions or work around security concerns with zip
    # files?  Not sure.  Note for my future self.
    with zipfile.ZipFile(install_op.software_path, "r") as software_zip:
        software_zip.extractall(extract_dir)
    install_apps_from_dir(install_op, extract_dir, move=True)


def install_tar(install_op):
    extract_dir = tempfile.mkdtemp(dir=install_op.temp_dir)
    # tarfile module is around but I don't know/trust that it
    # preserves all the things tar -p does, so I just use tar.  -k
    # means don't overwrite anything, since that should never be
    # happening here.
    subprocess.check_call(
        [
            "/usr/bin/tar",
            "-xkp",
            "-C",
            extract_dir,
            "-f",
            install_op.software_path,
        ]
    )
    install_apps_from_dir(install_op, extract_dir, move=True)


def install_pkg(install_op):
    logger.debug("Calling installer to install %r", install_op.software_path)
    subprocess.check_call(
        ["installer", "-pkg", install_op.software_path, "-target", "/"]
    )


def install_software(url_or_path, install_op):
    # 2.7.9 is when SSL certs started getting checked (according to
    # the docs).  Also, 2.7.4 is when zipfile module started stripping
    # bad stuff from path names, so that's important too.
    if sys.version_info.major == 2 and (
        sys.version_info.minor < 7
        or (sys.version_info.minor == 7 and sys.version_info.micro < 9)
    ):
        raise Exception(
            "Python too old, cannot securely use https, please upgrade"
        )
    try:
        if is_url(url_or_path):
            maybe_download_software_from_url(install_op, url_or_path)
        else:
            if not os.path.exists(url_or_path):
                raise Exception("%r does not exist" % (url_or_path,))
            logger.debug("Using on-disk %r", url_or_path)
            install_op.software_path = url_or_path
        extension = os.path.splitext(install_op.software_path)[1].lower()
        if extension == ".dmg":
            install_dmg(install_op)
        elif extension == ".zip":
            install_zip(install_op)
        elif re.search(
            r"(?i)\.tar(?:\.(?:Z|gz|bz2))?$", install_op.software_path
        ):
            install_tar(install_op)
        elif extension == ".pkg":
            install_pkg(install_op)
        else:
            raise Exception(
                "Don't know how to install %r" % (install_op.software_path,)
            )
    finally:
        install_op.run_clean_ups()


def main(argv):
    _logging.basicConfig()
    parser = argparse.ArgumentParser(prog=argv[0])
    parser.add_argument("--debug", "-d", action="store_true", default=False)
    parser.add_argument(
        "--owner",
        help=(
            "Owner for the installed applications."
            "  Ignored when installing an Installer package."
        ),
    )
    parser.add_argument(
        "--app-name",
        "-a",
        dest="app_names",
        action="append",
        default=[],
        metavar="NAME",
        help=(
            "Name of app bundle to install within extracted files."
            "  May be specified multiple times."
            "  Ignored when installing an Installer package."
        ),
    )
    app_dir_args = parser.add_mutually_exclusive_group()
    app_dir_args.add_argument(
        "--app-dir",
        help=(
            "Directory where app bundles will be installed."
            "  Ignored when installing an Installer package."
        ),
    )
    app_dir_args.add_argument(
        "--system",
        dest="app_dir",
        action="store_const",
        const="/Applications",
        help="Install into /Applications.",
    )
    parser.add_argument(
        "--cache",
        "-c",
        metavar="PATH",
        help="""\
            Directory or file to download to.  If PATH is a directory,
            the file will be downloaded into the directory.
            Otherwise, the file will be downloaded as PATH.  However,
            if PATH ends with a slash or if --name is also given, PATH
            will be unconditionally interpreted as a directory, and
            the directory will be created if it does not already
            exist.""",
    )
    parser.add_argument(
        "--name",
        "-n",
        dest="download_name",
        help="""\
            Name of the downloaded file.  If not given, will be
            inferred from the URL, or from the server response.
            Ignored when installing a local file.""",
    )
    parser.add_argument("url_or_path")
    parser.set_defaults(cache_dir=None)
    args = parser.parse_args(argv[1:])
    if args.debug:
        logger.setLevel(_logging.DEBUG)
    if args.download_name:
        args.cache_dir = args.cache
    elif args.cache:
        if args.cache.endswith("/") or os.path.isdir(args.cache):
            args.cache_dir = args.cache
        else:
            cache_dir, download_name = os.path.split()
            args.cache_dir = cache_dir or None
            args.download_name = download_name or None
    install_op = InstallOperation(
        cache_dir=args.cache_dir,
        download_name=args.download_name,
        app_names=args.app_names,
        dst_dir=args.app_dir,
        owner=args.owner,
    )
    install_software(args.url_or_path, install_op)


if __name__ == "__main__":
    sys.exit(main(sys.argv) or 0)
