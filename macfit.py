#!/usr/bin/env python

from __future__ import (
    absolute_import,
    division,
    print_function,
    unicode_literals,
)

from HTMLParser import HTMLParser
import argparse
import cgi
import hashlib
import json
import logging as _logging
import os
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

logger = _logging.getLogger("macfit")


def is_url(string):
    return re.search(r"(?i)^[a-z]+://", string)


def create_file(path):
    fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY)
    return os.fdopen(fd, "wb")


def get_url_path_base_name(url):
    return posixpath.basename(urlparse.urlparse(url).path)


# Homebrew uses ditto (and mkbom and ugh) to copy apps.  rsync from
# MacPorts is the only utility tested by Backup Bouncer[1] that passes
# all tests (ditto fails two; I was testing on macOS 10.13), but I
# don't want to depend on MacPorts.  macOS's built-in rsync fails more
# tests than its built-in tar.  tar and ditto both fail the same two
# tests (one of which is file creation time BTW).  tar is easier to
# use, so that's what I'm using.
#
# [1]: https://github.com/n8gray/Backup-Bouncer
def copy_with_tar(src, dst_dir):
    src_dir, src_name = os.path.split(src.rstrip("/"))
    assert src_name
    src_tar_cmd = [
        "/usr/bin/tar",
        "-cf",
        "-",
        "-C",
        src_dir or ".",
        "--",
        src_name,
    ]
    logger.debug("Source tar command: %r", src_tar_cmd)
    src_tar = subprocess.Popen(src_tar_cmd, stdout=subprocess.PIPE)
    if not os.path.isdir(dst_dir):
        os.makedirs(dst_dir)
    # "-k" to prevent tar from overwriting anything---that should
    # never happen.
    dst_tar_cmd = [
        "/usr/bin/tar",
        "-xpk",
        "--preserve",
        "-f",
        "-",
        "-C",
        dst_dir,
    ]
    dst_tar = subprocess.Popen(dst_tar_cmd, stdin=src_tar.stdout)
    dst_tar.wait()
    src_tar.wait()
    if dst_tar.returncode != 0 or src_tar.returncode != 0:
        raise Exception(
            "tar failed (src=%r dst=%r)"
            % (src_tar.returncode, dst_tar.returncode)
        )


def change_owner(path, uid, gid):
    logger.debug("Setting ownership of %r to %d:%d", path, uid, gid)
    subprocess.check_call(["chown", "-R", "%d:%d" % (uid, gid), path])


def chmod_recursive(path, mode="u+rwX,og+rX,og-w"):
    logger.debug("Calling chmod -R %r %r", path, mode)
    subprocess.check_call(["chmod", "-R", mode, path])


def is_bundle(path):
    # This is just meant to be a "good enough" test for whether
    # something looks like a macOS app, preference pane, or Mail.app
    # bundle.
    path = path.rstrip("/")
    if re.search(r"(?i)\.(?:app|prefpane|mailbundle)$", path) and os.path.isdir(
        path
    ):
        contents_dir = os.path.join(path, "Contents")
        return os.path.isdir(contents_dir) and os.path.exists(
            os.path.join(contents_dir, "Info.plist")
        )
    return False


def open_url(url, user_agent=None):
    # I preferred urllib2 to urllib here because it raises a nice
    # error on e.g. HTTP 404.
    headers = {"Accept": "*/*"}
    if user_agent:
        headers["User-Agent"] = user_agent
    logger.debug("Fetching URL %r", url)
    request = urllib2.Request(url, headers=headers)
    return urllib2.urlopen(request)


TYPE_DMG = "dmg"
TYPE_PKG = "pkg"
TYPE_BUNDLE = "bundle"


class Installer(object):
    def __init__(
        self,
        download_cache_dir=None,
        user_agent=None,
        agree_eulas=None,
        dir_handler=None,
        install_predicate=None,
        dst_dir=None,
        owner=None,
        check_dmg_signature=None,
        check_pkg_signature=None,
        check_bundle_signature=None,
    ):
        self.download_cache_dir = download_cache_dir
        self.user_agent = user_agent
        self.agree_eulas = agree_eulas
        self.dir_handler = dir_handler
        self.install_predicate = install_predicate or (
            lambda _installer, _path: True
        )
        if dst_dir is None:
            if os.getuid() == 0:
                dst_dir = DST_DIR_SYSTEM
            else:
                dst_dir = DST_DIR_USER
        self.dst_dir = dst_dir
        logger.debug("Destination directory is %r", dst_dir)
        if owner:
            pwent = pwd.getpwnam(owner)
            self.owner_uid = pwent.pw_uid
            self.owner_gid = pwent.pw_gid
        else:
            self.owner_uid = None
            self.owner_gid = None
        self.check_dmg_signature = check_dmg_signature
        self.check_pkg_signature = check_pkg_signature
        self.check_bundle_signature = check_bundle_signature
        self._clean_ups = []
        self._dev_null = open(os.devnull, "wb")
        self._add_clean_up(self._dev_null.close)
        self._temp_dir = tempfile.mkdtemp()
        logger.debug("Temp directory is %r", self._temp_dir)
        self._add_clean_up(shutil.rmtree, self._temp_dir, ignore_errors=True)

    def _add_clean_up(self, func, *args, **kwargs):
        self._clean_ups.append((func, args, kwargs))

    def clean_up(self, raise_exceptions=None):
        while self._clean_ups:
            try:
                func, args, kwargs = self._clean_ups.pop()
                func(*args, **kwargs)
            except Exception:
                if raise_exceptions:
                    raise
                else:
                    logger.exception(
                        "Ignoring exception from clean-up %r(*%r, **%r)",
                        func,
                        args,
                        kwargs,
                    )

    def __enter__(self):
        return self

    def __exit__(self, _exc_type, _exc_value, _traceback):
        self.clean_up()

    @property
    def _should_set_owner(self):
        return self.owner_uid is not None

    def _dst_dir_for_bundle(self, extension):
        assert extension.startswith(".")
        dst_dir = self.dst_dir
        if dst_dir in (DST_DIR_SYSTEM, DST_DIR_USER):
            if extension == ".app":
                dst_dir = "/Applications"
            elif extension == ".prefpane":
                dst_dir = "/Library/PreferencePanes"
            elif extension == ".mailbundle":
                dst_dir = "/Library/Mail/Bundles"
            else:
                raise Exception(
                    "Unsupported bundle extension %r" % (extension,)
                )
            if self.dst_dir == DST_DIR_USER:
                assert dst_dir.startswith("/")
                dst_dir = os.path.expanduser("~%s" % (dst_dir,))
        return dst_dir

    def install_from_url(self, url, download_name=None, check_hash=None):
        logger.debug("Installing from URL %r", url)
        if self.download_cache_dir:
            cache_file_name = download_name or get_url_path_base_name(url)
            if cache_file_name:
                cache_path = os.path.join(
                    self.download_cache_dir, cache_file_name
                )
                logger.debug("Looking for cache at %r", cache_path)
                if os.path.exists(cache_path):
                    logger.info("Using cached %r", cache_path)
                    return self.install_from_path(
                        cache_path, check_hash=check_hash
                    )
        logger.info("Downloading %r", url)
        response = open_url(url, user_agent=self.user_agent)
        if self.download_cache_dir:
            download_dir = self.download_cache_dir
            download_name = cache_file_name
        else:
            download_dir = tempfile.mkdtemp(dir=self._temp_dir)
        if not download_name:
            # Code for reading Content-Disposition courtesy
            # https://stackoverflow.com/a/11783319.
            _, params = cgi.parse_header(
                response.headers.get("Content-Disposition", "")
            )
            download_name = params.get("filename")
        if not download_name:
            # If we followed a redirect, maybe the final URL has a better
            # base name than the original URL.
            download_name = get_url_path_base_name(response.geturl())
        if not download_name:
            download_name = get_url_path_base_name(url)
        if not download_name:
            raise Exception("Can't figure out a file name for %r" % (url,))
        software_path = os.path.join(download_dir, download_name)
        logger.debug("Will download to %r", software_path)
        if not os.path.isdir(download_dir):
            # XXX Error not setting owner/perms here?  See
            # self._should_set_owner.
            os.makedirs(download_dir)
        with create_file(software_path) as download:
            shutil.copyfileobj(response, download)
        response.close()
        if download_dir == self.download_cache_dir and self._should_set_owner:
            logger.debug(
                "Chowning cached download to %d:%d",
                self.owner_uid,
                self.owner_gid,
            )
            os.chown(software_path, self.owner_uid, self.owner_gid)
        return self.install_from_path(software_path, check_hash=check_hash)

    def install_from_path(self, path, check_hash=None):
        logger.debug("Visiting %r", path)
        if os.path.isfile(path):
            return self.install_from_file(path, check_hash=check_hash)
        if check_hash:
            raise Exception("Cannot check hash of non-file %r" % (path,))
        if is_bundle(path):
            return self.install_bundle(path)
        if not os.path.isdir(path):
            return []
        if self.dir_handler:
            should_traverse, installed = self.dir_handler(self, path)
            if not isinstance(installed, list):
                installed = list(installed)
            if not should_traverse:
                return installed
        else:
            installed = []
        try:
            children = os.listdir(path)
        except os.error, ex:
            # OK!
            logger.warn(
                "Ignoring exception trying to list %r: %s: %s",
                path,
                ex.__class__.__name__,
                ex,
            )
            return []
        for child in children:
            child_path = os.path.join(path, child)
            if os.path.islink(child_path):
                # Ignore
                pass
            elif os.path.isfile(child_path):
                installed.extend(self.install_from_file(child_path))
            elif os.path.isdir(child_path):
                if child.lower() == "__macosx":
                    logger.debug(
                        "Ignoring %r (probably resource forks from a zip file)",
                        child_path,
                    )
                elif is_bundle(child_path):
                    installed.extend(self.install_bundle(child_path))
                else:
                    installed.extend(self.install_from_path(child_path))
        return installed

    def install_from_file(self, path, check_hash=None):
        if check_hash:
            hash_type, expected_hash = check_hash.split(":", 1)
            hash_type = hash_type.lower()
            hash_obj = hashlib.new(hash_type)
            with open(path, "rb") as the_file:
                while True:
                    # 16 KiB is good enough for shutil.copyfileobj, so
                    # it's good enough for me.
                    chunk = the_file.read(16384)
                    if not chunk:
                        break
                    hash_obj.update(chunk)
            actual_hash = hash_obj.hexdigest()
            if actual_hash != expected_hash:
                raise Exception(
                    (
                        "%s hash for %r is %r, does not match expected hash %r"
                        % (hash_type, path, actual_hash, expected_hash)
                    )
                )
            logger.debug("Hash check on %r passed", path)
        match = re.search(r"(?i)\.(dmg|pkg|zip|tar(?:\.(?:z|gz|bz2?))?)$", path)
        if match:
            # Extra split here to lob compression suffixes off tarballs.
            ext = match.group(1).split(".")[0].lower()
            method = getattr(self, "install_from_%s" % (ext,))
            return method(path)
        else:
            return []

    def _add_hdiutil_detach_clean_up(self, mount_point):
        self._add_clean_up(
            subprocess.check_call,
            ["hdiutil", "detach", mount_point],
            stdout=self._dev_null,
        )

    def _check_signature(self, file_path, file_type):
        if file_type == TYPE_DMG:
            assessment_type = "open"
            check_signature = self.check_dmg_signature
        elif file_type == TYPE_PKG:
            assessment_type = "install"
            check_signature = self.check_pkg_signature
        elif file_type == TYPE_BUNDLE:
            assessment_type = "execute"
            check_signature = self.check_bundle_signature
        else:
            raise Exception("Unknown file_type %r" % (file_type,))
        if not check_signature:
            logger.debug("No signature check requested for %r", file_path)
            return
        logger.debug("Checking signature for %r", file_path)
        try:
            stdout = subprocess.check_output(
                [
                    "spctl",
                    "-a",
                    "-t",
                    assessment_type,
                    # I think this is only necessary for testing DMG
                    # files, but it seems harmless for the other
                    # purposes as well.
                    "--context",
                    "context:primary-signature",
                    "--raw",
                    "-vv",
                    file_path,
                ],
                stderr=self._dev_null,
            )
        except subprocess.CalledProcessError:
            raise Exception(
                "Failed to verify signature on %r (spctl failed)" % (file_path,)
            )
        result = plistlib.readPlistFromString(stdout)
        if not result.get("assessment:verdict"):
            raise Exception(
                "spctl did not report a true verdict for %r" % (file_path,)
            )
        if callable(check_signature):
            originator = result.get("assessment:originator", "")
            logger.debug(
                "Calling signature checker for originator: %r", originator
            )
            check_signature(file_path, file_type, originator)
        logger.debug("Signature check passed")

    def install_from_dmg(self, path):
        self._check_signature(path, TYPE_DMG)
        logger.info("Mounting DMG %r", path)
        # "IDME" seems to be something that could happen automatically
        # when mounting a disk image.  I don't think anyone uses it,
        # and it's been disabled by default since forever.  Still, for
        # security reasons, and because Homebrew does it, I explicitly
        # disable it here.
        hdiutil = subprocess.Popen(
            [
                "hdiutil",
                "attach",
                "-plist",
                "-readonly",
                "-noidme",
                "-nobrowse",
                path,
            ],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
        )
        stdout, _ = hdiutil.communicate("qy\n")
        if hdiutil.wait() != 0:
            raise Exception("hdiutil failed (%r)" % (hdiutil.returncode,))
        match = re.search(r"^<\?xml", stdout, re.M)
        plist_xml = stdout[match.start() :]
        plist = plistlib.readPlistFromString(plist_xml)
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
                # Note that, at least on my recent-ish macOS,
                # detaching one mount point detaches the whole DMG, if
                # I'm reading hdiutil(1) correctly.
                self._add_hdiutil_detach_clean_up(mount_point)
            elif not any_device:
                any_device = entity.get("dev-entry")
        if not mount_point:
            if any_device:
                self._add_hdiutil_detach_clean_up(mount_point)
            raise Exception(
                (
                    "Attached disk image but found no mount point"
                    " (image may still be attached in some form)"
                )
            )
        logger.debug("Mounted DMG at %r", mount_point)
        return self.install_from_path(mount_point)

    def install_from_zip(self, path):
        extract_dir = tempfile.mkdtemp(dir=self._temp_dir)
        # Python's ZipFile.extractall doesn't preserve permissions
        # (https://bugs.python.org/issue15795), so we use unzip.
        subprocess.check_call(["/usr/bin/unzip", path, "-d", extract_dir])
        return self.install_from_path(extract_dir)

    def install_from_tar(self, path):
        extract_dir = tempfile.mkdtemp(dir=self._temp_dir)
        # tarfile module is around but I don't know/trust that it
        # preserves all the things tar -p does, so I just use tar.  -k
        # means don't overwrite anything, since that should never be
        # happening here.
        subprocess.check_call(
            ["/usr/bin/tar", "-xkp", "-C", extract_dir, "-f", path]
        )
        return self.install_from_path(extract_dir)

    def install_from_pkg(self, path):
        if not self.install_predicate(self, path):
            return []
        self._check_signature(path, TYPE_PKG)
        logger.info("Calling installer to install %r", path)
        subprocess.check_call(["installer", "-pkg", path, "-target", "/"])
        return [os.path.basename(path)]

    def install_bundle(self, path):
        if not self.install_predicate(self, path):
            return []
        path = path.rstrip("/")
        self._check_signature(path, TYPE_BUNDLE)
        bundle_name = os.path.basename(path)
        ext = os.path.splitext(bundle_name)[1].lower()
        dst_dir = self._dst_dir_for_bundle(ext)
        dst_bundle = os.path.join(dst_dir, bundle_name)
        if os.path.exists(dst_bundle):
            raise Exception(
                "%r already exists, will not overwrite" % (dst_bundle,)
            )
        real_temp_dir = os.path.realpath(self._temp_dir)
        real_bundle_path = os.path.realpath(path)
        can_move = real_bundle_path.startswith(real_temp_dir + os.sep)
        if can_move:
            logger.info("Moving %r to %r", path, dst_bundle)
            shutil.move(path, dst_bundle)
        else:
            logger.info("Copying %r to %r", path, dst_dir)
            copy_with_tar(path, dst_dir)
        if self._should_set_owner:
            change_owner(dst_bundle, self.owner_uid, self.owner_gid)
        chmod_recursive(dst_bundle)
        return [bundle_name]


def install_nothing_predicate(_installer, _path):
    return False


def make_regexp_install_predicate(regexps):
    def regexp_install_predicate(_, path):
        return any(re.search(regexp, path) for regexp in regexps)

    return regexp_install_predicate


def make_dir_handler_to_run_installer(installer_rel_path, installer_args):
    def dir_handler(_, path):
        installer_path = os.path.join(path, installer_rel_path)
        if os.path.isfile(installer_path) and os.access(
            installer_path, os.X_OK
        ):
            subprocess.check_call([installer_path] + installer_args)
            return True, [installer_path]
        return True, []

    return dir_handler


class Sentinel(object):
    def __init__(self, name):
        self.name = name

    def __repr__(self):
        return "<Sentinel %s>" % (self.name,)


DST_DIR_SYSTEM = Sentinel("DST_DIR_SYSTEM")
DST_DIR_USER = Sentinel("DST_DIR_USER")


class ScrapedLink(Exception):
    def __init__(self, url):
        Exception.__init__(self)
        self.url = url


class LinkScraper(HTMLParser):
    def __init__(self, base_url, link_regexp):
        HTMLParser.__init__(self)
        self._base_url = base_url
        self._link_regexp = re.compile(link_regexp)

    def handle_starttag(self, tag, attrs):
        if tag.lower() == "a":
            for name, value in attrs:
                if name.lower() == "href":
                    url = urlparse.urljoin(self._base_url, value)
                    if self._link_regexp.search(url):
                        # Raising an exception seems to be the
                        # best/only way to stop HTMLParser.
                        raise ScrapedLink(url)


def scrape_download_link_in_html(html_url, regexp, user_agent=None):
    scraper = LinkScraper(html_url, regexp)
    logger.debug("Fetching %r for scraping", html_url)
    response = open_url(html_url, user_agent=user_agent)
    data = response.read()
    response.close()
    try:
        scraper.feed(data)
    except ScrapedLink, ex:
        return ex.url
    else:
        raise Exception("No link matching %r on %r" % (regexp, html_url))


def make_signature_checker(regexp):
    def check_signature(file_path, _file_type, originator):
        if not re.search(regexp, originator):
            raise Exception(
                (
                    "Signature originator on %r does not match %r: %r"
                    % (file_path, regexp, originator)
                )
            )

    return check_signature


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
    install_opts = parser.add_mutually_exclusive_group()
    install_opts.add_argument(
        "--install",
        "-i",
        dest="install_regexps",
        action="append",
        default=[],
        metavar="REGEXP",
        help="""\
            Regexp for bundle or Installer pkg file to install within
            extracted files.  May be specified multiple times.""",
    )
    install_opts.add_argument(
        "--run-installer",
        "-r",
        nargs=2,
        metavar=("PATH", "ARGS"),
        help="""\
            Run an installer from one of the extracted directories or
            mounted volumes.  PATH must be a relative path, though it
            may be relative to any directory within the install files
            (though not within a bundle).  If PATH is found while
            extracting and traversing the install location, it will be
            run.  All other candidates for installation (bundles,
            packages) will be ignored.  ARGS must be either the empty
            string, or else a JSON array which gives a list of string
            arguments to call the installer with.""",
    )
    parser.add_argument(
        "--check-signature",
        "-C",
        metavar="REGEXP",
        help="""\
            All DMG files, installer packages, and bundles (app
            bundles, preference panes, Mail bundles) must have a valid
            signature from an originator matching REGEXP, as output by
            spctl.  REGEXP may also be the string \"valid\", in which
            case any valid signature will be accepted.""",
    )
    parser.add_argument(
        "--check-dmg-signature",
        metavar="REGEXP",
        help="Like --check-signature, but only applies to DMG files.",
    )
    parser.add_argument(
        "--check-pkg-signature",
        metavar="REGEXP",
        help="Like --check-signature, but only applies to installer packages.",
    )
    parser.add_argument(
        "--check-bundle-signature",
        metavar="REGEXP",
        help="""\
            Like --check-signature, but only applies to app bundles,
            preference panes, and mail bundles.""",
    )
    parser.add_argument(
        "--check-hash",
        metavar="TYPE:HASH",
        help="""\
            Check the downloaded or supplied file's hash matches the
            argument before proceeding to use it.  TYPE must be a hash
            type supported by your Python installation, such as sha256
            (always supported by Python).  HASH should be in hex.""",
    )
    dest_args = parser.add_mutually_exclusive_group()
    dest_args.add_argument(
        "--dest",
        dest="dst_dir",
        help=(
            "Directory where bundles will be installed."
            "  Ignored when installing an Installer package."
        ),
    )
    dest_args.add_argument(
        "--dest-system",
        dest="dst_dir",
        action="store_const",
        const=DST_DIR_SYSTEM,
        help="Install into system directory.",
    )
    dest_args.add_argument(
        "--dest-user",
        dest="dst_dir",
        action="store_const",
        const=DST_DIR_USER,
        help="Install into user home directory.",
    )
    parser.add_argument(
        "--cache",
        "-c",
        metavar="PATH",
        help="""\
            Directory or file to download to.  If PATH is a directory,
            the file will be downloaded into the directory.
            Otherwise, the file will be downloaded as PATH.  However,
            if PATH ends with a slash, PATH will be unconditionally
            interpreted as a directory.  Directories will be created
            if they do not already exist.""",
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
    download_args = parser.add_mutually_exclusive_group()
    download_args.add_argument(
        "--cask",
        action="store_true",
        default=False,
        help="""\
            The given install location is the name of a Homebrew Cask.
            Retrieve the URL (and do signature checks) as specified in
            the Cask's description.  This ONLY reads the URL (and
            hash) from Homebrew, NOTHING else.""",
    )
    download_args.add_argument("--scrape-html", metavar="REGEXP")
    parser.add_argument(
        "--user-agent", "-U", help="User agent to send with HTTP requests."
    )
    parser.add_argument(
        "--agree-eulas",
        action="store_true",
        default=False,
        help="Agree to any and all EULAs when mounting a DMG.",
    )
    parser.add_argument(
        "what_to_install",
        help="""\
            May be a local path, URL, Cask name (with --cask) or URL
            to scrape (with --scrape-html).""",
    )
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
            cache_dir, download_name = os.path.split(args.cache)
            args.cache_dir = cache_dir or None
            args.download_name = download_name or None
    dir_handler = None
    install_predicate = None
    if args.install_regexps:
        install_predicate = make_regexp_install_predicate(args.install_regexps)
    elif args.run_installer:
        dir_handler = make_dir_handler_to_run_installer(
            args.run_installer[0], json.loads(args.run_installer[1])
        )
        install_predicate = install_nothing_predicate
    if args.check_signature and (
        args.check_dmg_signature
        or args.check_pkg_signature
        or args.check_bundle_signature
    ):
        raise Exception(
            (
                "Cannot use --check-signature with any other"
                " --check-*-signature option"
            )
        )
    for file_type in (TYPE_DMG, TYPE_PKG, TYPE_BUNDLE):
        attr = "check_%s_signature" % (file_type,)
        check_value = args.check_signature or getattr(args, attr)
        if check_value and check_value != "valid":
            check_value = make_signature_checker(check_value)
        setattr(args, attr, check_value)
    if args.scrape_html:
        args.what_to_install = scrape_download_link_in_html(
            args.what_to_install, args.scrape_html, user_agent=args.user_agent
        )
        logger.info("Scraping found URL %r", args.what_to_install)
    elif args.cask:
        if args.check_hash:
            raise Exception(
                (
                    "Cannot use --check-hash with --cask (hash is taken"
                    " from the Cask)"
                )
            )
        cask_name = args.what_to_install
        cask_api_url = "https://formulae.brew.sh/api/cask/%s.json" % (
            cask_name,
        )
        response = open_url(cask_api_url, user_agent=args.user_agent)
        cask = json.load(response)
        response.close()
        args.what_to_install = cask["url"]
        if not re.search(r"^https?://", args.what_to_install):
            raise Exception(
                (
                    "URL for Cask %r does not look like a URL: %r"
                    % (cask_name, args.what_to_install)
                )
            )
        args.check_hash = "sha256:%s" % (cask["sha256"],)
    with Installer(
        download_cache_dir=args.cache_dir,
        user_agent=args.user_agent,
        agree_eulas=args.agree_eulas,
        dir_handler=dir_handler,
        install_predicate=install_predicate,
        dst_dir=args.dst_dir,
        owner=args.owner,
        check_dmg_signature=args.check_dmg_signature,
        check_pkg_signature=args.check_pkg_signature,
        check_bundle_signature=args.check_bundle_signature,
    ) as installer:
        if is_url(args.what_to_install):
            installed = installer.install_from_url(
                args.what_to_install,
                download_name=args.download_name,
                check_hash=args.check_hash,
            )
        else:
            installed = installer.install_from_path(
                args.what_to_install, check_hash=args.check_hash
            )
    if not installed:
        raise Exception("Failed to install anything")


if __name__ == "__main__":
    sys.exit(main(sys.argv) or 0)
