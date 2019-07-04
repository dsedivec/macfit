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
    # something looks like a macOS app or preference pane bundle.
    path = path.rstrip("/")
    if re.search(r"(?i)\.(?:app|prefpane)$", path) and os.path.isdir(path):
        contents_dir = os.path.join(path, "Contents")
        return os.path.isdir(contents_dir) and os.path.exists(
            os.path.join(contents_dir, "Info.plist")
        )
    return False


def open_url(url):
    # I preferred urllib2 to urllib here because it raises a nice
    # error on e.g. HTTP 404.  I spoof the UA because I *thought* I
    # needed it, but then it turned out the UA wasn't the problem, but
    # it could be in the future so I just left it here as I'd already
    # written the code.
    request = urllib2.Request(
        url,
        headers={
            "User-Agent": "User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_5) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/75.0.3770.100 Safari/537.36"
        },
    )
    return urllib2.urlopen(request)


class Installer(object):
    def __init__(
        self,
        download_cache_dir=None,
        install_predicate=None,
        dst_dir=None,
        owner=None,
    ):
        self.download_cache_dir = download_cache_dir
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
        self._clean_ups = []
        self.dev_null = open(os.devnull, "wb")
        self._add_clean_up(self.dev_null.close)
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

    @property
    def _dst_dir_application(self):
        if self.dst_dir == DST_DIR_SYSTEM:
            return "/Applications"
        elif self.dst_dir == DST_DIR_USER:
            return os.path.expanduser("~/Applications")
        else:
            return self.dst_dir

    @property
    def _dst_dir_prefpane(self):
        if self.dst_dir == DST_DIR_SYSTEM:
            return "/Library/PreferencePanes"
        elif self.dst_dir == DST_DIR_USER:
            return os.path.expanduser("~/Library/PreferencePanes")
        else:
            return self.dst_dir

    def install_from_url(self, url, download_name=None):
        logger.debug("Installing from URL %r", url)
        if self.download_cache_dir:
            cache_file_name = download_name or get_url_path_base_name(url)
            if cache_file_name:
                cache_path = os.path.join(
                    self.download_cache_dir, cache_file_name
                )
                logger.debug("Looking for cache at %r", cache_path)
                if os.path.exists(cache_path):
                    logger.debug("Using cached %r", cache_path)
                    return self.install_from_path(cache_path)
        logger.debug("Downloading %r", url)
        response = open_url(url)
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
        return self.install_from_path(software_path)

    def install_from_path(self, path):
        logger.debug("Installing from path %r", path)
        if os.path.isfile(path):
            return self.install_from_file(path)
        if is_bundle(path):
            return self.install_bundle(path)
        if not os.path.isdir(path):
            return []
        installed = []
        try:
            children = os.listdir(path)
        except os.error:
            # OK!
            return []
        for child in children:
            child_path = os.path.join(path, child)
            if os.path.islink(child_path):
                continue
            elif os.path.isfile(child_path):
                installed.extend(self.install_from_file(child_path))
            elif os.path.isdir(child_path):
                if is_bundle(child_path):
                    installed.extend(self.install_bundle(child_path))
                else:
                    installed.extend(self.install_from_path(child_path))
        return installed

    def install_from_file(self, path):
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
            stdout=self.dev_null,
        )

    def install_from_dmg(self, path):
        logger.debug("Mounting DMG %r", path)
        plist = plistlib.readPlistFromString(
            subprocess.check_output(
                # "IDME" seems to be something that could happen
                # automatically when mounting a disk image.  I don't
                # think anyone uses it, and it's been disabled by
                # default since forever.  Still, for security reasons,
                # and because Homebrew does it, I explicitly disable
                # it here.
                [
                    "hdiutil",
                    "attach",
                    "-plist",
                    "-readonly",
                    "-noidme",
                    "-nobrowse",
                    path,
                ]
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
        logger.debug("Calling installer to install %r", path)
        subprocess.check_call(["installer", "-pkg", path, "-target", "/"])
        return [os.path.basename(path)]

    def install_bundle(self, path):
        if not self.install_predicate(self, path):
            return []
        path = path.rstrip("/")
        bundle_name = os.path.basename(path)
        ext = os.path.splitext(bundle_name)[1].lower()
        if ext == ".app":
            dst_dir = self._dst_dir_application
        elif ext == ".prefpane":
            dst_dir = self._dst_dir_prefpane
        else:
            raise Exception("Can't figure out where to put %r" % (path,))
        dst_bundle = os.path.join(dst_dir, bundle_name)
        if os.path.exists(dst_bundle):
            raise Exception(
                "%r already exists, will not overwrite" % (dst_bundle,)
            )
        real_temp_dir = os.path.realpath(self._temp_dir)
        real_bundle_path = os.path.realpath(path)
        can_move = real_bundle_path.startswith(real_temp_dir + os.sep)
        if can_move:
            logger.debug("Moving %r to %r", path, dst_bundle)
            shutil.move(path, dst_bundle)
        else:
            copy_with_tar(path, dst_dir)
        if self._should_set_owner:
            change_owner(dst_bundle, self.owner_uid, self.owner_gid)
        chmod_recursive(dst_bundle)
        return [bundle_name]


class Sentinel(object):
    def __init__(self, name):
        self.name = name

    def __repr__(self):
        return "<Sentinel %s>" % (self.name,)


DST_DIR_SYSTEM = Sentinel("DST_DIR_SYSTEM")
DST_DIR_USER = Sentinel("DST_DIR_USER")


class ScrapedLink(Exception):
    def __init__(self, match):
        Exception.__init__(self)
        self.match = match


class LinkScraper(HTMLParser):
    def __init__(self, link_regexp):
        HTMLParser.__init__(self)
        self._link_regexp = re.compile(link_regexp)

    def handle_starttag(self, tag, attrs):
        if tag.lower() == "a":
            for name, value in attrs:
                if name.lower() == "href":
                    match = self._link_regexp.search(value)
                    if match:
                        raise ScrapedLink(match)


def scrape_download_link_in_html(html_url, regexp):
    scraper = LinkScraper(regexp)
    logger.debug("Fetching %r for scraping", html_url)
    response = open_url(html_url)
    data = response.read()
    response.close()
    try:
        scraper.feed(data)
    except ScrapedLink, ex:
        match = ex.match
        named_groups = match.groupdict()
        download_url = named_groups.get("url", match.group(0))
        return urlparse.urljoin(html_url, download_url)
    else:
        raise Exception("No link matching %r on %r" % (regexp, html_url))


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
    parser.add_argument("--scrape-html", metavar="REGEXP")
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
            cache_dir, download_name = os.path.split(args.cache)
            args.cache_dir = cache_dir or None
            args.download_name = download_name or None
    if args.install_regexps:

        def predicate(_, path):
            return any(
                re.search(regexp, path) for regexp in args.install_regexps
            )

    else:
        predicate = None
    if args.scrape_html:
        args.url_or_path = scrape_download_link_in_html(
            args.url_or_path, args.scrape_html
        )
        logger.debug("Scraping found URL %r", args.url_or_path)
    with Installer(
        download_cache_dir=args.cache_dir,
        install_predicate=predicate,
        dst_dir=args.dst_dir,
        owner=args.owner,
    ) as installer:
        if is_url(args.url_or_path):
            installed = installer.install_from_url(
                args.url_or_path, download_name=args.download_name
            )
        else:
            installed = installer.install_from_path(args.url_or_path)
    if not installed:
        raise Exception("Failed to install anything")


if __name__ == "__main__":
    sys.exit(main(sys.argv) or 0)
