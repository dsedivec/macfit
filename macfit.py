#!/usr/bin/env python

from __future__ import (
    absolute_import,
    division,
    print_function,
    unicode_literals,
)

import argparse
import cgi
import errno
import logging as _logging
import multiprocessing
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

TIMEOUT = 30


logger = _logging.getLogger("macfit")


def is_url(path):
    return re.search(r"(?i)^[a-z]+://", path)


def executor_loop(pipe):
    while True:
        f, args, kwargs = pipe.recv()
        if f is None:
            break
        try:
            result = f(*args, **kwargs)
        except Exception as ex:
            pipe.send((False, ex))
        else:
            pipe.send((True, result))


def make_executor_subprocess(context):
    theirs, ours = multiprocessing.Pipe()
    process = multiprocessing.Process(target=executor_loop, args=(theirs,))
    process.start()

    def clean_up_executor():
        if process.is_alive():
            logger.debug("Closing down privileged executor")
            # I bet this could block, and hence a bug.
            ours.send((None, None, None))
            process.join(TIMEOUT)
            if process.is_alive():
                process.terminate()

    context.add_clean_up(clean_up_executor)

    def run_in_executor(f, *args, **kwargs):
        ours.send((f, args, kwargs))
        succeeded, result = ours.recv()
        if succeeded:
            return result
        else:
            raise result

    return run_in_executor


def is_privileged():
    # I have a bad feeling that this line of code may indicate I do
    # not know what I'm doing with this foot cannon I'm holding.
    return os.getuid() == 0 or os.geteuid() == 0


def drop_privileges(user_name):
    # I arrived at this implementation after reading man pages and
    # numerous other sources, in particular:
    #
    # Stevens's APUE 3rd, section 8.11 "Changing User IDs and Group
    # IDs" (has a great diagram)
    #
    # _Secure Programming Cookbook for C and C++_ by Matt Messier, John Viega
    # Section 1.3: Dropping Privileges in setuid Programs
    # https://www.oreilly.com/library/view/secure-programming-cookbook/0596003943/ch01s03.html
    #
    # DJB's daemontools sources, particular setuidgid.c and prot.c
    # https://github.com/daemontools/daemontools/blob/master/src/
    #
    # _Setuid Demystified_ by Hao Chen, David Wagner, and Drew Dean
    # http://www.cs.umd.edu/~jkatz/TEACHING/comp_sec_F04/downloads/setuid.pdf
    #
    # "POS37-C. Ensure that privilege relinquishment is successful"
    # https://wiki.sei.cmu.edu/confluence/display/c/POS37-C.+Ensure+that+privilege+relinquishment+is+successful
    assert is_privileged()
    pwent = pwd.getpwnam(user_name)
    if not isinstance(pwent.pw_gid, int) or pwent.pw_gid == 0:
        raise Exception(
            "Couldn't find non-root group ID for user %r (got %r)"
            % (user_name, pwent.pw_gid)
        )
    os.setgroups([pwent.pw_gid])
    os.setregid(pwent.pw_gid, pwent.pw_gid)
    os.setreuid(pwent.pw_uid, pwent.pw_uid)
    for uid_func in (os.seteuid, os.setuid):
        try:
            uid_func(0)
        except os.error as ex:
            if ex.errno != errno.EPERM:
                raise Exception(
                    (
                        "Dropping privileges raised %r, not the expected EPERM"
                        % (ex.errno,)
                    )
                )
        else:
            raise Exception(
                "Failed to drop privileges (tested %r)" % (uid_func,)
            )


class Context(object):
    def __init__(self):
        self.app_dir = None
        self.privileged_exec = None
        self.software_path = None
        self._clean_ups = []
        self.dev_null = open(os.devnull, "wb")
        self.add_clean_up(self.dev_null.close)
        self.temp_dir = tempfile.mkdtemp()
        logger.debug("Temp directory is %r", self.temp_dir)
        self.add_clean_up(shutil.rmtree, self.temp_dir, ignore_errors=True)

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
            except Exception as ex:
                print(
                    (
                        "Ignoring exception from clean-up %r: %s: %s"
                        % (elem, ex.__class__.__name__, ex)
                    ),
                    file=sys.stderr,
                )
        self._clean_ups = []


def download_software_from_url(download_dir, url):
    # I preferred urllib2 to urllib here because it raises a
    # nice error on e.g. HTTP 404.
    response = urllib2.urlopen(url)
    # Code for reading Content-Disposition courtesy
    # https://stackoverflow.com/a/11783319.
    _, params = cgi.parse_header(
        response.headers.get("Content-Disposition", "")
    )
    file_name = params.get("filename")
    if not file_name:
        url_parsed = urlparse.urlparse(url)
        file_name = posixpath.basename(url_parsed.path)
    if not file_name:
        raise Exception("Can't figure out a file name for %r" % (url,))
    software_path = os.path.join(download_dir, file_name)
    with open(software_path, "wb") as download:
        shutil.copyfileobj(response, download)
    response.close()
    return software_path


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


def install_dmg(context):
    logger.debug("Mounting DMG")
    plist = plistlib.readPlistFromString(
        subprocess.check_output(
            # IDME seems to be something that could happen
            # automatically when mounting a disk image.  I don't think
            # anyone uses it, and it's been disabled by default since
            # forever.  Still, for security reasons, and because
            # Homebrew does it, I explicitly disable it here.
            [
                "hdiutil",
                "attach",
                "-plist",
                "-readonly",
                "-noidme",
                context.software_path,
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
            # Note that, on any recent macOS, detaching one mount
            # point should detach the whole DMG, if I'm reading
            # hdiutil(1) correctly.
            context.add_hdiutil_detach_clean_up(mount_point)
        elif not any_device:
            any_device = entity.get("dev-entry")
    if not mount_point:
        if any_device:
            context.add_hdiutil_detach_clean_up(mount_point)
        raise Exception(
            (
                "Attached disk image but found no mount point"
                " (image may still be attached in some form)"
            )
        )
    logger.debug("Mounted DMG at %r", mount_point)
    apps = []
    for item in os.listdir(mount_point):
        if item.lower().endswith(".app"):
            full_item_path = os.path.join(mount_point, item)
            if os.path.isdir(full_item_path):
                apps.append(item)
    if len(apps) != 1:
        raise Exception("Expected a single app bundle, found: %r" % (apps,))
    dst_app = os.path.join(context.app_dir, apps[0])
    if os.path.exists(dst_app):
        raise Exception("%r already exists" % (dst_app,))
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
    if not os.path.isdir(context.app_dir):
        logger.debug("Making application directory %r", context.app_dir)
        context.privileged_exec(os.mkdir, context.app_dir)
    logger.debug(
        "Copying %r from %r to %r", apps[0], mount_point, context.app_dir
    )
    context.privileged_exec(
        copy_with_tar, apps[0], mount_point, context.app_dir
    )
    logger.debug("Setting ownership of %r", dst_app)
    context.privileged_exec(
        subprocess.check_call,
        ["chown", "-R", "%d:%d" % (os.getuid(), os.getgid()), dst_app],
    )


def install_software(url_or_path, user=None, app_names=None, app_dir=None):
    if sys.version_info.major == 2 and (
        sys.version_info.minor < 7 or sys.version_info.micro < 9
    ):
        raise Exception(
            "Python too old, cannot securely use https, please upgrade"
        )
    context = Context()
    try:
        if is_privileged():
            if not user:
                raise Exception(
                    "Must provide unprivileged user name when running as root"
                )
            logger.debug("Making privileged executor")
            privileged_exec = make_executor_subprocess(context)
            logger.debug("Dropping privileges")
            drop_privileges(user)
        else:
            privileged_exec = lambda f, *args, **kwargs: f(*args, **kwargs)
        context.privileged_exec = privileged_exec
        if app_dir:
            context.app_dir = app_dir
        else:
            context.app_dir = os.path.expanduser("~/Applications")
        logger.debug("Applications directory is %r", context.app_dir)
        if is_url(url_or_path):
            logger.debug("Downloading %r", url_or_path)
            software_path = download_software_from_url(
                context.temp_dir, url_or_path
            )
        else:
            logger.debug("Using on-disk %r", url_or_path)
            software_path = url_or_path
        context.software_path = software_path
        extension = os.path.splitext(context.software_path)[1].lower()
        if extension == ".dmg":
            install_dmg(context)
        elif extension == ".pkg":
            logger.debug(
                "Calling installer as root to install %r", context.software_path
            )
            context.privileged_exec(
                subprocess.check_call,
                ["installer", "-pkg", software_path, "-target", "/"],
            )
        else:
            raise Exception("Don't know how to install %r" % (software_path,))
    finally:
        context.run_clean_ups()


def main(argv):
    _logging.basicConfig()
    parser = argparse.ArgumentParser(prog=argv[0])
    parser.add_argument("--debug", "-d", action="store_true", default=False)
    parser.add_argument("--verbose", "-v", action="store_true", default=False)
    parser.add_argument("--user", "-u")
    parser.add_argument(
        "--app-name",
        "-a",
        dest="app_names",
        action="append",
        default=[],
        help=(
            "Name of app bundle to install."
            "  May be specified multiple times."
            "  Ignored when installing an Installer package."
        ),
    )
    app_dir_args = parser.add_mutually_exclusive_group()
    app_dir_args.add_argument("--app-dir")
    app_dir_args.add_argument(
        "--system",
        dest="app_dir",
        action="store_const",
        const="/Applications",
        help="Install into /Applications",
    )
    parser.add_argument("url_or_path")
    args = parser.parse_args(argv[1:])
    if args.debug:
        logger.setLevel(_logging.DEBUG)
    elif args.verbose:
        logger.setLevel(_logging.INFO)
    install_software(
        args.url_or_path,
        user=args.user,
        app_names=args.app_names,
        app_dir=args.app_dir,
    )


if __name__ == "__main__":
    sys.exit(main(sys.argv) or 0)
