MacFIT is a tool to download and install macOS software.  Some of its features:

* Download and install app bundles from DMG files, zip files
* Install macOS installer packages (pkg files)
* Install preference panes and Mail.app plug-ins ("mail bundles")
* Scrape HTML or GitHub releases to find the file to download
* Get download URLs from [Homebrew casks](https://brew.sh)
* Install into /Applications, ~/Applications, or arbitrary other directories
* Can check signatures on bundles, DMG files, and installer packages via `spctl` (part of [Gatekeeper](https://en.wikipedia.org/wiki/Gatekeeper_(macOS)) as far as I know)
* Can check hashes (automatically happens with `--cask`)

I used this as part of the automated setup of my macOS Mojave install.  **However, I've since switched to mostly installing things via Homebrew casks, which is _probably_ less likely to break and _probably_ a bit more secure.**  I am still using this for installing Mail.app plug-ins, though.

MacFIT is a Python 3 program.  It doesn't use any libraries outside of the standard library.

```
$ ./macfit.py --help
usage: macfit.py [-h] [--debug] [--owner OWNER]
                 [--install REGEXP | --run-installer NAME ARGS | --run-bundle NAME]
                 [--check-signature REGEXP] [--check-dmg-signature REGEXP]
                 [--check-pkg-signature REGEXP]
                 [--check-bundle-signature REGEXP] [--check-hash TYPE:HASH]
                 [--dest DST_DIR | --dest-system | --dest-user] [--cache PATH]
                 [--name DOWNLOAD_NAME]
                 [--cask | --github REGEXP | --scrape-html REGEXP]
                 [--user-agent USER_AGENT] [--agree-eulas]
                 what_to_install

positional arguments:
  what_to_install       May be a local path, URL, Cask name (with --cask),
                        GitHub user/repo (with --github), or URL to scrape
                        (with --scrape-html).

optional arguments:
  -h, --help            show this help message and exit
  --debug, -d           Output lots of extra information about what the tool
                        is doing.
  --owner OWNER         Owner for the installed applications. Ignored when
                        installing an Installer package.
  --install REGEXP, -i REGEXP
                        Regexp for bundle or Installer pkg file to install
                        within extracted files. May be specified multiple
                        times.
  --run-installer NAME ARGS, -r NAME ARGS
                        Run an installer from one of the extracted directories
                        or mounted volumes. PATH must be a relative path,
                        though it may be relative to any directory within the
                        install files (though not within a bundle). If PATH is
                        found while extracting and traversing the install
                        location, it will be run. All other candidates for
                        installation (bundles, packages) will be ignored. ARGS
                        must be either the empty string, or else a JSON array
                        which gives a list of string arguments to call the
                        installer with.
  --run-bundle NAME, -R NAME
                        Run a bundle from one of the extracted directories or
                        mounted volumes. PATH must be a relative path, though
                        it may be relative to any directory within the install
                        files (though not within a bundle). If PATH is found
                        while extracting and traversing the install location,
                        it will be run. All other candidates for installation
                        (bundles, packages) will be ignored.
  --check-signature REGEXP, -C REGEXP
                        All DMG files, installer packages, and bundles (app
                        bundles, preference panes, Mail bundles) must have a
                        valid signature from an originator matching REGEXP, as
                        output by spctl. REGEXP may also be the string
                        "valid", in which case any valid signature will be
                        accepted.
  --check-dmg-signature REGEXP
                        Like --check-signature, but only applies to DMG files.
  --check-pkg-signature REGEXP
                        Like --check-signature, but only applies to installer
                        packages.
  --check-bundle-signature REGEXP
                        Like --check-signature, but only applies to app
                        bundles, preference panes, and mail bundles.
  --check-hash TYPE:HASH
                        Check the downloaded or supplied file's hash matches
                        the argument before proceeding to use it. TYPE must be
                        a hash type supported by your Python installation,
                        such as sha256 (always supported by Python). HASH
                        should be in hex.
  --dest DST_DIR        Directory where bundles will be installed. Ignored
                        when installing an Installer package. Defaults to
                        /Applications when run as root, otherwise
                        ~/Applications.
  --dest-system         Install into system directory.
  --dest-user           Install into user home directory.
  --cache PATH, -c PATH
                        Directory or file to download to. If PATH is a
                        directory, the file will be downloaded into the
                        directory. Otherwise, the file will be downloaded as
                        PATH. However, if PATH ends with a slash, PATH will be
                        unconditionally interpreted as a directory.
                        Directories will be created if they do not already
                        exist.
  --name DOWNLOAD_NAME, -n DOWNLOAD_NAME
                        Name of the downloaded file. If not given, will be
                        inferred from the URL, or from the server response.
                        Ignored when installing a local file.
  --cask                The given install location is the name of a Homebrew
                        Cask. Retrieve the URL (and do signature checks) as
                        specified in the Cask's description. This ONLY reads
                        the URL (and hash) from Homebrew, NOTHING else.
  --github REGEXP       Download latest release from GitHub repo. In this
                        case, what_to_install is the name of a GitHub repo,
                        such as robertklep/quotefixformac. The REGEXP is to
                        match a download name from the latest tagged release.
  --scrape-html REGEXP  what_to_install is a URL to an HTML page where we will
                        look for an <a href"..." where the href matches
                        REGEXP. The first matching URL scraped is the thing to
                        be downloaded and installed (as if that URL, instead,
                        were provided for what_to_install.
  --user-agent USER_AGENT, -U USER_AGENT
                        User agent to send with HTTP requests.
  --agree-eulas         Agree to any and all EULAs when mounting a DMG.
```
