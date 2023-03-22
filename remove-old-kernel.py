#!/usr/bin/env python3
# Requires Python >= 3.6
import argparse
import logging
import os
import re
import shutil
import subprocess
import sys


DEBUG = False

# Check for minimum Python version
if not sys.version_info >= (3, 6):
    print("ERROR: Requires Python 3.6 or higher")
    exit(1)


class LogFilter(logging.Filter):
    def filter(self, record):
        return record.levelno in (logging.DEBUG, logging.WARNING, logging.INFO)


def parseargs():
    """Process command line arguments"""
    parser = argparse.ArgumentParser(description="Remove old kernel packages to free up disk space on /boot ")
    parser.add_argument("-d", "--debug", action="store_true",
        help="generate additional debug information")
    parser.add_argument("-V", "--version", action="version", version="1.0.0")
    return parser.parse_args()


def get_logger(debug: bool = False) -> logging.Logger:
    """Retrieve logging object"""
    logger = logging.getLogger(__name__)

    if debug:
        logger.setLevel(logging.DEBUG)
    else:
        logger.setLevel(logging.INFO)

    h1 = logging.StreamHandler(sys.stdout)
    h1.setLevel(logging.DEBUG)
    h1.setFormatter(logging.Formatter(fmt="%(levelname)s: %(message)s"))
    h1.addFilter(LogFilter())

    h2 = logging.StreamHandler(sys.stdout)
    h2.setFormatter(logging.Formatter(fmt="%(levelname)s: %(message)s"))
    h2.setLevel(logging.ERROR)

    logger.addHandler(h1)
    logger.addHandler(h2)

    return logger


def version_sorted(versions: list) -> list:
    '''Sort kernel versions in ascending order'''

    # Replace hyphens with dots to make kernel version sortable
    versions2 = [v.replace('-', '.') for v in versions]

    # Sort 5 dotted kernel version number
    versions_sorted = sorted(versions2, key=lambda x: [int(y) for y in x.split('.')])

    # Revert back to old hyphen values, but keep new sort order
    for index, vs in enumerate(versions_sorted):
        for v in versions:
            if re.match(vs, v):
                versions_sorted[index] = v

    return versions_sorted


def get_freediskspace(partition: str) -> int:
    '''Return free disk space of partition'''
    logger = logging.getLogger(__name__)

    total, used, free = shutil.disk_usage(partition)

    logger.debug("Total: {} MiB".format(total // (2**20)))
    logger.debug("Used: {} MiB".format(used // (2**20)))
    logger.debug("Free: {} MiB".format(free // (2**20)))

    return free // (2**20)


def get_oldkernels() -> list:
    '''Return a list of all kernel versions older than the current running kernel'''
    logger = logging.getLogger(__name__)
    allkernels = []
    oldkernels = []

    cur = os.uname()[2]
    m = re.match("([0-9\.-]+)\.el", cur)
    if not m:
        return oldkernels

    curkernel = m.groups()[0]
    logger.debug(f"Current kernel: {curkernel}")

    # Get all installed kernels
    cmd = '/bin/rpm -qa name="kernel" --qf "%{NAME};%{VERSION};%{RELEASE}\n"'
    try:
        output = subprocess.run(cmd, timeout=60, encoding="utf-8", check=True, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    except FileNotFoundError as e:
        logger.error(f"Failed to query RPM database: rpm command not found ({e})")
    except subprocess.TimeoutExpired as e:
        logger.error(f"Failed to query RPM database: rpm command timeout expired ({e})")
    except subprocess.CalledProcessError as e:
        logger.error(f"Failed to query RPM database: rpm command returned: {e}")
    else:
        logger.debug(f"rpm command executed successfully ({cmd})")

        for line in output.stdout.splitlines():
            package_name, package_version, package_release = line.split(";", 2)
            package_release = package_release[:package_release.find(".el")]
            if package_name == "kernel":
                version = "{}-{}".format(package_version, package_release)
                logger.debug(f"Found installed kernel {package_name}-{version}")
                allkernels.append(version)

    for version in allkernels:
        logger.debug(f"Checking old kernel version {version} ...")
        m = re.match("([0-9\.-]+)", version)
        if m:
            if m.groups()[0] != curkernel:
                oldkernels.append(m.groups()[0])
        else:
            logger.debug(f"Invalid version string found ({version})")

    return oldkernels


def main():
    ''' Main function'''
    global DEBUG
    deletekernels = []

    # Parse commandline arguments
    args = parseargs()
    if args.debug:
        DEBUG = True
    logger = get_logger(args.debug)

    # Check free diskspace
    free = get_freediskspace("/boot")
    if free > 100 and not DEBUG:
        logger.info(f"OK: Enough space on /boot ({free} MiB)")
        exit(0)

    # Get a list of all old kernels
    oldkernels = get_oldkernels()
    logger.debug(f"Old kernels: {oldkernels}")
    if len(oldkernels) <= 1:
        logger.info("OK: No old kernels found to delete, keeping at least one old version")
        exit(0)

    # Leave at least one old kernel for backup
    logger.debug(f"Sorted old kernels: {version_sorted(oldkernels)}")
    deletekernels = version_sorted(oldkernels)[:-1]
    logger.warning(f"Delete kernels: {deletekernels}")

    # Remove all other old kernel packages
    for version in deletekernels:
        logger.debug(f"Deleting kernel {version} ...")
        if not DEBUG:
            try:
                logger.debug(f"rpm -qa | grep {version} | xargs yum remove -y --")
                subprocess.run(f"rpm -qa | grep {version} | xargs yum remove -y --", shell=True, timeout=60, encoding="utf-8", check=True, stdout=subprocess.PIPE)
            except FileNotFoundError as e:
                logger.error("File not found ({e})")
            except TimeoutExpired as e:
                logger.error("Timeout expired ({e})")
            except subprocess.CalledProcessError as e:
                logger.error(f"Error deleting packages ({e})")


if __name__ == "__main__":
    main()

