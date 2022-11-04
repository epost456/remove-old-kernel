#!/usr/bin/env python3
import argparse
import logging
import os
import re
import rpm
import shutil
import subprocess
import sys


DEBUG = False


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


def get_freediskspace(partition: str) -> int:
    logger = logging.getLogger(__name__)

    total, used, free = shutil.disk_usage(partition)

    logger.debug("Total: {} MiB".format(total // (2**20)))
    logger.debug("Used: {} MiB".format(used // (2**20)))
    logger.debug("Free: {} MiB".format(free // (2**20)))

    return free // (2**20)


def get_oldkernels() -> list:
    logger = logging.getLogger(__name__)
    allkernels = []
    oldkernels = []

    cur = os.uname()[2]
    m = re.match("([0-9\.-]+)\.el", cur)
    if not m:
        return oldkernels

    curkernel = m.groups()[0]
    logger.debug(f"Current kernel: {curkernel}")

    ts = rpm.TransactionSet()
    mi = ts.dbMatch()
    for package in mi:
        if package["name"] == "kernel":
            version = "%s-%s" % (package["version"], package["release"])
            allkernels.append(version)

    for version in sorted(allkernels):
        m = re.match("([0-9\.-]+)\.el", version)
        if m.groups()[0] != curkernel:
            oldkernels.append(m.groups()[0])
        else:
            break

    return oldkernels


def main():
    global DEBUG
    deletekernels = []

    args = parseargs()
    if args.debug:
        DEBUG = True
    logger = get_logger(args.debug)

    free = get_freediskspace("/boot")
    if free > 100 and not DEBUG:
        logger.info(f"OK: Enough space on /boot ({free} MiB)")
        exit(0)

    oldkernels = get_oldkernels()
    logger.debug(f"Old kernels: {oldkernels}")
    if len(oldkernels) <= 1:
        logger.info("OK: No old kernels found to delete, keeping at least one old version")
        exit(0)

    deletekernels = oldkernels.sort()[:-2]
    logger.warning(f"Delete kernels: {deletekernels}")

    for version in deletekernels:
        logger.debug("Deleting kernel {version}")
        if not DEBUG:
            pass
            #subprocess.run(f"rpm -qa | grep {version} | xargs yum remove -y --", shell=True, timeout=60, encoding="utf-8", check=True)


if __name__ == "__main__":
    main()

