import os
import argparse
import csv
import sys
import shutil
import coloredlogs, logging

__LOGGER__ = None


def logger():
    global __LOGGER__
    if not __LOGGER__:
        __LOGGER__ = logging.getLogger("kirby")
        coloredlogs.install(level='INFO', logger=__LOGGER__)

    return __LOGGER__


def arguments():
    parser = argparse.ArgumentParser(
        prog="kirby",
        description="parse forensic artifacts from windows images, using dissect"
    )
    parser.add_argument('targets', metavar="TARGETS", nargs="+", help="Path to single target or directory with multiple targets to parse")
    parser.add_argument('-o', '--output', type=str, help='Specify the output directory', required=True)
    parser.add_argument('--overwrite', action='store_true', help='overwrite destination directory')
    parser.add_argument('--dialect',
                        choices=csv.list_dialects(),
                        default='unix',
                        help='select CSV dialect')
    
    args = parser.parse_args()

    return args
