import os
import shutil
import sys
import traceback

from flow.record.adapter.csvfile import *
from dissect.target import Target
from dissect.target.exceptions import TargetError
from dissect.target.exceptions import UnsupportedPluginError
from dissect.target.helpers.record import TargetRecordDescriptor
from dissect.target.tools.query import record_output
from dissect.target.tools.info import (
    get_target_info
)

from utils.cli import logger

# changed "ips" type from "net.ipaddress[]" to "strings[]" from original dissect InfoRecord
InfoRecord = TargetRecordDescriptor(
    "target/info",
    [
        ("datetime", "last_activity"),
        ("datetime", "install_date"),
        ("string[]", "ips"),
        ("string", "os_family"),
        ("string", "os_version"),
        ("string", "architecture"),
        ("string[]", "language"),
        ("string", "timezone"),
        ("string[]", "disks"),
        ("string[]", "volumes"),
        ("string[]", "children"),
    ],
)

class HostAnalyzer:
    
    def __init__(self, targets: list, output: str, overwrite: bool = False):
        super(HostAnalyzer, self).__init__()
        
        
        self.__targets = targets
        self.__output = output
        self.__overwrite = overwrite
        self.__PLUGINS = [
            "amcache_install",
            "adpolicy",
            "sophos",
            "mcafee",
            "trendmicro",
            #"symantec" # => Error
            #("defender", "evtx"), => unsightly output -> better with evtx2bodyfile/mactime2
            ("anydesk", "logs"), 
            ("teamviewer", "logs"), 
            "powershell_history",
            "prefetch",
            "runkeys",
            "usb",
            "users",
            "userassist",
            "firewall",
            "adpolicy",
            "shimcache",
            # "evtx", # => unsightly output -> better with evtx2bodyfile/mactime2
            "muicache",
            # "user_details", # SEGV
            "activitiescache",
            "bam",
            "services",
            "shellbags",
            "shimcache",
            "startupinfo",
            "tasks",
            "trusteddocs",
            ("edge", "history"),
            ("chrome", "history"),
            ("firefox", "history"),
            ("iexplore", "history"),
            ##"lnk", # => Error
            ## "mft", # => unsightly output -> better with mft2bodyfile/mactime2
            ##"wer", # https://github.com/fox-it/acquire/pull/66
            ##"usnjrnl" # takes a lot of time
        ]


    def analyze_targets(self):
        filename = "hostinfo.csv"
        helper = "helper.csv"

        if os.path.isfile(os.path.join(self.__output, filename)):
            logger().info(f"The file '{os.path.join(self.__output, filename)}' exists already, appending new hostinfo data")
            reader = CsvfileReader(os.path.join(self.__output, filename))
            records = []
            for record in reader.__iter__():
                records.append(record)

            try:
                """write newly acquired hostinfo data into a helper.csv file before reading and writing it again into the hostinfo. This is necessary to form a uniform record construct from type csv_reader (prevents having multiple csv head lines in the file)"""
                writer_h = CsvfileWriter(os.path.join(self.__output, helper),
                                exclude=["_generated", "_source", "_classification", "_version"])
                self.__enumerate_targets(writer_h)
                writer_h.close()

                reader_h = CsvfileReader(os.path.join(self.__output, helper))
                for record in reader_h.__iter__():
                    records.append(record)

                writer = CsvfileWriter(os.path.join(self.__output, filename),
                                    exclude=["_generated", "_source", "_classification", "_version"])
                for record in records:
                    writer.write(record)
                writer.close()

                # remove helper csv file after 
                if os.path.exists(os.path.join(self.__output, helper)):
                    try:
                        os.remove(os.path.join(self.__output, helper))
                        logger().info(f"File '{os.path.join(self.__output, helper)}' deleted successfully.")
                    except Exception as e:
                        logger().error(f"An error occurred while deleting {os.path.join(self.__output, helper)}: {e}")
                else:
                    logger().error(f"File '{os.path.join(self.__output, helper)}' not found.")
            except TargetError as e:
                    logger().error(e)

        else:                
            writer = CsvfileWriter(os.path.join(self.__output, filename),
                                exclude=["_generated", "_source", "_classification", "_version"])
            self.__enumerate_targets(writer)


    # will enumerate all targets and create hostinfo as well as invoke all plugins for each target
    def __enumerate_targets(self, writer: CsvfileWriter):
        try:
            for target in Target.open_all(self.__targets):
                try:
                    self.__dst_dir = self.__create_destination_directory(target)
                    record = InfoRecord(**get_target_info(target), _target=target)
                    writer.write(record)
                    self.__write_target_info(target)
                    self.__invoke_plugins(target)
                except Exception as e:
                    logger().error(f"Exception in retrieving information for target: `%s`.: {e}", target)
        except TargetError as e:
                logger().error(e)


    def __invoke_plugins(self, target: Target):
        for plugin in self.__PLUGINS:
            self.__invoke_plugin(target, plugin)


    def __invoke_plugin(self, target, plugin):
        try:
            filename = plugin
            if isinstance(plugin, tuple):
                filename = "_".join(plugin)
                for p in plugin[:-1]:
                    target = getattr(target, p)
                plugin = plugin[-1]

            assert isinstance(plugin, str)
            records = getattr(target, plugin)()
            self.__write_csv(filename, records)
            logger().info(f"run of {plugin} was successful")
        except UnsupportedPluginError as e:
            logger().warning(f"{plugin}: {e.root_cause_str()}")
        except Exception:
            tb_str = traceback.format_exc()
            logger().error(f"{plugin}: An unexpected error occurred:\r\n {tb_str}")


    def __write_csv(self, filename, records):
        if not filename.endswith(".csv"):
            filename += ".csv"

        writer = CsvfileWriter(os.path.join(self.__dst_dir, filename),
                               exclude=["hostname", "domain", "_generated", "_source", "_classification", "_version"])

        for entry in records:
            #logger().info(f"Enty {entry} in Records {records}")
            writer.write(entry)


    def __create_destination_directory(self, target: Target):
        logger().info(f"found image with hostname '{target.hostname}'; creating target directory for it")
        dst = os.path.join(self.__output, target.hostname)
        if os.path.exists(dst):
            if self.__overwrite:
                logger().info(f"target directory '{dst}' exists already, deleting it")
                shutil.rmtree(dst)
            else:
                logger().error(f"target directory '{dst}' exists already, exiting")
                sys.exit(1)
        os.makedirs(dst)
        return dst


    def __write_target_info(self, target: Target):
        
        try:
            record = InfoRecord(**get_target_info(target), _target=target)
            filename = f"hostinfo_{target.hostname}.csv"
            writer = CsvfileWriter(os.path.join(self.__dst_dir, filename),
                               exclude=["_generated", "_source", "_classification", "_version"])
            writer.write(record)
        except Exception as e:
            logger().error(e)

