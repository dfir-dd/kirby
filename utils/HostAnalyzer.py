import os
import shutil
import sys
import traceback

from flow.record.adapter.csvfile import CsvfileWriter
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
    
    def __init__(self, targets: str, output:str, overwrite: bool = False):
        super(HostAnalyzer, self).__init__()
        self.__overwrite = overwrite
        self.__targets = targets
        self.__output_directory = output
        self.__PLUGINS = [
            # antivirus
            #("defender", "evtx"), => unsightly output -> better with evtx2bodyfile/mactime2
            "mcafee",
            "sophos",
            ("symantec", "logs"),
            ("trendmicro" , "wflogs"),
            # browser history
            ("edge", "history"),
            ("chrome", "history"),
            ("firefox", "history"),
            ("iexplore", "history"),
            # remoteaccess
            ("anydesk", "logs"), 
            ("teamviewer", "logs"),
            # powershell
            "powershell_history", 
        ]
        # self.__PLUGINS = [
        #     "amcache_install",
        #     "adpolicy",
        #     "sophos",
        #     "mcafee",
        #     "trendmicro",
        #     #"symantec" # => Error
        #     #("defender", "evtx"), => unsightly output -> better with evtx2bodyfile/mactime2
        #     ("anydesk", "logs"), 
        #     ("teamviewer", "logs"), 
        #     "powershell_history",
        #     "prefetch",
        #     "runkeys",
        #     "usb",
        #     "users",
        #     "userassist",
        #     "firewall",
        #     "adpolicy",
        #     "shimcache",
        #     # "evtx", # => unsightly output -> better with evtx2bodyfile/mactime2
        #     "muicache",
        #     # "user_details", # SEGV
        #     "activitiescache",
        #     "bam",
        #     "services",
        #     "shellbags",
        #     "shimcache",
        #     "startupinfo",
        #     "tasks",
        #     "trusteddocs",
        #     ("edge", "history"),
        #     ("chrome", "history"),
        #     ("firefox", "history"),
        #     ("iexplore", "history"),
        #     ##"lnk", # => Error
        #     ## "mft", # => unsightly output -> better with mft2bodyfile/mactime2
        #     ##"wer", # https://github.com/fox-it/acquire/pull/66
        #     ##"usnjrnl" # takes a lot of time
        # ]

        
    # will enumerate all targets and create hostinfo as well as invoke all plugins for each target     
    def analyze_targets(self):
        filename = "hostinfo.csv"
        writer = CsvfileWriter(os.path.join(self.__output_directory, filename),
                               exclude=["_generated", "_source", "_classification", "_version"])

        try:
            for i, target in enumerate(Target.open_all(self.__targets)):
                try:
                    self.__dst_dir = self.__create_destination_directory(target)
                    record = InfoRecord(**get_target_info(target), _target=target)
                    writer.write(record)
                    self.write_target_info(target)
                    self.invoke_plugins(target)
                except Exception as e:
                    target.log.error(f"Exception in retrieving information for target: `%s`.: {e}", target)
        except TargetError as e:
            logger().error(e)


    def invoke_plugins(self, target: Target):
        for plugin in self.__PLUGINS:
            self.invoke_plugin(target, plugin)


    def invoke_plugin(self, target, plugin):
        try:
            filename = plugin
            if isinstance(plugin, tuple):
                filename = "_".join(plugin)
                for p in plugin[:-1]:
                    target = getattr(target, p)
                plugin = plugin[-1]

            assert isinstance(plugin, str)
            records = getattr(target, plugin)()
            self.write_csv(filename, records)
            logger().info(f"run of {plugin} was successful")
        except UnsupportedPluginError as e:
            logger().warning(f"{plugin}: {e.root_cause_str()}")
        except Exception:
            tb_str = traceback.format_exc()
            logger().error(f"{plugin}: An unexpected error occurred:\r\n {tb_str}")


    def write_csv(self, filename, records):
        if not filename.endswith(".csv"):
            filename += ".csv"

        writer = CsvfileWriter(os.path.join(self.__output_directory, self.__dst_dir, filename),
                               exclude=["hostname", "domain", "_generated", "_source", "_classification", "_version"])

        for entry in records:
            #logger().info(f"Enty {entry} in Records {records}")
            writer.write(entry)


    def __create_destination_directory(self, target: Target):
        logger().info(f"found image with hostname '{target.hostname}'; creating target directory for it")
        dst = os.path.join(self.__output_directory, target.hostname)
        if os.path.exists(dst):
            if self.__overwrite:
                logger().info(f"target directory '{dst}' exists already, deleting it")
                shutil.rmtree(dst)
            else:
                logger().error(f"target directory '{dst}' exists already, exiting")
                sys.exit(1)
        os.makedirs(dst)
        return dst


    def write_target_info(self, target: Target):
        
        try:
            record = InfoRecord(**get_target_info(target), _target=target)
            filename = "hostinfo_" + target.hostname + ".csv"
            writer = CsvfileWriter(os.path.join(self.__output_directory, self.__dst_dir, filename),
                               exclude=["_generated", "_source", "_classification", "_version"])
            writer.write(record)
        except Exception as e:
            logger().error(e)

