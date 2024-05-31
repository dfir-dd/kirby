import csv
import os
import shutil
import sys
import traceback

from flow.record.adapter.csvfile import CsvfileWriter
from dissect.target import Target
from dissect.target.exceptions import TargetError
from dissect.target.exceptions import UnsupportedPluginError
from dissect.target.helpers.record import TargetRecordDescriptor
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
            # This list does not include all available dissect plugins, ether because they could not be fully tested (lacking of testdata) or lead to errors (see end of list)
            ("defender", "exclusions"),
            ("defender", "quarantine"),
            ("mcafee", "msc"),
            ("sophos", "hitmanlogs"),
            ("sophos", "sophoshomelogs"),
            ("symantec", "firewall"),
            ("symantec", "logs"),
            ("trendmicro" , "wffirewall"),
            ("trendmicro" , "wflogs"),
            ("edge", "history"),
            ("chrome", "history"),
            ("firefox", "history"),
            ("iexplore", "history"),
            ("brave", "history"),
            ("chrome", "downloads"),
            ("edge", "downloads"),
            ("firefox", "downloads"),
            ("iexplore", "downloads"),
            ("brave", "downloads"),
            ("chrome", "extensions"), 
            ("edge", "extensions"),
            ("firefox", "extensions"),
            ("brave", "extensions"),
            ("anydesk", "logs"), 
            ("teamviewer", "logs"),
            "powershell_history",
            ("amcache", "application_files"),
            ("amcache", "applications"),
            ("amcache", "device_containers"),
            ("amcache", "drivers"),
            ("amcache", "shortcuts"),
            ("cim", "consumerbindings"),# plugin needs to be adapted in order to correctly read ActiveScriptConsumer information
            "alternateshell",
            "bootshell",
            ("notifications", "wpndatabase"),
            "prefetch",
            "recyclebin",
            "sevenzip", # the csv output will contain multiple headers, as the plugin produces non valid csv format, however the headers are the same and do not vary, therefore it is still included, maybe use "sort -ru" to work with the resulting csv
            "auditpol",
            "bam",
            ("clsid", "machine"),
            ("clsid", "user"),
            ("mru", "acmru"),
            ("mru", "msoffice"),
            ("mru", "mstsc"),
            ("mru", "networkdrive"),
            ("mru", "recentdocs"),
            ("mru", "run"),
            "network_history",
            "runkeys",
            "shellbags",
            "usb",
            "userassist",
            "sam",
            "services",
            "startupinfo",
            "wer",
        ### The following plugins are not included, as they tend to throw errors or produce invalid csv output format
        #     "amcache_install", # => no valid csv format
        #     "symantec" # => Error
        #     ("defender", "evtx"), => unsightly output -> better with evtx2bodyfile/mactime2
        #     "shimcache", # => no valid csv format in output, some lines are oddly separated
        #      "evtx", # => unsightly output -> better with evtx2bodyfile/mactime2
        #     "muicache", # strange output format
        #     "user_details", # SEGV
        #     "activitiescache", # => unsightly output, sometimes entries are not in valid csv format
        #     "tasks", # => not a valid csv format
        #     "lnk", # => Error
        #     "mft", # => no valid csv format, unsightly output, slow -> better with mft2bodyfile/mactime2
        #     "usnjrnl", # takes a lot of time
        #     "walkfs", # => Throws errors during runtime AttributeError,TypeError
        #     ("etl","boot"), # => not valid csv format
        #     ("etl","etl") # => not valid csv format
        #     ("etl","shutdown") # => not valid csv format
        #     "pfro", # some lines of the input file are not parsed correctly, artifact is also not really relevant
        #     "schdlgu", # => ValueError
        #     ("cit", "dp"), # not valid csv format
        #     "firewall", # not valid csv format
        #     ("mru", "opensave"), # does only check opensave key for Win XP, not modern OpenSavePIDLMRU key
        #     ("mru", "lastvisited"), # does only check lastvisited key for Win XP, not modern LastVisitedPIDLMRU key
        #     ("thumbcache", "iconcache"), # => error
        #     ("thumbcache", "thumbcache"), # => not a valid csv format
        ]


    def analyze_targets(self):
        filename = "hostinfo.csv"
        fieldnames = ['hostname', 'domain', 'last_activity', 'install_date', 'ips', 'os_family', 'os_version', 'architecture', 'language', 'timezone', 'disks', 'volumes', 'children', '_generated', '_source']

        if os.path.isfile(os.path.join(self.__output, filename)) and os.path.getsize(os.path.join(self.__output, filename)) > 0:
            logger().info(f"The file '{os.path.join(self.__output, filename)}' already exists, appending new hostinfo data")
            with open(os.path.join(self.__output, filename), 'a', newline='') as csvfile:
                writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
                self.__enumerate_targets(writer)

        else:                
            with open(os.path.join(self.__output, filename), "w", newline="") as csvfile:
                writer = csv.DictWriter(csvfile, fieldnames=fieldnames, quoting=csv.QUOTE_ALL)
                writer.writeheader()
                self.__enumerate_targets(writer)


    # will enumerate all targets and create hostinfo.csv as well as invoke all plugins for each target
    def __enumerate_targets(self, writer):
        try:
            for target in Target.open_all(self.__targets):
                try:
                    self.__dst_dir = self.__create_destination_directory(target)
                    record = InfoRecord(**get_target_info(target), _target=target)
                    rdict = record._asdict(fields=writer.fieldnames)
                    writer.writerow(rdict)
                    self.__write_target_info(target)
                    self.invoke_plugins(target)
                except Exception as e:
                    logger().error(f"Exception in retrieving information for target: `%s`.: {e}", target)
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

