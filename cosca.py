import logging
import json
import os
import sys
import tempfile
import argparse
import importlib
import docker
from docker.errors import DockerException
from common.logging_setup import setup_logger
from common.target_type import TargetType


class Cosca:

    def __init__(self):
        self.args = self.parse_args()
        self.log_level = logging.WARNING if self.args.quiet else (
            logging.DEBUG if self.args.verbose else logging.INFO)
        self.logger = setup_logger(__name__, 1, level=self.log_level)
        if not self.is_docker_daemon_running():
            self.logger.error("Docker daemon is not running. Please start docker daemon and run cosca again.")
            sys.exit(1)

    def parse_args(self):
        self.parser = argparse.ArgumentParser(
            description="Scan targets based on their types.")
        self.parser.add_argument(
            "-c", "--combo", help="Name of the combo of scanners to execute. Combos are defined in combo.json", default="custom1")
        self.parser.add_argument("-t", "--target", nargs='+', help="Space separated targets to scan. Could be folders, urls, github repos, docker images",
                                 default=["https://ginandjuice.shop"])
                                #  default=["/home/jose/vulnerables/ffufme-main"])
                                #  default=["/home/jose/vulnerables/WebGoat-main"])
                                #  default=["https://github.com/trufflesecurity/test_keys"])
        self.parser.add_argument("-o", "--output", nargs='+',
                                 help=f"Specify outputs. Separate more than one option with spaces. Options: {' '.join(self.get_filenames('output_handlers'))}", default=["pdf", "zip", "defectdojo"])
        log_group = self.parser.add_mutually_exclusive_group()
        log_group.add_argument('-q', '--quiet', action='store_true',
                               help='Run in quiet mode (only shows json minimal output)', default=False)
        log_group.add_argument('-v', '--verbose', action='store_true',
                               help='Run in verbose mode (debugging output)', default=True)
        log_group.add_argument('-f', '--force_pull', action='store_true',
                               help='Force docker to pull the scanner images from the registry before running the scanners. This ensures that the latest version of the scanners are being are being used. It may also avoid to use tampered images that may reside in the local docker daemon.', default=True)
        
        
        args = self.parser.parse_args()
        return args

    def get_combo_mappings(self, combo):
        file_path = "combos.json"
        try:
            with open(file_path, 'r', encoding='utf-8') as file:
                data = json.load(file)
            for c in data["combos"]:
                if c["name"] == combo:
                    mappings = {}
                    for t in c["mappings"]:
                        mappings[t["type"]] = t["scanners"]
                    return mappings
        except json.JSONDecodeError as e:
            self.logger.error("JSONDecodeError: %s", e)
        except FileNotFoundError as e:
            self.logger.error("FileNotFoundError: %s", e)
        self.logger.error(
            "Combo %s not found in %s. Please verify combo name.", combo, file_path)
        sys.exit(1)

    def trigger_scans(self, target, combo, working_dir, outputs):
        mappings = self.get_combo_mappings(combo)
        reports = []
        self.logger.info("Combo: %s", combo)
        for i_target, t in enumerate(target):
            self.logger.info(
                "Scanning target #%d out of %d", i_target+1, len(target))
            target_type = TargetType.get_target_type(t)
            self.logger.info("Target: %s", t)
            self.logger.info("Target type: %s", target_type.value)
            self.logger.info("Working directory: %s", working_dir)
            for index, scanner in enumerate(mappings[target_type.value]):
                self.logger.info(
                    "Running scanner #%d out of %d", index+1, len(mappings[target_type.value]))
                try:
                    self.logger.info("Scanner: %s", scanner)
                    scanner_sub_dir = os.path.join(working_dir, scanner)
                    os.makedirs(scanner_sub_dir)
                    try:
                        module = importlib.import_module(f"scanners.{scanner}")
                    except ModuleNotFoundError:
                        self.logger.error(
                            "Scanner module scanners.%s not found. Please implement a class inherited from Scanner in scanners/%s.py", scanner, scanner)
                        sys.exit(1)
                    cls = getattr(module, "CustomScanner")
                    instance = cls(log_level=self.log_level)
                    output_details = instance.scan(t, scanner_sub_dir, outputs)
                    aux_args = instance.get_aux_args()
                    reports.append({"output": output_details,
                                    "target": t,
                                    "target_id": instance.get_target_id(t),
                                    "scanner": scanner,
                                    "aux_args": aux_args
                                    })
                except (AttributeError, ModuleNotFoundError) as e:
                    self.logger.error("Error while invoking scanner: %s", e)
                    sys.exit(1)
        return reports

    def get_filenames(self, folder_name):
        filenames = []
        for filename in os.listdir(folder_name):
            if os.path.isfile(os.path.join(folder_name, filename)):
                filenames.append(os.path.splitext(filename)[0])
        return filenames

    def main(self):
        outputs = []
        for output in self.args.output:
            try:
                module = importlib.import_module(f"output_handlers.{output}")
            except ModuleNotFoundError:
                self.logger.error(
                    "Output module output_handlers.%s not found. Please implement a class inherited from OutputHandler in output_handlers/%s.py", output, output)
                sys.exit(1)
            cls = getattr(module, "CustomOutputHandler")
            instance = cls(output, self.parser, self.log_level)
            outputs.append(instance)
        with tempfile.TemporaryDirectory(prefix="cosca_") as tmp_dir:
            json_summary = self.trigger_scans(
                self.args.target, self.args.combo, tmp_dir, outputs)
            if self.args.quiet:
                print(json.dumps(json_summary))
            self.logger.debug(json_summary)

    def is_docker_daemon_running(self):
        try:
            client = docker.from_env()
            client.ping()
            return True
        except DockerException:
            return False

if __name__ == '__main__':
    app = Cosca()
    app.main()
