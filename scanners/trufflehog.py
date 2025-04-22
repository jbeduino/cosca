import os
import os.path
from datetime import datetime
from urllib.parse import urlparse
import sys
import json
import validators
from scanner import Scanner
from common.target_type import TargetType

class CustomScanner(Scanner):
    """ Trufflehog (https://github.com/trufflesecurity/trufflehog) for Combo Scanner """
    NAME = "trufflehog"
    DOCKER_IMAGE = "trufflesecurity/trufflehog:latest"
    DEFECTDOJO_IMPORT_FORMAT = "Trufflehog Scan"
    ACCEPTED_TARGET_TYPES = [TargetType.DIRECTORY, TargetType.GITHUB]
    

    def scan(self, target, working_dir, outputs, network):
        target_id=super().get_target_id(target)
        self.logger.info("Starting to scan target: %s (ID: %s)", target, target_id)
        report_filename=f"{datetime.now().strftime('%y%m%d%H%M%S')}_{self.NAME}_{target_id}.json"

        if validators.url(target) and urlparse(target).netloc == "github.com":
            self.logger.info("Scanning github %s", target)
            command_json = f"github --repo {target} --json",
            command_plain = f"github --repo {target}",
        elif os.path.exists(target):
            self.logger.info("Scanning directory %s", target)
            command_json = f"filesystem {target} --json",
            command_plain = f"github --repo {target}",
        else:
            self.logger.error("Invalid target: %s", target)
            sys.exit(1)
        log_plain=self.run_container(self.DOCKER_IMAGE, command_plain)
        log_json=self.run_container(self.DOCKER_IMAGE, command_json)
        host_report_path = f"{working_dir}/{report_filename}"
        self.report_path = host_report_path
        try:
            log_json = [s for s in log_json.split("\n") if s.startswith('{"SourceMetadata"')]
            with open(host_report_path, 'w', encoding='utf-8') as f:
                for line in log_json:
                    f.write(line + "\n")
        except (FileNotFoundError, PermissionError) as e:
            self.logger.error("Couldn't create output file in host %s/%s. %s",
                              working_dir, report_filename, e)
            sys.exit(1)
        self.logger.debug("Custom scan completed.")
        self.logger.debug("Temporary scan report generated: %s", host_report_path)
        output_files=[]
        for o in outputs:
            o.process_stdout(log_plain)
            output_files.append(o.process_files(host_report_path,target,self.NAME,self.get_aux_args()))
        return output_files

    def get_findings_count(self,json_file):
        severity_index={"False":3,"True":4}
        findings_count=[0,0,0,0,0,0]
        try:
            with open(json_file, 'r', encoding='utf-8') as file:
                lines = file.read().split("\n")
            for line in lines:
                if line.strip():
                    json_line=json.loads(line)
                    i=severity_index[str(json_line["Verified"])]
                    findings_count[i]=findings_count[i]+1
        except (FileNotFoundError, json.JSONDecodeError, KeyError, IOError) as e:
            self.logger.error("An I/O error occurred in get_findings_count function. %s", e)
            sys.exit(1)
        return findings_count

    def get_aux_args(self):
        return {'defectdojo_format': self.DEFECTDOJO_IMPORT_FORMAT,
                'json_findings': self.get_findings_count(self.report_path)
                }
