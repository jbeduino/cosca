from datetime import datetime
import json
from scanner import Scanner
from common.target_type import TargetType


class CustomScanner(Scanner):
    """ Kics (https://github.com/Checkmarx/kics) for Combo Scanner """
    NAME = "kics"
    DOCKER_IMAGE = "checkmarx/kics:latest"
    DEFECTDOJO_IMPORT_FORMAT = "KICS Scan"
    REPORT_FILENAME = f"scan_results_{NAME}_{datetime.now().strftime('%y%m%d%H%M%S')}.json"
    CONTAINER_TARGET_DIRECTORY = "/src"
    CONTAINER_REPORT_DIRECTORY = "/tmp"
    ACCEPTED_TARGET_TYPES = [TargetType.DIRECTORY]

    def scan(self, target, working_dir, outputs, network):
        self.logger.info("Starting to scan target: %s", target)
        command=f"scan -p {self.CONTAINER_TARGET_DIRECTORY} \
            --output-path {self.CONTAINER_REPORT_DIRECTORY} \
            --output-name {self.REPORT_FILENAME}"
        volumes={target: {'bind': self.CONTAINER_TARGET_DIRECTORY, 'mode': 'rw'},
            working_dir: {'bind': self.CONTAINER_REPORT_DIRECTORY, 'mode': 'rw'}}
        logs=self.run_container(self.DOCKER_IMAGE, command, volumes)
        host_report_path = f"{working_dir}/{self.REPORT_FILENAME}"
        self.report_path = host_report_path
        self.logger.debug("Custom scanning completed.")
        self.logger.info("Scan report generated: %s", host_report_path)
        output_files=[]
        for o in outputs:
            o.process_stdout(logs)
            output_files.append(o.process_files(host_report_path,target,self.NAME,self.get_aux_args()))
        return output_files


    def get_findings_count(self,json_file):
        severity_index={"INFO":0,"LOW":1,"MEDIUM":2,"HIGH":3,"CRITICAL":4,"TRACE":5}
        findings_count=[0,0,0,0,0,0]
        with open(json_file, 'r', encoding='utf-8') as file:
            data = json.load(file)
        for q in data["queries"]:
            i=severity_index[q["severity"]]
            findings_count[i]=findings_count[i]+1*len(q["files"])
        return findings_count


    def get_aux_args(self):
        return {'defectdojo_format': self.DEFECTDOJO_IMPORT_FORMAT,
                'json_findings': self.get_findings_count(self.report_path)
                }