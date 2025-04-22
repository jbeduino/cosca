""" Semgrep (https://semgrep.dev/) for Combo Scanner """
import sys
import json
from datetime import datetime
from scanner import Scanner
from common.target_type import TargetType

class CustomScanner(Scanner):
    """ Semgrep (https://github.com/semgrep/semgrep) for Combo Scanner """
    NAME = "semgrep"
    DOCKER_IMAGE = "semgrep/semgrep"
    DEFECTDOJO_IMPORT_FORMAT = "Semgrep JSON Report"
    CONTAINER_TARGET_DIRECTORY = "/src"
    CONTAINER_REPORT_DIRECTORY = "/tmp"
    ACCEPTED_TARGET_TYPES = [TargetType.DIRECTORY]
    
    # def __init__(self):
    #     super().__init__(self.NAME, self.DOCKER_IMAGE)
    #     self.report_path = ""

    def scan(self, target, working_dir, outputs, network):
        target_id=super().get_target_id(target)
        self.logger.info("Starting to scan target: %s (ID: %s)", target, target_id)
        report_filename=f"{datetime.now().strftime('%y%m%d%H%M%S')}_{self.NAME}_{target_id}.json"
        container_report_path=f"{self.CONTAINER_REPORT_DIRECTORY}/{report_filename}"
        volumes={target: {'bind': self.CONTAINER_TARGET_DIRECTORY, 'mode': 'rw'},
                     working_dir: {'bind': self.CONTAINER_REPORT_DIRECTORY,
                                                  'mode': 'rw'}}
        command=f"semgrep --config auto --text --json-output={container_report_path} \
                {self.CONTAINER_TARGET_DIRECTORY}"
        logs=self.run_container(self.DOCKER_IMAGE, command, volumes, user="semgrep")
        host_report_path = f"{working_dir}/{report_filename}"
        self.report_path = host_report_path
        self.logger.debug("Custom scan completed.")
        self.logger.debug("Temporary scan report generated: %s", host_report_path)
        output_files=[]
        for o in outputs:
            o.process_stdout(logs)
            output_files.append(o.process_files(host_report_path,target,self.NAME,self.get_aux_args()))
        return output_files

    def get_findings_count(self, json_file):
        severity_index={"INFO":0,"LOW":1,"MEDIUM":2,"HIGH":3,"CRITICAL":4,"UNKNOWN":5}
        findings_count=[0,0,0,0,0,0]
        try:
            with open(json_file, 'r', encoding='utf-8') as file:
                data = json.load(file)
            findings = data.get('results', [])
            for f in findings:
                i=severity_index[f["extra"]["metadata"]["impact"]]
                findings_count[i]=findings_count[i]+1
        except (FileNotFoundError, json.JSONDecodeError, KeyError, IOError) as e:
            self.logger.error("An I/O error occurred in get_findings_count function. %s", e)
            sys.exit()
        return findings_count

    def get_aux_args(self):
        return {'defectdojo_format': self.DEFECTDOJO_IMPORT_FORMAT,
                'json_findings': self.get_findings_count(self.report_path)
                }