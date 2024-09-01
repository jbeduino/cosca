import os
import sys
from datetime import datetime
import docker
from scanner import Scanner
import json

class CustomScanner(Scanner):
    """ 
    Trivy (https://github.com/aquasecurity/trivy) scanner for Combo Scanner 
    """
    NAME = "trivy"
    DOCKER_IMAGE = "aquasec/trivy"
    DEFECTDOJO_IMPORT_FORMAT = "Trivy"
    SEVERITY_INDEX={"INFO":1,"LOW":1,"MEDIUM":2,"HIGH":3,"CRITICAL":4,"UNKNOWN":5}
    REPORT_FILENAME = f"scan_results_{NAME}_{datetime.now().strftime('%y%m%d%H%M%S')}.json"
    CONTAINER_REPORT_DIRECTORY = "/tmp"
    CONTAINER_REPORT_PATH = f"{CONTAINER_REPORT_DIRECTORY}/{REPORT_FILENAME}"
    # HOST_REPORT_DIRECTORY = f"{os.path.expanduser('~')}/.sympho/output_{NAME}"
    # HOST_REPORT_PATH = f"{HOST_REPORT_DIRECTORY}/{REPORT_FILENAME}"

    def __init__(self):
        super().__init__(self.NAME, self.DOCKER_IMAGE)
        self.report_path = ""

    def scan(self, target, working_dir, outputs):
        target_id=super().get_target_id(target)
        self.logger.info("Starting to scan target: %s (ID: %s)", target, target_id)
        # generate txt output
        # client = docker.from_env()
        # container = client.containers.run(
        #     self.DOCKER_IMAGE,
        #     command=f"image --format table {target} ",
        #     volumes={self.HOST_REPORT_DIRECTORY: {
        #         'bind': self.CONTAINER_REPORT_DIRECTORY, 'mode': 'rw'}},
        #     detach=True,
        #     stdout=True,
        #     stderr=True
        # )
        # container.wait()
        # logs = container.logs()
        # container.remove()
        # print(logs.decode("utf-8"))
        command=f"image --format table {target} "
        volumes={working_dir: {
                'bind': self.CONTAINER_REPORT_DIRECTORY, 'mode': 'rw'}}
        logs=self.run_container(self.DOCKER_IMAGE, command, volumes)
        for o in outputs:
            o.process_stdout(logs)
        # generate json file output
        # self.logger.info("Generating out file...")
        # client = docker.from_env()
        # container = client.containers.run(
        #     self.DOCKER_IMAGE,
        #     command=f"image --format json {target}",
        #     volumes={self.HOST_REPORT_DIRECTORY: {
        #         'bind': self.CONTAINER_REPORT_DIRECTORY, 'mode': 'rw'}},
        #     detach=True,
        #     stdout=True,
        #     stderr=True
        # )
        # container.wait()
        # logs = container.logs()
        # container.remove()
        command=f"image --quiet --format json {target}"
        volumes={working_dir: {
                'bind': self.CONTAINER_REPORT_DIRECTORY, 'mode': 'rw'}}
        logs=self.run_container(self.DOCKER_IMAGE, command, volumes)
        report_filename=f"{datetime.now().strftime('%y%m%d%H%M%S')}_{self.NAME}_{target_id}.json"
        host_report_path = f"{working_dir}/{report_filename}"
        self.report_path = host_report_path

        try:
            with open(f'{host_report_path}', 'w', encoding='utf-8') as f:
                f.write(logs)
        except (FileNotFoundError, PermissionError):
            self.logger.error(
                "Could't create output file in host %s", host_report_path)
            sys.exit(1)
        self.logger.debug("Custom scan completed.")
        self.logger.debug("Temporary scan report generated: %s", host_report_path)
        for o in outputs:
            o.process_files(host_report_path,target,self.NAME,self.get_aux_args())
        return f"{host_report_path}"

    def get_findings_count(self, json_file):
        findings_count=[0,0,0,0,0,0]
        with open(json_file, 'r', encoding='utf-8') as file:
            data = json.load(file)
        for r in data["Results"]:
            try:
                if "Vulnerabilities" in r:
                    for v in r["Vulnerabilities"]:
                        i=self.SEVERITY_INDEX[v["Severity"]]
                        findings_count[i]=findings_count[i]+1
                if "Secrets" in r:
                    for s in r["Secrets"]:
                        i=self.SEVERITY_INDEX[s["Severity"]]
                        findings_count[i]=findings_count[i]+1
            except KeyError as e:
                self.logger.error("Error reading severity from json: %s", e)
        return findings_count

    def get_aux_args(self):
        return {'defectdojo_format': self.DEFECTDOJO_IMPORT_FORMAT,
                'json_findings': self.get_findings_count(self.report_path)
                }