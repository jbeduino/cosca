import os
import sys
import docker
from scanner import Scanner


class CustomScanner(Scanner):
    """
    Grype (https://github.com/anchore/grype) for 
    cdxgen (https://github.com/CycloneDX/cdxgen) SBOM scanner for Combo Scanner
    """
    NAME = "cdxgen_grype"
    SCANNER_IMAGE = "anchore/grype"
    SBOM_IMAGE = "ghcr.io/cyclonedx/cdxgen"
    DEFECTDOJO_IMPORT_FORMAT = "Anchore Grype"
    SBOM_FILE_NAME = "sbom.json"
    REPORT_FILE_NAME = f"scan_results_{NAME}.json"
    CONTAINER_TARGET_DIRECTORY = "/src"
    HOST_REPORT_DIRECTORY = f"/tmp/sympho/output_{NAME}"
    HOST_REPORT_FILE = f"{HOST_REPORT_DIRECTORY}/{REPORT_FILE_NAME}"
    CONTAINER_REPORT_DIRECTORY = "/tmp"
    CONTAINER_REPORT_FILE = f"{CONTAINER_REPORT_DIRECTORY}/{REPORT_FILE_NAME}"

    def __init__(self):
        super().__init__(self.NAME, self.SCANNER_IMAGE)

    def scan(self, target, working_dir):
        try:
            os.makedirs(self.HOST_REPORT_DIRECTORY, exist_ok=True)
            self.logger.info("Created subdirectories for path: %s",
                             self.HOST_REPORT_DIRECTORY)
        except (FileExistsError, PermissionError, OSError) as e:
            self.logger.error(
                "Exception creating subdirectories for path: %s", self.HOST_REPORT_DIRECTORY)
            self.logger.error(e)
            sys.exit(1)
        self.logger.info("Generating SBOM...")
        sbom_path = f"{self.HOST_REPORT_DIRECTORY}/{self.SBOM_FILE_NAME}"
        client = docker.from_env()
        command = f"-r {self.CONTAINER_TARGET_DIRECTORY} \
        -o {self.CONTAINER_REPORT_DIRECTORY}/{self.SBOM_FILE_NAME} -p"
        container = client.containers.run(
            self.SBOM_IMAGE,
            command,
            volumes={target: {'bind': self.CONTAINER_TARGET_DIRECTORY, 'mode': 'rw'},
                     self.HOST_REPORT_DIRECTORY: {'bind': self.CONTAINER_REPORT_DIRECTORY,
                                                  'mode': 'rw'}},
            detach=True,
            stdout=True,
            stderr=True
        )
        container.wait()
        logs = container.logs()
        container.remove()
        print(logs.decode("utf-8"))
        self.logger.info("Scanning SBOM...")
        report_path = f"{self.HOST_REPORT_DIRECTORY}/{self.REPORT_FILE_NAME}"
        command = f"sbom:{self.CONTAINER_REPORT_DIRECTORY}/{self.SBOM_FILE_NAME} -o table"
        client = docker.from_env()
        container = client.containers.run(
            self.SCANNER_IMAGE,
            command,
            volumes={self.HOST_REPORT_DIRECTORY: {
                'bind': self.CONTAINER_REPORT_DIRECTORY, 'mode': 'rw'}},
            detach=True,
            stdout=True,
            stderr=True
        )
        container.wait()
        logs = container.logs()
        container.remove()
        print(logs.decode("utf-8"))
        self.logger.info("Generating SBOM file...")
        report_path = f"{self.HOST_REPORT_DIRECTORY}/{self.REPORT_FILE_NAME}"
        command = f"sbom:{self.CONTAINER_REPORT_DIRECTORY}/{self.SBOM_FILE_NAME} -o json"
        client = docker.from_env()
        container = client.containers.run(
            self.SCANNER_IMAGE,
            command,
            volumes={self.HOST_REPORT_DIRECTORY: {
                'bind': self.CONTAINER_REPORT_DIRECTORY, 'mode': 'rw'}},
            detach=True,
            stdout=True,
            stderr=True
        )
        container.wait()
        logs = container.logs()
        container.remove()
        try:
            with open(f'{report_path}', 'w', encoding='utf-8') as f:
                f.write(logs.decode("utf-8"))
        except (FileNotFoundError, PermissionError):
            self.logger.error(
                "Could't create output file in host %s", report_path)
            sys.exit(1)
        self.logger.info("Custom scanning completed.")
        self.logger.info("SBOM generated: %s", sbom_path)
        self.logger.info("Scan report generated: %s", report_path)
        return f"{report_path}"
