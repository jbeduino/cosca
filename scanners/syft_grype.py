import docker
from scanner import Scanner


class CustomScanner(Scanner):
    """
    Grype (https://github.com/anchore/grype) for 
    Syft (https://github.com/anchore/syft) SBOM scanner for Combo Scanner
    """
    NAME = "syft_grype"
    SCANNER_IMAGE = "anchore/grype"
    SBOM_IMAGE = "anchore/syft"
    SBOM_FILE_NAME = "sbom.json"
    DEFECTDOJO_IMPORT_FORMAT = "Anchore Grype"
    REPORT_FILE_NAME = f"scan_results_{NAME}.json"
    CONTAINER_TARGET_DIRECTORY = "/src"
    CONTAINER_REPORT_DIRECTORY = "/tmp"
    CONTAINER_REPORT_FILE = f"{CONTAINER_REPORT_DIRECTORY}/{REPORT_FILE_NAME}"

    def __init__(self):
        super().__init__(self.NAME, self.SCANNER_IMAGE)

    def scan(self, target, working_dir):
        self.logger.info("Generating SBOM...")
        sbom_path = f"{working_dir}/{self.SBOM_FILE_NAME}"
        client = docker.from_env()
        container = client.containers.run(
            self.SBOM_IMAGE,
            command=f"scan dir:{self.CONTAINER_TARGET_DIRECTORY} -o table",
            volumes={
                target: {'bind': self.CONTAINER_TARGET_DIRECTORY, 'mode': 'rw'}},
            detach=True,
            stdout=True,
            stderr=True
        )
        container.wait()
        logs = container.logs()
        print(logs.decode("utf-8"))
        container.remove()
        self.logger.info("Creating SBOM file...")
        client = docker.from_env()
        container = client.containers.run(
            self.SBOM_IMAGE,
            command=f"scan dir:{self.CONTAINER_TARGET_DIRECTORY} -o json",
            volumes={
                target: {'bind': self.CONTAINER_TARGET_DIRECTORY, 'mode': 'rw'}},
            detach=True,
            stdout=True,
            stderr=True
        )
        container.wait()
        logs = container.logs()
        container.remove()
        try:
            with open(f'{sbom_path}', 'w', encoding='utf-8') as f:
                f.write(logs.decode("utf-8"))
        except (FileNotFoundError, PermissionError):
            self.logger.error(
                "Could't create output file in host %s", sbom_path)
            exit()
        self.logger.info("Scanning SBOM...")
        report_path = f"{working_dir}/{self.REPORT_FILE_NAME}"
        command = f"sbom:{self.CONTAINER_REPORT_DIRECTORY}/{self.SBOM_FILE_NAME}"
        client = docker.from_env()
        container = client.containers.run(
            self.SCANNER_IMAGE,
            command,
            volumes={working_dir: {
                'bind': self.CONTAINER_REPORT_DIRECTORY, 'mode': 'rw'}},
            detach=True,
            stdout=True,
            stderr=True
        )
        container.wait()
        logs = container.logs()
        container.remove()
        print(logs.decode("utf-8"))
        self.logger.info("Generating report file...")
        report_path = f"{working_dir}/{self.REPORT_FILE_NAME}"
        command = f"sbom:{self.CONTAINER_REPORT_DIRECTORY}/{self.SBOM_FILE_NAME} --output json"
        client = docker.from_env()
        container = client.containers.run(
            self.SCANNER_IMAGE,
            command,
            volumes={working_dir: {
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
                "Could't create output file in host %s", sbom_path)
            exit()
        self.logger.debug("Custom scanning completed.")
        self.logger.info("SBOM generated: %s", sbom_path)
        self.logger.info("Scan report generated: %s", report_path)
        return f"{report_path}"
