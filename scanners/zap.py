import docker
from scanner import Scanner


class CustomScanner(Scanner):
    NAME = "zap"
    SCANNER_IMAGE = "zaproxy/zap-stable"
    REPORT_FILE_NAME = f"scan_results_{NAME}.json"
    REPORT_FILE_NAME_HTML = f"scan_results_{NAME}.html"
    CONTAINER_TARGET_DIRECTORY = "/src"
    HOST_REPORT_DIRECTORY = f"/tmp/sympho/output_{NAME}"
    HOST_REPORT_FILE = f"{HOST_REPORT_DIRECTORY}/{REPORT_FILE_NAME}"
    CONTAINER_REPORT_DIRECTORY = "/zap/wrk"
    CONTAINER_REPORT_FILE = f"{CONTAINER_REPORT_DIRECTORY}/{REPORT_FILE_NAME}"

    def __init__(self):
        super().__init__(self.NAME, self.SCANNER_IMAGE)

    def scan(self, target, working_dir):
        self.logger.info("Starting to scan target: %s", target)
        client = docker.from_env()
        command = f'zap-baseline.py -t {target} -r {self.REPORT_FILE_NAME_HTML} -J {self.REPORT_FILE_NAME}'
        container = client.containers.run(
            self.SCANNER_IMAGE,
            command,
            volumes={self.HOST_REPORT_DIRECTORY: {
                'bind': self.CONTAINER_REPORT_DIRECTORY, 'mode': 'rw'}},
            user='0',
            detach=True,
            stdout=True,
            stderr=True
        )
        container.wait()
        logs = container.logs()
        report_path = f"{self.HOST_REPORT_DIRECTORY}/{self.REPORT_FILE_NAME}"
        print(logs.decode("utf-8"))
        self.logger.debug("Custom scanning completed.")
        self.logger.info("Scan report generated: %s", report_path)
        return f"{report_path}"
