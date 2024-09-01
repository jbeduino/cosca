from abc import ABC, abstractmethod
import logging
import hashlib
import docker
from common.logging_setup import setup_logger
from typing import List, Dict


class Scanner(ABC):
    """Inherit from this class to integrate a specific scanner. Scanners are tipically based on docker and rely on the run_container method."""

    def __init__(self, log_level=logging.INFO):
        self.report_path = ""
        self.logger = setup_logger(self.NAME, 2, level=log_level)
        self.logger.debug("Scanner initialized.")

    @property
    @abstractmethod
    def NAME(self):
        """Scanner name. This constant must be defined in all subclasses. """

    @property
    @abstractmethod
    def DOCKER_IMAGE(self):
        """Scanner name. This constant must be defined in all subclasses. """

    @property
    @abstractmethod
    def DEFECTDOJO_IMPORT_FORMAT(self):
        """This constant must be defined in all subclasses. 
        Reference formats: https://documentation.defectdojo.com/dev/integrations/parsers/file/"""

    @abstractmethod
    def scan(self, target, working_dir, show_stdout=False) -> List[Dict[str, str]]:
        """This method must be overriden in all subclasses and must return
          the path to the report file

          Returns:
          A json list with details of outputs generated during the scans
          e.g.
          """

    @abstractmethod
    def get_aux_args(self) -> str:
        """This method must be overriden in all subclasses and must return 
        a json string containing necessary variables to be used from output modules"""

    def run_container(self, image, command, volumes={}, environment={}, user={}):
        client = docker.from_env()
        container = client.containers.run(
            image,
            command=command,
            volumes=volumes,
            environment=environment,
            user=user,
            detach=True,
            stdout=True,
            stderr=True
        )
        container.wait()
        logs = container.logs().decode("utf-8")
        container.remove()
        return logs

    def get_target_id(self, s, length=8):
        hash_object = hashlib.sha256(s.encode('utf-8'))
        hash_id = hash_object.hexdigest()
        return hash_id[:length]
