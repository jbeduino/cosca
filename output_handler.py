import os
from abc import ABC, abstractmethod
import logging
from typing import Dict
from common.logging_setup import setup_logger


class OutputHandler(ABC):
    """
    Inherit from this class to implement specific output processing after the scanners execute.
    Place the inherited class in output_handlers directory. To invoke the implemented output processing, 
    add '-o FILE_NAME'  cosca command (don't include the .py extension).
    """

    def __init__(self, name, parser,log_level=logging.INFO):
        self.name = name
        self.parser = parser
        self.logger = setup_logger(name,'📝',level=log_level)
        self.logger.debug("Output Handler initialized.")
        self.setup()

    @abstractmethod
    def setup(self):
        """This method must be overriden to prepare the variables necessary 
        to generate an specific output"""

    @abstractmethod
    def process_files(self, report_path, target, scanner, aux_args) -> Dict[str, str]:
        """This method must be overriden and must return a boolean
          depending on the output processing result
          Returns:
            dict: A dictionary representing the JSON object.
            e.g.
           return {self.name : [{"pdf_summary": pdf_path},{"json_summary": json_path}]}
          """

    @abstractmethod
    def process_stdout(self, stdout):
        """This method must be overriden and must return a boolean
          depending on the processing result
          """