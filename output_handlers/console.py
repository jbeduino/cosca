import os
import tempfile
from output_handler import OutputHandler


class CustomOutputHandler(OutputHandler):
    """
    
    """
    def setup(self):
        self.tmp_dir = tempfile.gettempdir()
        self.args = self.parser.parse_args()

    def process_files(self, report_path, target, scanner, aux_args):
        return {self.name : []}

    def process_stdout(self, stdout):
        self.logger.debug("Standard output from container START")
        print(stdout)
        self.logger.debug("Standard output from container END")
