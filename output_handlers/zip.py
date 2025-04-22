import zipfile
import tempfile
import os
from output_handler import OutputHandler


class CustomOutputHandler(OutputHandler):
    """
    Creates a zip file with all the output files generated during the scans.
    """

    def setup(self):
        self.tmp_dir = tempfile.gettempdir()
        self.parser.add_argument(
            "--zip_output_folder", help="Folder to place the zip file", default=self.tmp_dir)
        self.parser.add_argument(
            "--zip_file_prefix", help="Filename prefix for the zip file", default="")
        self.args = self.parser.parse_args()
        self.stdout=None

    def add_files_to_zip(self, folder_name, zip_filename):
        with zipfile.ZipFile(zip_filename, 'a') as zipf:
            for root, _, files in os.walk(folder_name):
                for file in files:
                    file_path = os.path.join(root, file)
                    arcname = os.path.relpath(file_path, folder_name)
                    if arcname not in zipf.namelist():
                        zipf.write(file_path, arcname)


    def remove_prefix_from_path(self, file_path, prefix):
        if file_path.startswith(prefix):
            return file_path[len(prefix):].lstrip(os.sep)
        return file_path

    def process_files(self, report_path, target, scanner, aux_args):
        self.logger.debug("Generating output...")
        if self.stdout:
            stdout_path=f"{os.path.dirname(report_path)}{os.sep}{os.path.splitext(os.path.basename(report_path))[0]}_stdout.log"
            with open(stdout_path, 'a', encoding='utf-8') as file:
                file.write(self.stdout)
        zip_name = f"{self.args.zip_file_prefix}{os.path.normpath(self.remove_prefix_from_path(report_path, self.tmp_dir)).split(os.sep)[0]}.zip"
        zip_path = f"{self.args.zip_output_folder}{os.sep}{zip_name}"
        self.add_files_to_zip(os.path.dirname(report_path), zip_path)
        
        self.logger.info("File %s added to zip file: file://%s",
                         os.path.basename(report_path), zip_path)
        return {self.name : [{"zip_file": zip_path}]}

    def process_stdout(self, stdout):
        self.stdout=stdout