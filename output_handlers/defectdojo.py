from datetime import datetime
import string
import sys
import os
import random
import requests
from output_handler import OutputHandler

class CustomOutputHandler(OutputHandler):
    """
    Upload cosca scan output to DefectDojo
    """
    def setup(self):
        self.dd_url = os.getenv('DEFECTDOJO_URL', '')
        self.api_url = f'{self.dd_url}/api/v2'
        dd_api_key = os.getenv('DEFECTDOJO_API_KEY', '')
        self.headers = {
            'Authorization': f'Token {dd_api_key}'
        }
        dd_product_type_id = os.getenv('DEFECTDOJO_PRODUCT_TYPE_ID', '')
        dd_product_id = os.getenv('DEFECTDOJO_PRODUCT_ID', '')
        dd_engagement_id = os.getenv('DEFECTDOJO_ENGAGEMENT_ID', '')
        self.parser.add_argument(
            "--dd_url", help="DefectDojo Url. e.g. https://demo.defectdojo.org", default=self.dd_url)
        self.parser.add_argument("--dd_api_key", help="DefectDojo API KEY to import the reports. Either this argument or the environment variable DEFECTDOJO_API_KEY is required if --defectdojo is set. Get your API key from https://DEFECTDOJO_URL/api/key-v2", default=dd_api_key)
        self.parser.add_argument(
            "--dd_product_id", help="Either this argument or the environment variable DEFECTDOJO_PRODUCT_ID is required if --defectdojo is set.", default=dd_product_id)
        self.parser.add_argument("--dd_product_type_id",
                            help="Either this argument or the environment variable DEFECTDOJO_PRODUCT_TYPE_ID is required if --defectdojo is set.", default=dd_product_type_id)
        self.parser.add_argument(
            "--dd_engagement_id", help="Either this argument or the environment variable DEFECTDOJO_ENGAGEMENT_ID is required if --defectdojo is set.", default=dd_engagement_id)
        self.args = self.parser.parse_args()
        if not self.args.dd_url:
            self.parser.error(
                "--dd_url or DEFECTDOJO_URL environment variable required when --defectdojo (-d) is specified")
        if not self.args.dd_api_key:
            self.parser.error(
                "--dd_api_key or DEFECTDOJO_API_KEY environment variable required when --defectdojo (-d) is specified")

    def process_stdout(self, stdout):
        pass

    def process_files(self, report_path, target, scanner, aux_args):
        """
        Import scan report into DefectDojo.

        Args:
            engagement_id (int): import the report into this Defectdojo engagement.
            scan_type (str): scan type format. 
                Reference https://documentation.defectdojo.com/dev/integrations/parsers/file/
            file_path (str): path to the report file to be imported.

        Returns:
            str: Defectdojo's response
        """
        self.logger.debug("Generating output...")
        random_id=''.join(random.choices(string.ascii_letters + string.digits, k=4))
        if not self.args.dd_engagement_id:
            self.logger.debug(
                "--dd_engagement_id and DEFECTDOJO_ENGAGEMENT_ID environment variable are not set. A new engagement will be created in DefectDojo.")
            if not  self.args.dd_product_id:
                self.logger.debug(
                    "--dd_product_id and DEFECTDOJO_PRODUCT_ID environment variable are not set. A new product will be created in DefectDojo.")
                if not  self.args.dd_product_type_id:
                    self.logger.debug(
                        "--dd_product_type_id and DEFECTDOJO_PRODUCT_TYPE_ID environment variable are not set. A new product type will be created in DefectDojo.")
                    self.args.dd_product_type_id = self.create_product_type(
                        f"Type{random_id}", "Dummy product type")
                self.args.dd_product_id = self.create_product(
                    f"P{random_id}", "Dummy product",  self.args.dd_product_type_id)
            self.args.dd_engagement_id = self.create_engagement("Temporary engagement", "Temporary engagement to facilitate importing tasks", self.args.dd_product_id)

        url = f"{self.api_url}/import-scan/"
        with open(report_path, 'rb') as file:
            files = {'file': file}
            data = {
                'engagement': self.args.dd_engagement_id,
                'scan_type': aux_args["defectdojo_format"],
                'active': 'true',
                'verified': 'true'
            }
            response = requests.post(
                url, headers=self.headers, files=files, data=data, timeout=60*10)
            if response.status_code == 201:
                self.logger.debug('Scan uploaded successfully!')
                response_data = response.json()
                import_results_link=f"{self.dd_url}/test/{response_data.get('test')}"
                self.logger.info('Check scan results %s/test/%s',self.dd_url,response_data.get('test'))
            else:
                self.logger.error('Failed to upload scan. Status code: %s', str(response.status_code))
                self.logger.error(response.content.decode('utf-8'))

            return {self.name : [{"link": import_results_link}]}

    def create_product_type(self, name, description):
        url = f"{self.api_url}/product_types/"
        product_type_payload = {
            "name": name,
            "description": description,
            "critical_product": True,
            "key_product": True
        }
        product_type_response = requests.post(
            f"{url}", headers=self.headers, json=product_type_payload, timeout=60*2)
        if product_type_response.status_code == 201:
            product_type_id = product_type_response.json()["id"]
            self.logger.debug("Product Type created, ID = %s", product_type_id)
            return product_type_id
        else:
            self.logger.error('Failed to create Product Type. Status code: %s', str(product_type_response.status_code))
            self.logger.error(product_type_response.content.decode('utf-8'))
            sys.exit(1)
    
    def create_product(self, name, description, type_id):
        url = f"{self.api_url}/products/"
        product_payload = {
            "name": name,
            "description": description,
            "prod_type": type_id
        }
        product_response = requests.post(
            f"{url}", headers=self.headers, json=product_payload, timeout=60*2)
        if product_response.status_code == 201:
            product_id = product_response.json()["id"]
            self.logger.debug("Product created, ID = %s", product_id)
            return product_id
        else:
            self.logger.error('Failed to create Product. Status code: %s', str(product_response.status_code))
            self.logger.error(product_response.content.decode('utf-8'))
            sys.exit(1)

    def create_engagement(self, name, description, product_id):
        url = f"{self.api_url}/engagements/"
        date = datetime.now().strftime('%Y-%m-%d')
        engagement_payload = {
            "name": name,
            "description": description,
            "target_start": date,
            "target_end": date,
            "product": product_id,
            "environment": "Pre-prod",
            "engagement_type": "CI/CD",
            "deduplication_on_engagement": True,
            "close_old_findings": True
        }
        engagement_response = requests.post(
            f"{url}", headers=self.headers, json=engagement_payload, timeout=60*2)
        if engagement_response.status_code == 201:
            engagement_id = engagement_response.json()["id"]
            self.logger.debug("Engagement created, ID = %s", engagement_id)
            return engagement_id
        else:
            self.logger.error('Failed to create Engagement. Status code: %s', str(engagement_response.status_code))
            self.logger.error(engagement_response.content.decode('utf-8'))
            sys.exit(1)