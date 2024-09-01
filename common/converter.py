import xml.etree.ElementTree as ET
from urllib.parse import urlparse, urlunparse
import hashlib
import json


class JUnit2Sarif():
    """
    Converts JUnit file format to SARIF
    """
    SARIF = {
        "$schema": "https://raw.githubusercontent.com/microsoft/sarif-python-om\
/main/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": []
    }
    RUN = {
        "tool": {
            "driver": {
                "name": "Dastardly",
                "version": "1.0",
                "informationUri": "https://portswigger.net/burp/dastardly",
                "rules": []
            }
        },
        "originalUriBaseIds": {
            "target": {
                "uri": "PLACEHOLDER",
                "description": {
                    "text": "The base URI for all Dastardly scan artifacts."
                }
            }
        },
        "results": []
    }

    def __init__(self):
        pass

    def sarif_problem_severity(self, s):
        return {
            "High": "error",
            "Medium": "warning",
            "Low": "note",
            "Information": "none"
        }.get(s, "none")

    def sarif_security_severity(self, s):
        return {
            "High": "7.0",
            "Medium": "4.0",
            "Low": "1.0",
            "Information": "0.0"
        }.get(s, "1.0")

    def convert(self, source_file, destination_file):
        tree = ET.parse(source_file)
        root = tree.getroot()
        rule_index = 0
        for suite in root.findall('testsuite'):
            if JUnit2Sarif.RUN['originalUriBaseIds']['target']['uri'] == "PLACEHOLDER":
                parsed_url = urlparse(suite.attrib['name'])
                stripped_url = urlunparse(
                    (parsed_url.scheme, parsed_url.netloc, '', '', parsed_url.query, ''))
                JUnit2Sarif.RUN['originalUriBaseIds']['target']['uri'] = stripped_url + "/"
            if int(suite.attrib['failures']) == 0:
                continue
            for case in suite.findall('testcase'):
                failure = case.find('failure')
                if failure is None:
                    continue
                severity = case.attrib.get('type', '')
                rule_id = hashlib.md5(
                    bytes(suite.attrib['name'] + failure.attrib['message'], 'utf-8')).hexdigest()
                rule = {
                    "id": rule_id,
                    "shortDescription": {
                        "text": failure.attrib['message']
                    },
                    "help": {
                        "text": failure.attrib['message'],
                        "markdown": "# " + failure.attrib['message']
                    },
                    "properties": {
                        "impact": [failure.attrib['message']],
                        "problem.severity": self.sarif_problem_severity(severity),
                        "resolution": [failure.attrib['message']],
                        "security-severity": self.sarif_security_severity(severity)
                    }
                }
                severity_failure = failure.attrib.get('type', '')
                stripped_text = failure.text.strip()
                rule['help']['text'] = stripped_text
                rule['help']['markdown'] = stripped_text
                rule['properties']['impact'] = [stripped_text]
                rule['properties']['resolution'] = [stripped_text]
                rule['properties']['problem.severity'] = self.sarif_problem_severity(
                    severity_failure)
                rule['properties']['security-severity'] = self.sarif_security_severity(
                    severity_failure)
                self.RUN['tool']['driver']['rules'].append(rule)
                parsed_url = urlparse(suite.attrib['name'])
                result = {
                    "ruleId": rule_id,
                    "ruleIndex": rule_index,
                    "level": self.sarif_problem_severity(severity_failure),
                    "message": {
                        "text": failure.attrib['message']
                    },
                    "locations": [
                        {
                            "physicalLocation": {
                                "artifactLocation": {
                                    "uri": urlunparse(("", "", parsed_url.path.lstrip('/'),
                                                        parsed_url.params, parsed_url.query,
                                                          parsed_url.fragment)),
                                    "uriBaseId": "target"
                                }
                            }
                        }
                    ],
                    "hostedViewerUri": suite.attrib['name']
                }
                self.RUN['results'].append(result)
                rule_index += 1
        self.SARIF['runs'].append(self.RUN)
        with open(destination_file, 'w', encoding='utf-8') as f:
            json.dump(self.SARIF, f, indent=4)
        return destination_file




# j2s = JUnit2Sarif()
# j2s.convert('/tmp/junit1.json','/tmp/output3.sarif')
