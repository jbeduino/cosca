import unittest
from unittest.mock import patch, Mock
from common.target_type import TargetType

# python -m unittest discover -s tests

class TestTargetType(unittest.TestCase):

    @patch('os.path.exists')
    def test_directory(self, mock_exists):
        mock_exists.return_value = True
        self.assertEqual(TargetType.DIRECTORY, TargetType.get_target_type('/some/path'))

    @patch('validators.url')
    @patch('requests.get')
    def test_github(self, mock_get, mock_url):
        mock_url.return_value = True
        mock_get.return_value = Mock(status_code=200, text='')
        with patch('urllib.parse.urlparse', return_value=Mock(netloc='github.com')):
            self.assertEqual(TargetType.GITHUB, TargetType.get_target_type('https://github.com/some/repo'))

    @patch('validators.url')
    @patch('requests.get')
    def test_openapi(self, mock_get, mock_url):
        mock_url.return_value = True
        mock_get.return_value = Mock(status_code=200, text='"openapi"')
        self.assertEqual(TargetType.OPENAPI, TargetType.get_target_type('https://petstore.swagger.io'))

    #TODO review
    @patch('validators.url')
    @patch('requests.get')
    def test_soap(self, mock_get, mock_url):
        mock_url.return_value = True
        mock_get.return_value = Mock(status_code=200, text='<soapenv:Envelope>')
        self.assertEqual(TargetType.SOAP, TargetType.get_target_type('https://www.dataaccess.com/webservicesserver/NumberConversion.wso'))

    @patch('validators.url')
    @patch('requests.post')
    @patch('requests.get')
    def test_graphql(self, mock_get, mock_post, mock_url):
        mock_url.return_value = True
        mock_get.return_value = Mock(status_code=200, text='')
        mock_post.return_value = Mock(status_code=200, text='{"data": {"__schema": {}}}')
        self.assertEqual(TargetType.GRAPHQL, TargetType.get_target_type('https://graphqlzero.almansi.me/api'))

    @patch('validators.url')
    @patch('requests.get')
    def test_web(self, mock_get, mock_url):
        mock_url.return_value = True
        mock_get.return_value = Mock(status_code=200, text='httpbin')
        self.assertEqual(TargetType.WEB, TargetType.get_target_type('https://httpbin.org'))

    def test_valid_image_names(self):
        valid_names = [
            "myrepo/myimage:latest",
            "myrepo/myimage",
            "myrepo/myimage:1.0",
            "myrepo/myimage@sha256:1234567890abcdef",
            "myimage",
            "myimage:1.0",
            "myimage@sha256:1234567890abcdef"
        ]
        for name in valid_names:
            with self.subTest(name=name):
                self.assertTrue(TargetType.get_target_type(name), TargetType.DOCKER)

    def test_invalid_image_names(self):
        invalid_names = [
            "invalid_image_name!",
            "InvalidUpperCase",
            "repo/invalid:tag@sha256:1234567890abcdef"
        ]
        for name in invalid_names:
            with self.subTest(name=name):
                self.assertFalse(TargetType.get_target_type(name), None)

if __name__ == '__main__':
    unittest.main()
