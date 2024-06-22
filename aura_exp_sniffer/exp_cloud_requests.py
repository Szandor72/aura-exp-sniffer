import requests
from requests.exceptions import RequestException
import urllib3
from urllib3.exceptions import InsecureRequestWarning
import urllib.parse
import re
import json
from json.decoder import JSONDecodeError

from message_utils import print_message, print_error


# Disable SSL warnings
urllib3.disable_warnings(InsecureRequestWarning)


class BasicHttp:
    """
    Basic HTTP request supporting get/post with sid cookie for authenticated calls
    """

    headers = None
    USER_AGENT = "Mozilla/5.0 (Macintosh; Intel Mac OS X 11_2_1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/88.0.4324.150 Safari/537.36"

    def __init__(self, salesforce_sid_cookie_value=""):
        self.headers = {"User-Agent": self.USER_AGENT}
        self.cookies = {}
        if salesforce_sid_cookie_value:
            self.cookies["sid"] = salesforce_sid_cookie_value

    def request(self, url, values=None, method="GET"):
        if method == "POST":
            self.headers["Content-Type"] = "application/x-www-form-urlencoded"
            try:
                response = requests.post(
                    url,
                    data=values,
                    headers=self.headers,
                    cookies=self.cookies,
                    verify=False,
                )
                response_body = response.text
            except RequestException as e:
                raise
        else:
            try:
                response = requests.get(
                    url, headers=self.headers, cookies=self.cookies, verify=False
                )
                response_body = response.text
            except RequestException as e:
                raise
        return response_body


class AuraConfigLoader:
    """
    Loads the Aura Config like fwuid from the Experience Cloud URL
    """

    def __init__(self, url: str):
        self.url = url
        self.aura_config = {}

    def get_aura_config(self):
        print_message("Getting Aura Config")
        raw_response = BasicHttp().request(self.url)
        raw_response = self._handle_login_page_redirects(raw_response)
        aura_endpoint_details = self._extract_aura_endpoint_details(raw_response)
        self._validate_aura_endpoint_details(aura_endpoint_details)
        return json.dumps(self._build_aura_config(aura_endpoint_details))

    def _handle_login_page_redirects(self, raw_response):
        if ("window.location.href ='%s" % self.url) in raw_response:
            location_url = re.search(r"window.location.href =\'([^\']+)", raw_response)
            login_page_url = location_url.group(1)
            print_message("Redirecting to", login_page_url)
            try:
                return BasicHttp().request(login_page_url)
            except Exception as e:
                print_error("Error accessing login page", str(e))
                raise
        return raw_response

    def _extract_aura_endpoint_details(self, raw_response):
        if "fwuid" not in raw_response:
            print_error(
                "Couldn't find fwuid.",
                "No Aura App Login Page. Are we maybe redirected to a Visualforce Page?",
            )
            raise

        urlencoded_aura_endpoints = re.search(
            r"\/s\/sfsites\/l\/([^\/]+fwuid[^\/]+)", raw_response
        )

        if urlencoded_aura_endpoints:
            return json.loads(urllib.parse.unquote(urlencoded_aura_endpoints.group(1)))
        return {}

    def _validate_aura_endpoint_details(self, details):
        if not all(details.get(key) for key in ["fwuid", "app", "loaded"]):
            print_error("Aborting", "Couldn't find fwuid or markup details.")
            raise

    def _build_aura_config(self, details):
        return {
            "mode": "PROD",
            "fwuid": details.get("fwuid"),
            "app": details.get("app"),
            "loaded": details.get("loaded"),
            "dn": [],
            "globals": {},
            "uad": False,
        }


class AuraEndpointSelector:
    """
    Selects the preferred Aura endpoint for the Experience Cloud URL
    """

    def __init__(self, url):
        self.url = url
        self.active_endpoint = None

    def select_aura_endpoint(self):
        if self.active_endpoint:
            return
        aura_endpoints = ("aura", "s/aura", "s/sfsites/aura", "sfsites/aura")
        available_endpoints = self._check_endpoints_availability(aura_endpoints)

        if not available_endpoints:
            print_error("No endpoints available", "Is the URL correct?")
            raise

        print_message("Available Endpoints", available_endpoints)
        self._select_preferred_endpoint(available_endpoints)
        return self.active_endpoint

    def _check_endpoints_availability(self, endpoints):
        available_endpoints = []
        for endpoint in endpoints:
            url = f"{self.url}/{endpoint}"
            print_message("Checking", url)
            if self._is_endpoint_available(url):
                available_endpoints.append(url)
        return available_endpoints

    def _is_endpoint_available(self, url):
        try:
            response = BasicHttp().request(url, method="POST")
            return "aura:invalidSession" in response
        except Exception as e:
            print_error("Error accessing {url}", str(e))
            return False

    def _select_preferred_endpoint(self, available_endpoints):
        for endpoint in available_endpoints:
            if "s/sfsites/" in endpoint:
                self.active_endpoint = endpoint
                return
        self.active_endpoint = available_endpoints[0]


class AuraActionRequest:
    def __init__(self, payload: str, config: map):
        self.aura_endpoint_url = config.active_endpoint
        self.payload = payload
        self.aura_endpoint_config = config.aura_config
        self.aura_token = config.aura_token
        self.sid = config.session_id

    def send_request(self):
        values = {
            "message": self.payload,
            "aura.context": self.aura_endpoint_config,
            "aura.token": self.aura_token,
        }

        try:
            response_body = BasicHttp().request(
                self.aura_endpoint_url,
                values=values,
                method="POST",
            )
            response_json = json.loads(response_body)
        except JSONDecodeError:
            raise Exception(f"JSON Decode error. Response -> {response_body}")
        except Exception as e:
            raise e

        if (
            response_json.get("exceptionEvent") is not None
            and response_json.get("exceptionEvent") is True
        ):
            raise Exception(response_json)

        if (
            response_json.get("actions") is None
            or response_json.get("actions")[0].get("state") is None
        ):
            raise Exception(
                "Failed to get action property in response: %s" % response_json
            )

        return response_json.get("actions")[0].get("returnValue")
