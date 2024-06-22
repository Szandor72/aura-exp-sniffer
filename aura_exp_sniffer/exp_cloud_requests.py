import requests
from requests.exceptions import RequestException
import urllib3
from urllib3.exceptions import InsecureRequestWarning
import urllib.parse
import re
import json
from json.decoder import JSONDecodeError

from file_utils import load_payload_json_for
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

    def __init__(self, config: object):
        self.url = config.url
        self.session_id = config.session_id
        self.aura_config = {}

    def get_aura_config(self):
        print_message("Getting Aura Config")
        raw_response = BasicHttp(self.session_id).request(self.url)
        raw_response = self._handle_login_page_redirects(raw_response)
        bootstrap_url = self._extract_bootstrap_url(raw_response)
        aura_endpoint_details = self._extract_aura_endpoint_details(raw_response)
        self._validate_aura_endpoint_details(aura_endpoint_details)
        return {
            "aura_config": json.dumps(self._build_aura_config(aura_endpoint_details)),
            "bootstrap_url": bootstrap_url,
        }

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

    def _extract_bootstrap_url(self, raw_response):
        extractScriptTagsPattern = R"<script([^>]*)?>.*?</script>"

        srcFromLastScriptTag = (
            re.findall(extractScriptTagsPattern, raw_response)[-1]
            .replace('src="', "")
            .replace('"', "")
            .replace(" ", "")
        )
        parsedUrl = urllib.parse.urlsplit(self.url)
        return parsedUrl.scheme + "://" + parsedUrl.netloc + srcFromLastScriptTag

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
    Selects the preferred Aura endpoint for the Experience Cloud URL.
    Even if session_id is present, needs to run unauthenticated
    """

    def __init__(self, config: object):
        self.url = config.url
        self.active_endpoint = None

    def select_aura_endpoint(self):
        if self.active_endpoint:
            return
        aura_endpoints = ("aura", "s/aura", "s/sfsites/aura", "sfsites/aura")
        available_endpoints = self._check_endpoints_availability(aura_endpoints)

        if not available_endpoints:
            print_error("No endpoints available", "Is the URL correct?")
            raise

        print_message("Available Endpoints")
        print(available_endpoints)
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


class AuraRoutesCollector:
    """
    Follows bootstrap url and extracts route details
    """

    def __init__(self, config: object):
        self.bootstrap_url = config.aura_bootstrap_url
        self.session_id = config.session_id
        self.routes = []

    def collect(self):
        print_message("Start Collecting Routes")
        raw_response = BasicHttp().request(self.bootstrap_url)
        self.routes = self._extract_routes(raw_response)
        return self.routes

    def _extract_routes(self, raw_response: str):
        aura_attributes = self.bootstrap_url.split("bootstrap.js?aura.attributes=")[1]
        aura_attributes = aura_attributes.split("&jwt=")[0]
        aura_attributes = json.loads(urllib.parse.unquote(aura_attributes))

        view_details_pattern = R'routes":\{.+?,\s?.+?\}\s?\}'

        parsed_response = raw_response.replace("\n", "")
        parsed_response = " ".join(parsed_response.split())
        view_details = re.search(view_details_pattern, parsed_response)
        routes_json = view_details.group().replace('routes":', "")
        routes_map = json.loads(routes_json)

        # print(json.dumps(routes_map, indent=4))

        routes = []
        for key, value in routes_map.items():
            routes.append(
                dict(
                    path=key,
                    id=value["id"],
                    event=value["event"],
                    route_uddid=value["route_uddid"],
                    view_uuid=value["view_uuid"],
                    themeLayoutType=aura_attributes["themeLayoutType"],
                    publishedChangelistNum=aura_attributes["publishedChangelistNum"],
                    brandingSetId=aura_attributes["brandingSetId"],
                )
            )

        return routes


class AuraComponentCollector:
    def __init__(self, config: object):
        self.routes = config.routes
        self.config = config
        self.custom_components = []

    def collect(self):
        print_message(
            "Start Collecting Components"
        ), "%s routes to scan. Be patient." % len(self.routes)
        excluded_standard_component_namespaces = list(
            load_payload_json_for("IGNORELIST.json")
        )
        payload_template = load_payload_json_for("ACTION$getPageComponent.json")
        for route in self.routes:
            payload = self._create_payload_for_getCustomComponents(
                route, payload_template
            )
            json_response = AuraActionRequest(
                payload, self.config, return_full_response=True
            ).send_request()
            all_component_descriptors = self._find_component_descriptors(json_response)
            for cmp in all_component_descriptors:
                if (
                    not any(x in cmp for x in excluded_standard_component_namespaces)
                    and cmp not in self.custom_components
                ):
                    self.custom_components.append(cmp)
        return self.custom_components

    def _find_component_descriptors(self, json_response):
        descriptors = []
        for key, value in json_response.items():
            if key == "descriptor" and value.startswith("markup://"):
                descriptors.append(value.replace("markup://", ""))
            elif isinstance(value, dict):
                descriptors.extend(self._find_component_descriptors(value))
            elif isinstance(value, list):
                for item in value:
                    if isinstance(item, dict):
                        descriptors.extend(self._find_component_descriptors(item))
        return set(descriptors)

    def _create_payload_for_getCustomComponents(self, route, payload):
        payload["actions"][0]["params"]["attributes"]["viewId"] = route["id"]
        payload["actions"][0]["params"]["attributes"]["routeType"] = route["event"]
        payload["actions"][0]["params"]["attributes"]["themeLayoutType"] = route[
            "themeLayoutType"
        ]
        payload["actions"][0]["params"]["attributes"]["params"]["viewid"] = route[
            "view_uuid"
        ]
        payload["actions"][0]["params"]["publishedChangelistNum"] = route[
            "publishedChangelistNum"
        ]
        payload["actions"][0]["params"]["brandingSetId"] = route["brandingSetId"]
        return payload


class AuraActionRequest:
    def __init__(self, payload: json, config: map, return_full_response: bool = False):
        self.aura_endpoint_url = config.active_endpoint
        self.payload = json.dumps(payload)
        self.aura_endpoint_config = config.aura_config
        self.aura_token = config.aura_token
        self.session_id = config.session_id
        self.return_raw_response = return_full_response

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

        if self.return_raw_response:
            return response_json

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
