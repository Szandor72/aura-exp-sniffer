import typer
from typing_extensions import Annotated
from types import SimpleNamespace
import sys
import json
from pathlib import Path
from typing import Optional


from aura_exp_sniffer.exp_cloud_requests import (
    AuraEndpointSelector,
    AuraConfigLoader,
    AuraActionRequest,
    AuraRoutesCollector,
    AuraComponentCollector,
    AuraComponentApexMethodCollector,
)
from aura_exp_sniffer.message_utils import (
    print_message,
    print_error,
    print_pretty,
    print_component_apex_details,
)
from aura_exp_sniffer.file_utils import load_payload_json_for, dump_json_to_file

cli = typer.Typer(
    help="Aura Exp Sniffer: A simple security research tool to access undocumented Aura APIs",
    no_args_is_help=True,
)


@cli.callback()
def main(
    cli_context: typer.Context,
    url: Annotated[
        str,
        typer.Option(
            "--url",
            "-u",
            help="Experience Cloud URL, e.g. https://company.portal.com/s",
            show_default=False,
        ),
    ],
    token_json: Annotated[
        str,
        typer.Option(
            "--token",
            "-t",
            help="JSON with Aura Token and SID (session id) for authenticated access",
        ),
    ] = "",
):
    """
    Handles --url  validation and --token parsing and will set the active endpoint and aura config for the CLI context
    """
    if not url:
        print_error(
            "Missing experience URL",
            "pass --url, e.g. --url https://company.portal.com/s",
        )
        raise typer.Exit(1)
    # if url ends with / or /s, remove it
    if url.endswith("/s"):
        url = url[:-2]
    if url.endswith("/"):
        url = url[:-1]
    aura_token = ""
    session_id = ""
    if token_json:
        token_details = parse_token_from_shell(token_json)
        aura_token = token_details["token"]
        session_id = token_details["sid"]
    if not cli_context.obj:
        cli_context.obj = SimpleNamespace(
            url=url,
            aura_token=aura_token,
            aura_bootstrap_url="",
            session_id=session_id,
            active_endpoint="",
            aura_config={},
            routes=[],
            custom_component_list=[],
        )
    # we set config values for each command invocation but only once
    # and only if we don't show help or other typer default options
    if not all(
        [cli_context.obj.active_endpoint, cli_context.obj.aura_config]
    ) and not any(
        arg in sys.argv
        for arg in ["--help", "--show-completion", "--install-completion"]
    ):
        select_aura_endpoint_after_validation(cli_context)
        get_aura_config_from_url(cli_context)


def parse_token_from_shell(token_json: str):
    """
    Due to shell parsing, quotation marks might get lost for the token json
    """
    if '"' not in token_json:
        return json.loads(
            token_json.replace("token", '"token"')
            .replace("sid", '"sid"')
            .replace(":", ':"')
            .replace(",", '",')
            .replace("}", '"}')
        )
    return json.loads(token_json)


def select_aura_endpoint_after_validation(cli_context: typer.Context):
    """
    Check if Aura endpoints for the Experience Cloud URL are available and select preferably the sfsites endpoint
    """
    if cli_context.obj.active_endpoint:
        return

    cli_context.obj.active_endpoint = AuraEndpointSelector(
        cli_context.obj
    ).select_aura_endpoint()

    print_message("Active Endpoint set", cli_context.obj.active_endpoint)


def get_aura_config_from_url(cli_context: typer.Context):
    """
    Get necessary configuration for Aura API access
    """
    if cli_context.obj.aura_config:
        return

    try:
        aura_config = AuraConfigLoader(cli_context.obj).get_aura_config()
        aura_endpoint_config = aura_config.get("aura_config")
        bootstrap_url = aura_config.get("bootstrap_url")

        cli_context.obj.aura_config = aura_endpoint_config
        cli_context.obj.aura_bootstrap_url = bootstrap_url

        print_message("Aura Endpoint Config retrieved")
    except Exception as e:
        print_error("Fatal Error", e)
        raise typer.Exit(1)


@cli.command("routes")
def get_routes(
    cli_context: typer.Context,
    display: Annotated[
        bool, typer.Option("-d", "--display", help="Display each route path")
    ] = True,
):
    """
    Get all available Aura routes
    """
    print_message("Getting Aura Routes", "follow Bootstrap URL")
    routes = AuraRoutesCollector(cli_context.obj).collect()

    cli_context.obj.routes = routes

    if display:
        print_message("Routes", "%s routes found" % len(routes))
        for route in routes:
            route_url = f'{cli_context.obj.url}/s{route.get("path")}'
            display_message = f'{route_url} {route.get("path")}'
            print_pretty(display_message)


@cli.command("custom-components")
def get_custom_components(
    cli_context: typer.Context,
    display: Annotated[
        bool, typer.Option("-d", "--display", help="Display each component name")
    ] = True,
):
    """
    Get all exposed custom component names
    """
    if not cli_context.obj.routes:
        get_routes(cli_context, display=False)

    custom_component_list = AuraComponentCollector(cli_context.obj).collect()

    cli_context.obj.custom_component_list = custom_component_list

    if display:
        print_message(
            "Custom Components", "%s components found" % len(custom_component_list)
        )
        for component in custom_component_list:
            print_pretty(component)


@cli.command("apex-methods")
def get_apex_methods(cli_context: typer.Context):
    """
    Get all Apex methods exposed in custom components
    """
    if not cli_context.obj.custom_component_list:
        get_custom_components(cli_context, display=False)
    if len(cli_context.obj.custom_component_list) == 0:
        print_error("No custom components found", "No Apex methods to retrieve")
        raise typer.Exit(1)
    components_with_apex_details = AuraComponentApexMethodCollector(
        cli_context.obj
    ).collect()
    print_component_apex_details(components_with_apex_details)


@cli.command()
def call_apex(
    cli_context: typer.Context,
    namespace: str,
    class_name: str,
    method_name: str,
    parameter_file: Annotated[
        Optional[Path],
        typer.Argument(
            help="Points to a JSON file containing apex parameters for method call"
        ),
    ] = None,
):
    """
    Call an Apex method with params. Method parameters need to be made available within a json-file
    """
    print_message(
        "Calling Apex method", "%s.%s.%s" % (namespace, class_name, method_name)
    )
    payload = load_payload_json_for("ACTION$executeApexMethod.json")
    payload["actions"][0]["descriptor"] = "apex://%s.%s/ACTION$%s" % (
        namespace,
        class_name,
        method_name,
    )
    if parameter_file:
        payload["actions"][0]["params"] = json.loads(parameter_file.read_text())

    try:
        json_response = AuraActionRequest(
            payload, cli_context.obj, return_full_response=True
        ).send_request()
    except Exception as e:
        print_error("Error calling %s.%s" % (class_name, method_name))
        print_pretty(e)
        raise typer.Exit(1)
    if json_response["actions"][0]["returnValue"]:
        print_pretty(json_response["actions"][0]["returnValue"])
        return
    if json_response["actions"][0]["error"]:
        print_error("Error", json_response["actions"][0]["error"])


@cli.command("sobjects")
def list_accessible_sobjects(
    cli_context: typer.Context,
    display: Annotated[
        bool, typer.Option("-d", "--display", help="Display each route path")
    ] = True,
):
    """
    Will print most accessible Standard and Custom sObjects respectively.
    """

    payload = load_payload_json_for("ACTION$getConfigData.json")
    ignored_standard_sobjects = load_payload_json_for(
        "IGNORELIST-STANDARD-SOBJECTS.json"
    )
    try:
        json_response = AuraActionRequest(payload, cli_context.obj).send_request()
    except Exception as e:
        print_error("Error retrieving sObject list")
        print_pretty(e)
        raise typer.Exit(1)
    api_name_to_id_prefixes = json_response.get("apiNamesToKeyPrefixes")
    custom_sobject_list = []
    standard_sobject_list = []
    all_sobjects = []
    for key in api_name_to_id_prefixes.keys():
        if key not in ignored_standard_sobjects:
            all_sobjects.append(key)
            if key.endswith("__c"):
                custom_sobject_list.append(key)
            else:
                standard_sobject_list.append(key)
    if display:
        print_message("Custom sObject list")
        print_pretty(custom_sobject_list)
        print_message("Standard sObject list")
        print_pretty(standard_sobject_list)
    return all_sobjects


@cli.command("records")
def get_records(
    cli_context: typer.Context,
    sobject_name: Annotated[str, typer.Argument(help="The sObject API Name")] = "User",
    number_of_records: Annotated[
        int, typer.Argument(help="Number of records to fetch")
    ] = 3,
    display: Annotated[
        bool, typer.Option("--display", "-d", help="Display results")
    ] = True,
    dump: Annotated[
        bool, typer.Option("--dump", "-d", help="Dump records to a file")
    ] = False,
    skip_existing: Annotated[
        bool,
        typer.Option(
            "--skip-existing",
            "-s",
            help="Works with --dump only. Skip retrieving records if file dump already exists",
        ),
    ] = False,
    ignore_exception: Annotated[
        bool,
        typer.Option(
            help="Continue on exception when dumping all records", hidden=True
        ),
    ] = False,
):
    """
    Get records by sObject API Name
    """
    # early return on special case if we dump records and skip_existing is set
    url_for_filename = cli_context.obj.url.replace("https://", "").replace("/", "_")
    filename = f"{url_for_filename}-{sobject_name}-records.json"
    if dump and skip_existing and Path("file-dumps", filename).exists():
        return

    DEFAULT_PAGE = 1
    payload = load_payload_json_for("ACTION$getItems.json")
    payload["actions"][0]["params"]["entityNameOrId"] = sobject_name
    payload["actions"][0]["params"]["pageSize"] = number_of_records
    payload["actions"][0]["params"]["currentPage"] = DEFAULT_PAGE

    json_response = json.loads("{}")
    try:
        json_response = AuraActionRequest(payload, cli_context.obj).send_request()
    except Exception as e:
        print_error("Error retrieving %s records" % sobject_name)
        print_pretty(e)
        if not ignore_exception and not dump:
            raise typer.Exit(1)
    if json_response.get("result") and json_response.get("totalCount"):

        retrieved_records = []
        for recordWraper in json_response["result"]:
            retrieved_records.append(recordWraper["record"])

        if display and not dump:
            print_message("Records")
            print_pretty(retrieved_records)

        print_message(
            "Total records of type %s that can be retrieved" % sobject_name,
            json_response["totalCount"],
        )

        if dump:
            if skip_existing and Path(filename).exists():
                return
            dump_json_to_file(retrieved_records, filename)
        return
    print_error("Error retrieving %s records" % sobject_name, "No records found")


@cli.command("dump")
def dump_records_to_files(
    cli_context: typer.Context,
    full: Annotated[
        bool, typer.Option("--full", "-f", help="Retrieve all records (max 1000)")
    ] = False,
    skip_existing: Annotated[
        bool,
        typer.Option(
            "--skip-existing",
            "-s",
            help="Works with --dump only. Skip retrieving records if file dump already exists",
        ),
    ] = False,
):
    """
    Dump accessible records to files. Retrieve 10 records per sObject by default.
    """
    # TODO where should we store max_page_size and default_page_size?
    max_page_size = 1000
    default_page_size = 10
    all_sobjects = list_accessible_sobjects(cli_context, display=False)
    number_of_records = max_page_size if full else default_page_size
    for sobject_name in all_sobjects:
        get_records(
            cli_context,
            sobject_name,
            number_of_records,
            display=False,
            dump=True,
            skip_existing=skip_existing,
            ignore_exception=True,
        )


@cli.command("record")
def get_record(
    cli_context: typer.Context,
    record_id: Annotated[str, typer.Argument(help="The Id of an sObject record")],
    dump: Annotated[
        bool, typer.Option("--dump", "-d", help="Dump records to a file")
    ] = False,
):
    """
    Get record by record Id
    """
    payload = load_payload_json_for("ACTION$getRecord.json")
    payload["actions"][0]["params"]["recordId"] = record_id
    try:
        json_response = AuraActionRequest(payload, cli_context.obj).send_request()
    except Exception as e:
        print_error("Error retrieving record with record id %s" % record_id)
        print_pretty(e)
        raise typer.Exit(1)
    if json_response.get("record"):
        print_message("Record", "successfully retrieved")
        print_pretty(json_response.get("record"))
    else:
        print_error("Error retrieving record", "No record found")
        raise typer.Exit(1)

    if dump:
        url_for_filename = cli_context.obj.url.replace("https://", "").replace("/", "_")
        dump_json_to_file(
            json_response.get("record"), f"{url_for_filename}-{record_id}-record.json"
        )


@cli.command("feed-items")
def get_feed_items(
    cli_context: typer.Context,
    record_id: Annotated[str, typer.Argument(help="The Id of an sObject record")],
    dump: Annotated[
        bool, typer.Option("--dump", "-d", help="Dump records to a file")
    ] = False,
):
    """
    Get feed items by record Id
    """
    payload = load_payload_json_for("ACTION$getFeedItems.json")
    payload["actions"][0]["params"]["recordId"] = record_id
    try:
        json_response = AuraActionRequest(payload, cli_context.obj).send_request()
    except Exception as e:
        print_error("Error retrieving feed items for record id %s" % record_id)
        print_pretty(e)
        raise typer.Exit(1)
    if json_response:
        print_message("Feed Items Response")
        print_pretty(json_response)

    if dump:
        url_for_filename = cli_context.obj.url.replace("https://", "").replace("/", "_")
        dump_json_to_file(
            json_response["record"], f"{url_for_filename}-{record_id}-feed-items.json"
        )


@cli.command("search")
def search_records(
    cli_context: typer.Context,
    search_term: Annotated[str, typer.Argument(help="the term to search for")],
    sobject_name: Annotated[str, typer.Argument(help="the sObject API Name")],
    fields: Annotated[
        str,
        typer.Argument(
            help="Comma delimited list of fields to return, e.g. 'Name, Industry'"
        ),
    ],
    raw_response: Annotated[
        bool, typer.Option("--raw", help="Return raw JSON response")
    ] = False,
):
    """
    Search for records by term and sObject API Name. At least one additional fields is required.
    """
    payload = load_payload_json_for("ACTION$searchRecord.json")
    payload["actions"][0]["params"]["scope"] = sobject_name
    payload["actions"][0]["params"]["term"] = search_term
    if fields:
        payload["actions"][0]["params"]["additionalFields"] = (
            fields.split(", ") if ", " in fields else fields.split(",")
        )
    json_response = AuraActionRequest(
        payload, cli_context.obj, return_full_response=raw_response
    ).send_request()
    if raw_response:
        print_pretty(json_response)
        return
    if json_response["result"]:
        print_message("Search completed", "successfully retrieved")
        print_pretty(json_response["result"])
    else:
        print_error("Error searching for records", "No result returned")
        raise typer.Exit(1)


@cli.command("profile-menu")
def get_profile_menu(cli_context: typer.Context):
    """
    Get the profile menu
    """
    payload = load_payload_json_for("ACTION$getProfileMenuResponse.json")
    json_response = AuraActionRequest(payload, cli_context.obj).send_request()
    if json_response:
        print_message("Profile Menu Details")
        print_pretty(json_response)


if __name__ == "__main__":
    cli()
