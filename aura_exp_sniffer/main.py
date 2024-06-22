import typer
from typing_extensions import Annotated
from types import SimpleNamespace
import sys
from rich import print


from exp_cloud_requests import (
    AuraEndpointSelector,
    AuraConfigLoader,
    AuraActionRequest,
    AuraRoutesCollector,
    AuraComponentCollector,
    AuraComponentApexMethodCollector,
)
from message_utils import (
    print_message,
    print_error,
    print_json,
    print_component_apex_details,
)
from file_utils import load_payload_json_for, dump_json_to_file

cli = typer.Typer(
    help="Aura Sniffer: A simple security research tool to access undocumented Aura APIs",
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
        ),
    ],
    token_json: Annotated[
        str,
        typer.Option(
            "--token",
            "-t",
            help="JSON with Aura Token and SID (session id) to access Aura APIs",
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
    # TODO add json token parsing here
    aura_token = ""
    session_id = ""
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
    if (
        not all([cli_context.obj.active_endpoint, cli_context.obj.aura_config])
        and not "--help" in sys.argv
    ):
        select_aura_endpoint_after_validation(cli_context)
        get_aura_config_from_url(cli_context)


def select_aura_endpoint_after_validation(cli_context: typer.Context):
    """
    Check if Aura endpoints for the Experience Cloud URL are available and select preferably the sfsites endpoint
    """
    if cli_context.obj.active_endpoint:
        return

    try:
        cli_context.obj.active_endpoint = AuraEndpointSelector(
            cli_context.obj
        ).select_aura_endpoint()
    except Exception as e:
        print_error("Error selecting Aura endpoint", str(e))
        raise typer.Exit(1)

    print_message(":white_check_mark: Active Endpoint", cli_context.obj.active_endpoint)


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
    except Exception as e:
        raise typer.Exit(1)

    cli_context.obj.aura_config = aura_endpoint_config
    cli_context.obj.aura_bootstrap_url = bootstrap_url

    print_message(":white_check_mark: Success", "Aura Endpoint Config set")


@cli.command()
def get_routes(
    cli_context: typer.Context,
    display: Annotated[
        bool, typer.Option("-d", "--display", help="Display each component name")
    ] = True,
):
    """
    Get all available Aura routes
    """
    print_message("Getting Aura Routes:", "follow Bootstrap URL")
    try:
        routes = AuraRoutesCollector(cli_context.obj).collect()
    except Exception as e:
        print_error("Error getting Aura routes", str(e))
        raise typer.Exit(1)

    cli_context.obj.routes = routes

    if display:
        print_message("Routes", "%s routes found" % len(routes))
        for route in routes:
            print(route.get("path"))


@cli.command()
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
    try:
        custom_component_list = AuraComponentCollector(cli_context.obj).collect()
    except Exception as e:
        print_error("Error getting custom component names", str(e))
        raise typer.Exit(1)

    cli_context.obj.custom_component_list = custom_component_list

    if display:
        print_message(
            "Custom Components", "%s components found" % len(custom_component_list)
        )
        for component in custom_component_list:
            print(component)


@cli.command()
def get_apex_methods(cli_context: typer.Context):
    """
    Get all Apex methods exposed in custom components
    """
    if not cli_context.obj.custom_component_list:
        get_custom_components(cli_context, display=False)
    if len(cli_context.obj.custom_component_list) == 0:
        print_error("No custom components found", "No Apex methods to retrieve")
        raise typer.Exit(1)
    try:
        components_with_apex_details = AuraComponentApexMethodCollector(
            cli_context.obj
        ).collect()
        print_component_apex_details(components_with_apex_details)
    except Exception as e:
        print_error("Error getting Apex methods", str(e))
        raise typer.Exit(1)


@cli.command()
def list_accessible_sobjects(cli_context: typer.Context):
    """
    Will print accessible Standard and Custom sObjects respectively
    """
    try:
        payload = load_payload_json_for("ACTION$getConfigData.json")
        json_response = AuraActionRequest(payload, cli_context.obj).send_request()
        api_name_to_id_prefixes = json_response.get("apiNamesToKeyPrefixes")
        custom_sobject_list = []
        standard_sobject_list = []
        for key in api_name_to_id_prefixes.keys():
            if key.endswith("__c"):
                custom_sobject_list.append(key)
            else:
                standard_sobject_list.append(key)
        print_message("Custom sObject list", custom_sobject_list)
        print_message("Standard sObject list", standard_sobject_list)
    except Exception as e:
        print_error("Error getting sObject list", str(e))
        raise typer.Exit(1)


@cli.command()
def get_records(
    cli_context: typer.Context,
    sobject_name: Annotated[str, typer.Argument(help="The sObject API Name")] = "User",
    number_of_records: Annotated[
        int, typer.Argument(help="Number of records to fetch")
    ] = 10,
    dump: Annotated[
        bool, typer.Option("--dump", "-d", help="Dump records to a file")
    ] = False,
):
    """
    Get records by sObject API Name
    """
    MAX_PAGE_SIZE = 1000
    DEFAULT_PAGE = 1
    payload = load_payload_json_for("ACTION$getItems.json")
    payload["actions"][0]["params"]["entityNameOrId"] = sobject_name
    payload["actions"][0]["params"]["pageSize"] = number_of_records
    payload["actions"][0]["params"]["currentPage"] = DEFAULT_PAGE
    json_response = AuraActionRequest(payload, cli_context.obj).send_request()
    if json_response["result"] and json_response["totalCount"]:
        print_message(
            "Total records of type %s retrieved" % sobject_name,
            json_response["totalCount"],
        )
        retrieved_records = []
        for recordWraper in json_response["result"]:
            retrieved_records.append(recordWraper["record"])

        print_message("Records")
        print_json(retrieved_records)

        if dump:
            url_for_filename = cli_context.obj.url.replace("https://", "").replace(
                "/", "_"
            )
            dump_json_to_file(
                retrieved_records, f"{url_for_filename}-{sobject_name}-records.json"
            )
        return
    print_error("Error retrieving %s records" % sobject_name, "No records found")


if __name__ == "__main__":
    cli()
