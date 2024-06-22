import typer
from typing_extensions import Annotated
from types import SimpleNamespace
import json


from exp_cloud_requests import AuraEndpointSelector, AuraConfigLoader, AuraActionRequest
from message_utils import print_message, print_error
from file_utils import load_payload_json_for

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
            session_id=session_id,
            active_endpoint="",
            aura_config={},
        )
    if not all([cli_context.obj.active_endpoint, cli_context.obj.aura_config]):
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
            cli_context.obj.url
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
        aura_endpoint_config = AuraConfigLoader(cli_context.obj.url).get_aura_config()
    except Exception as e:
        raise typer.Exit(1)

    cli_context.obj.aura_config = aura_endpoint_config

    print_message(":white_check_mark: Success", "Aura Endpoint Config set")


@cli.command()
def fetch(cli_context: typer.Context):
    """
    Not implemented
    """
    try:
        payload = load_payload_json_for("ACTION$getConfigData.json")
        print(json.dumps(payload, indent=2))
        json_response = AuraActionRequest(
            cli_context.obj.active_endpoint,
            json.dumps(payload),
            cli_context.obj.aura_config,
            cli_context.obj.aura_token,
            cli_context.obj.session_id,
        ).send_request()
        print_message("SObject List", json_response)
    except Exception as e:
        print_error("Error getting sObject list", str(e))
        raise typer.Exit(1)


if __name__ == "__main__":
    cli()
