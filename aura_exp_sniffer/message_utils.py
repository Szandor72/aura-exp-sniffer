from rich import print

ERROR_TEMPLATE = "[bold red][-] {title}:[/bold red] [yellow]{details}[/yellow]"
MESSAGE_TEMPLATE = "[bold green][+] {title}:[/bold green] {details}"


def print_message(title, message=""):
    print(MESSAGE_TEMPLATE.format(title=title, details=message))


def print_error(title, message=""):
    print(ERROR_TEMPLATE.format(title=title, details=message))


def print_json(json_data):
    print(json_data)
