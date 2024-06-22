from rich import print

ERROR_TEMPLATE = "[bold red][-] {title}:[/bold red] [yellow]{details}[/yellow]"
MESSAGE_TEMPLATE = "[bold green][+] {title}:[/bold green] {details}"


def print_message(title, message=""):
    print(MESSAGE_TEMPLATE.format(title=title, details=message))


def print_error(title, message=""):
    print(ERROR_TEMPLATE.format(title=title, details=message))


def print_json(json_data):
    print(json_data)


def print_component_apex_details(components_with_apex_details):
    for cmp in components_with_apex_details:
        print("    %s [%s]" % (cmp["component_name"], cmp["type"]))
        for method in cmp["methods"]:
            params = ""
            for param in method["params"]:
                if param == "UNKNOWN":
                    params = "???"
                    continue
                params += "%s %s, " % (
                    param["type"].replace("apex://", ""),
                    param["name"],
                )
            params = params[0:-2]
            print(
                "        %s.%s(%s)"
                % (method["classname"], method["methodname"], params)
            )
