import os
import json


def load_payload_json_for(filename: str):
    file_path = os.path.join(
        os.getcwd(), "aura_exp_sniffer", "request_templates", filename
    )
    with open(file_path, "r") as file:
        payload = json.load(file)
    return payload


def dump_json_to_file(json_data: json, filename: str):
    """
    Dumps JSON data to a file.
    """
    file_path = os.path.join(os.getcwd(), "file-dumps", filename)
    os.makedirs(os.path.dirname(file_path), exist_ok=True)
    with open(file_path, "w") as file:
        json.dump(json_data, file, indent=4)
