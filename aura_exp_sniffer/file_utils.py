from pathlib import Path
import json


def load_payload_json_for(filename: str):
    file_path = Path("aura_exp_sniffer", "request_templates", filename)
    with file_path.open("r") as file:
        payload = json.load(file)
    return payload


def dump_json_to_file(json_data: json, filename: str):
    """
    Dumps JSON data to a file.
    """
    file_path = Path("file-dumps", filename)
    file_path.parent.mkdir(parents=True, exist_ok=True)
    with file_path.open("w") as file:
        json.dump(json_data, file, indent=4)
