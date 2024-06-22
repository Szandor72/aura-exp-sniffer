import os
import json


def load_payload_json_for(filename: str):
    file_path = os.path.join(
        os.getcwd(), "aura_exp_sniffer", "request_templates", filename
    )
    with open(file_path, "r") as file:
        payload = json.load(file)
    return payload
