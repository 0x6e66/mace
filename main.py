import sys
import os
import requests
from dotenv import load_dotenv

load_dotenv()

TOKEN = os.getenv("MALPEDIA_API_TOKEN")
URL = "https://malpedia.caad.fkie.fraunhofer.de"
SAMPLES_DIR = "./samples"


def main():
    if len(sys.argv) != 2:
        print("Usage: python main.py <malware family>")
        print("eg:    python main.py win.redline_stealer")

        exit(1)

    family = sys.argv[1]

    os.system(f"mkdir -p {SAMPLES_DIR}")
    res = get(f"/api/list/samples/{family}")

    os.system(f"mkdir {SAMPLES_DIR}/{family}")
    outdir = f"{SAMPLES_DIR}/{family}"

    for sample in filter(lambda x: x["status"] == "unpacked", res):
        hash = sample["sha256"]

        os.system(f"""
            curl -H "Authorization: apitoken {TOKEN}" https://malpedia.caad.fkie.fraunhofer.de/api/get/sample/{hash}/zip \
            | jq -r '.["zipped"]' | base64 -d > {outdir}/{hash}.zip""")


def get(endpoint):
    headers = {
        "Authorization": f"apitoken {TOKEN}"
    }
    return requests.get(
        url=f"{URL}{endpoint}",
        headers=headers
    ).json()


if __name__ == "__main__":
    main()
