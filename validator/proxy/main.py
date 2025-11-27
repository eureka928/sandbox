from fastapi import FastAPI, Header
import os
import json
import requests
import time
from loggers.logger import get_logger
from models import InferenceRequest, InferenceResponse


logger = get_logger()
app = FastAPI(title="Chutes Proxy")

CHUTES_API_KEY = os.getenv("CHUTES_API_KEY")
if not CHUTES_API_KEY:
    raise RuntimeError("CHUTES_API_KEY environment variable is required!")

CHUTES_API_URL = "https://llm.chutes.ai/v1/chat/completions"
DEFAULT_MODEL = "unsloth/gemma-3-12b-it"
# DEFAULT_MODEL = "deepseek-ai/DeepSeek-V3.1"
TIMEOUT = 300
MAX_RETRIES = 5
BACKOFF_FACTOR = 1.5


@app.post("/inference", response_model=InferenceResponse)
async def inference(
    request: InferenceRequest,
    x_job_id: str = Header(default="unknown"),
    x_project_id: str = Header(default="unknown"),
):
    logger.info(f"Request from [J:{x_job_id}|P:{x_project_id}]")

    if not request.model:
        request.model = DEFAULT_MODEL

    headers = {
        "Authorization": f"Bearer {CHUTES_API_KEY}"
    }
    payload_dict = request.model_dump()

    for attempt in range(1, MAX_RETRIES + 1):
        try:
            logger.info(f"Sending request to Chutes. Attempt: {attempt}")
            resp = requests.post(CHUTES_API_URL, headers=headers, json=payload_dict, timeout=TIMEOUT)

            resp.raise_for_status()
            break

            # TODO: Add handling for errors, pass on some errors

        except requests.RequestException as e:
            status = resp.status_code
            if status not in (502, 429):
                logger.error(f"Chutes API non-retryable error: {e} {resp.text}")
                break

            if attempt == MAX_RETRIES:
                logger.error(f"Chutes API error after {attempt} attempts: {e} {resp.text}")

            sleep_time = BACKOFF_FACTOR * (2 ** (attempt - 1))
            logger.warning(f"Received {status} from Chutes API, retrying in {sleep_time:.1f}s...")
            time.sleep(sleep_time)

    resp_json = resp.json()
    logger.info(f"Received response from Chutes: {json.dumps(resp_json, indent=2)}")

    if "choices" in resp_json and len(resp_json["choices"]):
        choice_message = resp_json["choices"][0]["message"]
        response = {
            "content": choice_message["content"],
            "role": choice_message["role"],
            "input_tokens": resp_json["usage"]["prompt_tokens"],
            "output_tokens": resp_json["usage"]["completion_tokens"],
        }
        return response

    else:
        logger.error(f"No choices received: {resp_json}")
