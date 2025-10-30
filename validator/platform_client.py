from __future__ import annotations

import os
import json
from typing import Any, Literal
import requests

from validator.models.platform import JobRun, AgentExecution, AgentEvaluation


class PlatformError(Exception):
    def __init__(self, message: str, status_code: int | None = None, details: Any | None = None):
        super().__init__(message)
        self.status_code = status_code
        self.details = details


class PlatformClient:
    def __init__(self, base_url: str, api_key: str, timeout: int = 10):
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key
        self.timeout = timeout

        self.headers = {"Authorization": f"Bearer {self.api_key}"}

    def _call_api(
        self,
        method: Literal["GET", "POST", "PUT", "PATCH", "DELETE"],
        endpoint: str,
        *,
        params: dict[str, Any] | None = None,
        json: dict[str, Any] | None = None,
    ) -> dict[str, Any] | list[Any] | None:
        url = f"{self.base_url}/api/{endpoint.lstrip('/')}"

        try:
            response = requests.request(
                method=method,
                url=url,
                params=params,
                json=json,
                headers=self.headers,
                timeout=self.timeout,
            )
            response.raise_for_status()

        except requests.HTTPError as exc:
            try:
                details = exc.response.json()
            except Exception:
                details = exc.response.text

            raise PlatformError(
                f"Platform API request failed ({exc.response.status_code}): {details}",
                status_code=exc.response.status_code,
                details=details,
            ) from exc

        except requests.RequestException as exc:
            raise PlatformError(f"Request failed: {exc}") from exc

        if not response.text.strip():
            return None

        try:
            return response.json()

        except json.JSONDecodeError:
            raise PlatformError(f"Expected JSON response from {url}, got invalid JSON.")

    def get_next_job_run(self, validator_id: int):
        endpoint = f"jobs/runs/validator/{validator_id}"
        resp = self._call_api('get', endpoint)
        if not resp:
            return

        job_run = JobRun.model_validate(resp)
        return job_run

    def get_job_run_code(self, job_run_id: int):
        endpoint = f"jobs/runs/{job_run_id}/code"
        resp = self._call_api('get', endpoint)
        return resp['code']

    def submit_agent_execution(self, agent_execution: AgentExecution) -> dict:
        endpoint = f"agents/execution/"
        payload = agent_execution.model_dump(mode="json")
        resp = self._call_api("post", endpoint, json=payload)
        return resp

    def submit_agent_evaluation(self, agent_evaluation: AgentEvaluation) -> dict:
        endpoint = f"agents/evaluation/"
        payload = agent_evaluation.model_dump(mode="json")
        resp = self._call_api("post", endpoint, json=payload)
        return resp

    def start_job_run(self, job_run_id: int) -> dict:
        endpoint = f"jobs/runs/{job_run_id}/start"
        resp = self._call_api("post", endpoint)
        return resp

    def complete_job_run(self, job_run_id: int, status='success') -> dict:
        endpoint = f"jobs/runs/{job_run_id}/complete"
        payload = {
            "status": status,
        }
        resp = self._call_api("post", endpoint, json=payload)
        return resp
