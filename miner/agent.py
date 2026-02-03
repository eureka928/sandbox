import hashlib
import json
import os
import re
import requests
import sys
import time
import traceback
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Any
from textwrap import dedent


from langchain.output_parsers import PydanticOutputParser
from pydantic import BaseModel
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TimeRemainingColumn
from rich.panel import Panel


MAX_WORKERS = 4

console = Console()


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"

class Vulnerability(BaseModel):
    """A security vulnerability finding."""
    title: str
    description: str
    vulnerability_type: str
    severity: Severity
    confidence: float
    location: str
    file: str
    id: str | None = None
    reported_by_model: str = ""
    status: str = "proposed"

    def __init__(self, **data):
        super().__init__(**data)
        if not self.id:
            id_source = f"{self.file}:{self.title}"
            self.id = hashlib.md5(id_source.encode()).hexdigest()[:16]

class Vulnerabilities(BaseModel):
    """A collection of security vulnerability vulnerabilities."""
    vulnerabilities: list[Vulnerability]

class AnalysisResult(BaseModel):
    """Result from analyzing a project."""
    project: str
    timestamp: str
    files_analyzed: int
    files_skipped: int
    total_vulnerabilities: int
    vulnerabilities: list[Vulnerability]
    token_usage: dict[str, int]


class BaselineRunner:
    def __init__(self, config: dict[str, Any] | None = None, inference_api: str = None):
        self.config = config or {}
        self.model = self.config['model']
        self.inference_api = inference_api or os.getenv('INFERENCE_API', "http://bitsec_proxy:8000")
        self.project_id = os.getenv('PROJECT_ID', "local")
        self.job_id = os.getenv('JOB_ID', "local")

        console.print(f"Inference: {self.inference_api}")

    def inference(self, messages: dict[str, Any]) -> dict[str, Any]:
        payload = {
            "model": self.config['model'],
            "messages": messages,
        }

        headers = {
            "x_project_id": self.project_id or "local",
            "x_job_id": self.job_id,
        }

        resp = None
        try:
            inference_url = f"{self.inference_api}/inference"
            resp = requests.post(
                inference_url,
                headers=headers,
                json=payload,
            )
            resp.raise_for_status()

        except requests.exceptions.HTTPError as e:
            # This prevents the AttributeError when requests.post() raises a RequestException before returning
            if resp is not None:
                try:
                    error_detail = resp.json()
                except (ValueError, AttributeError):
                    error_detail = resp.text if hasattr(resp, 'text') else str(resp)
            else:
                error_detail = "No response received"
            console.print(f"Inference Proxy Error: {e} {error_detail}")
            raise

        except requests.exceptions.RequestException as e:
            if resp is not None:
                try:
                    error_detail = resp.json()
                except (ValueError, AttributeError):
                    error_detail = resp.text if hasattr(resp, 'text') else str(resp)
            else:
                error_detail = "No response received"
            console.print(f"Inference Error: {e} {error_detail}")
            raise

        return resp.json()

    def clean_json_response(self, response_content: str) -> dict[str, Any]:
        while response_content.startswith("_\n"):
            response_content = response_content[2:]

        response_content = response_content.strip()

        if response_content.startswith("return"):
            response_content = response_content[6:]

        response_content = response_content.strip()

        # Remove code block markers if present
        if response_content.startswith("```") and response_content.endswith("```"):
            lines = response_content.splitlines()

            if lines[0].startswith("```"):
                lines = lines[1:]

            if lines and lines[-1].strip() == "```":
                lines = lines[:-1]

            response_content = "\n".join(lines).strip()

        resp_json = json.loads(response_content)

        return resp_json

    def post_process_vulnerabilities(
        self, vulnerabilities: Vulnerabilities, file_path: str
    ) -> Vulnerabilities:
        """Post-process vulnerabilities: filter by confidence and standardize locations."""
        confidence_threshold = 0.75
        filtered = []
        filtered_count = 0

        for v in vulnerabilities.vulnerabilities:
            calibrated_confidence = v.confidence

            # Boost confidence for well-formed Contract.function locations
            location_parts = v.location.replace(":", ".").split(".")
            if len(location_parts) >= 2:
                # Check if first part looks like a contract name (capitalized)
                if location_parts[0] and location_parts[0][0].isupper():
                    calibrated_confidence = min(1.0, calibrated_confidence + 0.05)

            # Reduce confidence for vague language (word boundaries to avoid "payment")
            vague_patterns = [
                r"\bmight\b", r"\bpossibly\b", r"\bcould potentially\b",
                r"\bmay be\b", r"\bmay cause\b", r"\bmay lead\b"
            ]
            desc_lower = v.description.lower()
            if any(re.search(p, desc_lower) for p in vague_patterns):
                calibrated_confidence = max(0.0, calibrated_confidence - 0.1)

            v.confidence = round(calibrated_confidence, 2)

            # Filter by confidence threshold
            if v.confidence < confidence_threshold:
                filtered_count += 1
                continue

            # Normalize location format
            v.location = self._normalize_location(v.location, file_path)

            # Ensure file field is set
            if not v.file:
                v.file = file_path

            filtered.append(v)

        if filtered_count > 0:
            console.print(
                f"[dim]  → Filtered {filtered_count} low-confidence findings[/dim]"
            )

        return Vulnerabilities(vulnerabilities=filtered)

    def _normalize_location(self, location: str, file_path: str) -> str:
        """Normalize location to file_path:Contract.function format."""
        location = location.strip()

        # Already has file path
        if file_path in location:
            return location

        # Has some file reference with colon
        if ":" in location and "/" in location.split(":")[0]:
            return location

        # Just Contract.function - prepend file path
        if ":" not in location:
            return f"{file_path}:{location}"

        return location

    def analyze_file(self, relative_path: str, content: str) -> tuple[Vulnerabilities, int, int]:
        """Analyze a single file for security vulnerabilities.
        
        Returns:
            Tuple of (vulnerabilities, input_tokens, output_tokens)
        """
        file_path = Path(relative_path)

        console.print(f"[dim]  → Analyzing {relative_path} ({len(content)} bytes)[/dim]")

        parser = PydanticOutputParser(pydantic_object=Vulnerabilities)
        format_instructions = parser.get_format_instructions()

        system_prompt = dedent(f"""
            You are an expert smart contract security auditor. Find ALL exploitable vulnerabilities.

            ## DESCRIPTION REQUIREMENTS (CRITICAL FOR MATCHING)
            Each finding description MUST include these elements for proper detection:
            1. **Filename**: Include the .sol filename (e.g., "In Vault.sol, the...")
            2. **Function call pattern**: Reference functions as `functionName(` (e.g., "the withdraw() function")
            3. **Core mechanism**: The specific flaw (e.g., "state updated after external call")
            4. **Impact**: Concrete consequence (e.g., "allows attacker to drain all funds")

            ## LOCATION FORMAT
            Use: `ContractName.functionName` (e.g., `Vault.withdraw`)

            ## VULNERABILITY TYPES (use exact names)
            reentrancy, access-control, integer-overflow, flash-loan-attack,
            front-running, denial-of-service, logic-error, oracle-manipulation,
            precision-loss, unchecked-external-call, storage-collision

            ## SEVERITY
            - critical: Direct fund loss, no preconditions
            - high: Fund loss with conditions, protocol disruption
            - medium: Limited loss, multiple steps required
            - low: Minor issues, theoretical only

            ## CONFIDENCE (0.0-1.0)
            - 0.9+: Definite vulnerability with clear exploit
            - 0.8-0.9: High confidence, minor uncertainty
            - 0.75-0.8: Confident but needs specific conditions
            - Only report if confidence >= 0.75

            ## EXAMPLE GOOD DESCRIPTION
            "In Vault.sol, the withdraw() function updates the user balance after calling
            an external contract via transfer(). An attacker can deploy a malicious contract
            that re-enters withdraw() before the balance update, draining all ETH from the vault."

            ## DO NOT REPORT
            - Gas optimizations (unless DoS)
            - Code style issues
            - Theoretical issues without exploit path

            {format_instructions}

            IMPORTANT: Output ONLY valid JSON. Begin with `{{"vulnerabilities":`
        """)

        # Extract just the filename for clearer reference
        filename = file_path.name

        user_prompt = dedent(f"""
            Analyze {filename} for security vulnerabilities.

            File path: {relative_path}
            ```{file_path.suffix[1:] if file_path.suffix else 'txt'}
            {content}
            ```

            For each vulnerability found:
            - Reference the file as "{filename}" in descriptions
            - Use function() notation when mentioning functions
            - Set location to ContractName.functionName format
            - Set file field to "{relative_path}"
        """)

        try:
            messages = [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt},
            ]

            response = self.inference(messages=messages)
            response_content = response['content'].strip()

            msg_json = self.clean_json_response(response_content)

            vulnerabilities = Vulnerabilities(**msg_json)
            for v in vulnerabilities.vulnerabilities:
                v.reported_by_model = self.config['model']

            # Post-process vulnerabilities
            vulnerabilities = self.post_process_vulnerabilities(
                vulnerabilities, relative_path
            )

            if vulnerabilities.vulnerabilities:
                console.print(f"[green]  → Found {len(vulnerabilities.vulnerabilities)} vulnerabilities[/green]")
            else:
                console.print("[yellow]  → No vulnerabilities found[/yellow]")

            input_tokens = response.get('input_tokens', 0)
            output_tokens = response.get('output_tokens', 0)

            return vulnerabilities, input_tokens, output_tokens
            
        except Exception as e:
            console.print(f"[red]Error analyzing {file_path.name}: {e}[/red]")
            return Vulnerabilities(vulnerabilities=[]), 0, 0

    def process_file(self, file_path, source_dir):
        relative_path = str(file_path.relative_to(source_dir))

        try:
            with open(file_path, "r", encoding="utf-8") as f:
                content = f.read()

            if not content.strip():
                return "skipped", None

            vulnerabilities, input_tokens, output_tokens = self.analyze_file(
                relative_path, content
            )

            return "ok", (
                vulnerabilities.vulnerabilities,
                input_tokens,
                output_tokens,
            )

        except Exception as e:
            return "error", (file_path.name, e)

    def analyze_project(
        self, 
        source_dir: Path,
        project_name: str,
        file_patterns: list[str] | None = None
    ) -> AnalysisResult:
        """Analyze a project for security vulnerabilities.
        
        Args:
            source_dir: Directory containing source files
            project_name: Name of the project
            file_patterns: List of glob patterns for files to analyze
            
        Returns:
            AnalysisResult with vulnerabilities
        """
        console.print("\n[bold cyan]Analyzing project[/bold cyan]")
        
        # Find files to analyze
        if file_patterns:
            files = []
            for pattern in file_patterns:
                files.extend(source_dir.glob(pattern))

        else:
            # Default to common smart contract patterns
            patterns = ['**/*.sol', '**/*.vy', '**/*.cairo', '**/*.rs', '**/*.move']
            files = []
            for pattern in patterns:
                files.extend(source_dir.glob(pattern))
        
        # Remove duplicates and filter
        exclude_dirs = {"testing", "mocks", "examples"}
        files = set(files)
        files = [
            f for f 
            in files 
            if f.is_file() and 'test' not in f.name.lower()
            and not any(part.lower() in exclude_dirs for part in f.parts)
        ]

        if not files:
            console.print("[yellow]No files found to analyze[/yellow]")
            return AnalysisResult(
                project=project_name,
                timestamp=datetime.now().isoformat(),
                files_analyzed=0,
                files_skipped=0,
                total_vulnerabilities=0,
                vulnerabilities=[],
                token_usage={'input_tokens': 0, 'output_tokens': 0, 'total_tokens': 0}
            )

        console.print(f"[dim]Found {len(files)} files to analyze[/dim]")

        # Analyze files
        all_vulnerabilities = []
        files_analyzed = 0
        files_skipped = 0
        total_input_tokens = 0
        total_output_tokens = 0

        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
            TimeRemainingColumn(),
            console=console,
            transient=False
        ) as progress:
            task = progress.add_task(f"Analyzing {len(files)} files...", total=len(files))

            with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
                futures = {
                    executor.submit(self.process_file, file_path, source_dir): file_path
                    for file_path in files
                }

                for future in as_completed(futures):
                    result_type, result = future.result()

                    if result_type == "ok":
                        vulns, in_tok, out_tok = result
                        all_vulnerabilities.extend(vulns)
                        files_analyzed += 1
                        total_input_tokens += in_tok
                        total_output_tokens += out_tok

                    elif result_type == "skipped":
                        files_skipped += 1

                    elif result_type == "error":
                        filename, err = result
                        console.print(f"[red]Error processing {filename}: {err}[/red]")
                        files_skipped += 1

                    progress.advance(task)

        # Deduplicate vulnerabilities
        unique_vulnerabilities = {
            v.id: v for v in all_vulnerabilities
        }
        vulns = list(unique_vulnerabilities.values())
        
        result = AnalysisResult(
            project=project_name,
            timestamp=datetime.now().isoformat(),
            files_analyzed=files_analyzed,
            files_skipped=files_skipped,
            total_vulnerabilities=len(unique_vulnerabilities),
            vulnerabilities=vulns,
            token_usage={
                'input_tokens': total_input_tokens,
                'output_tokens': total_output_tokens,
                'total_tokens': total_input_tokens + total_output_tokens
            }
        )

        self.print_summary(result)
        
        return result

    def print_summary(self, result: AnalysisResult):
        """Print analysis summary."""
        console.print(f"\n[bold]Summary for {result.project}:[/bold]")
        console.print(f"  Files analyzed: {result.files_analyzed}")
        console.print(f"  Files skipped: {result.files_skipped}")
        console.print(f"  Total vulnerabilities: {result.total_vulnerabilities}")
        console.print(f"  Token usage: {result.token_usage['total_tokens']:,}")
        console.print(f"    Input tokens: {result.token_usage['input_tokens']:,}")
        console.print(f"    Output tokens: {result.token_usage['output_tokens']:,}")

        if result.vulnerabilities:
            # Count by severity
            severity_counts = {}
            for vulnerability in result.vulnerabilities:
                sev = vulnerability.severity
                severity_counts[sev] = severity_counts.get(sev, 0) + 1

            console.print("  By severity:")
            for sev in [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW]:
                if sev.value in severity_counts:
                    color = {
                        Severity.CRITICAL: 'red',
                        Severity.HIGH: 'orange1',
                        Severity.MEDIUM: 'yellow',
                        Severity.LOW: 'green'
                    }[sev]
                    console.print(f"    [{color}]{sev.value.capitalize()}:[/{color}] {severity_counts[sev.value]}")

    def save_result(self, result: AnalysisResult, output_file: str = "agent_report.json"):
        result_dict = result.model_dump()

        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(result_dict, f, indent=2)

        console.print(f"\n[green]Results saved to: {output_file}[/green]")
        return output_file


def agent_main(project_dir: str = None, inference_api: str = None):
    config = {
        'model': "deepseek-ai/DeepSeek-V3-0324"
    }

    if not project_dir:
        project_dir = "/app/project_code"

    console.print(Panel.fit(
        "[bold cyan]SCABENCH BASELINE RUNNER[/bold cyan]\n"
        f"[dim]Model: {config['model']}[/dim]\n",
        border_style="cyan"
    ))

    try:
        runner = BaselineRunner(config, inference_api)

        source_dir = Path(project_dir) if project_dir else None
        if not source_dir or not source_dir.exists() or not source_dir.is_dir():
            console.print(f"[red]Error: Invalid source directory: {project_dir}[/red]")
            sys.exit(1)
        
        result = runner.analyze_project(
            source_dir=source_dir,
            project_name=project_dir,
        )
        
        output_file = runner.save_result(result)
        
        # Final summary
        console.print("\n" + ("=" * 60))
        console.print(Panel.fit(
            f"[bold green]ANALYSIS COMPLETE[/bold green]\n\n"
            f"Project: {result.project}\n"
            f"Files analyzed: {result.files_analyzed}\n"
            f"Total vulnerabilities: {result.total_vulnerabilities}\n"
            f"Results saved to: {output_file}",
            border_style="green"
        ))

        return result.model_dump(mode="json")
        
    except ValueError as e:
        console.print(f"[red]Configuration error: {e}[/red]")
        sys.exit(1)

    except Exception as e:
        console.print(f"[red]Error: {e}[/red]")
        print(traceback.print_exc())
        sys.exit(1)


if __name__ == '__main__':
    from scripts.projects import fetch_projects
    from validator.manager import SandboxManager

    SandboxManager(is_local=True)
    time.sleep(10) # wait for proxy to start
    fetch_projects()
    inference_api = 'http://localhost:8087'
    report = agent_main('projects/code4rena_secondswap_2025_02', inference_api=inference_api)
