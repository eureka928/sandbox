"""
Local test runner for the miner agent + scorer pipeline.

Runs agent_main() directly against local project directories (no Docker),
then optionally scores findings against the ScaBench benchmark.
"""

import json
import os
import sys
from dataclasses import asdict
from pathlib import Path

from rich.console import Console
from rich.table import Table
from rich import box

from miner.agent import agent_main
from scripts.projects import init_project, PROJECTS_DIR, PROJECTS_FILE
from loggers.logger import get_logger

logger = get_logger()
console = Console()

BENCHMARK_FILE = os.path.join(
    "validator", "curated-highs-only-2025-08-08.json"
)
JOBS_DIR = os.path.join("jobs", "local_test")


def _load_projects():
    """Load project definitions from miner/projects.json."""
    with open(PROJECTS_FILE, "r", encoding="utf-8") as f:
        return json.load(f)


def _load_benchmark():
    """Load benchmark data and return a dict keyed by project_id."""
    if not os.path.exists(BENCHMARK_FILE):
        console.print(
            f"[yellow]Benchmark file not found: {BENCHMARK_FILE}[/yellow]"
        )
        return {}
    with open(BENCHMARK_FILE, "r", encoding="utf-8") as f:
        data = json.load(f)
    return {
        e["project_id"]: e.get("vulnerabilities", [])
        for e in data
        if e.get("project_id") and e.get("vulnerabilities")
    }


def _ensure_project(project):
    """Download and extract a project if not already present."""
    os.makedirs(PROJECTS_DIR, exist_ok=True)
    init_project(project)
    project_dir = os.path.join(PROJECTS_DIR, project["project_key"])
    if not os.path.isdir(project_dir):
        raise FileNotFoundError(
            f"Project directory not found after fetch: {project_dir}"
        )
    return project_dir


def run_local_test(
    project_keys=None,
    inference_api="http://localhost:8087",
    skip_scoring=False,
):
    """
    Run the miner agent locally on projects and optionally score results.

    Args:
        project_keys: List of project keys to test, or None for all.
        inference_api: URL of the inference API endpoint.
        skip_scoring: If True, skip the scoring phase.
    """
    all_projects = _load_projects()

    if project_keys:
        projects = [
            p for p in all_projects if p["project_key"] in project_keys
        ]
        missing = set(project_keys) - {p["project_key"] for p in projects}
        if missing:
            console.print(
                f"[red]Unknown project keys: {', '.join(missing)}[/red]"
            )
            console.print(
                "Available: "
                + ", ".join(p["project_key"] for p in all_projects)
            )
            sys.exit(1)
    else:
        projects = all_projects

    benchmark_map = {} if skip_scoring else _load_benchmark()

    results_summary = []

    for project in projects:
        project_key = project["project_key"]
        console.print(
            f"\n[bold cyan]{'=' * 60}[/bold cyan]"
            f"\n[bold cyan]Project: {project_key}[/bold cyan]"
            f"\n[bold cyan]{'=' * 60}[/bold cyan]"
        )

        # Fetch project source
        try:
            project_dir = _ensure_project(project)
        except Exception as e:
            console.print(f"[red]Failed to fetch project: {e}[/red]")
            results_summary.append({"project": project_key, "error": str(e)})
            continue

        # Run the miner agent
        console.print(f"\n[bold]Running agent on {project_dir}[/bold]")
        try:
            report = agent_main(
                project_dir=project_dir, inference_api=inference_api
            )
        except SystemExit:
            console.print(f"[red]Agent failed for {project_key}[/red]")
            results_summary.append(
                {"project": project_key, "error": "agent_main exited"}
            )
            continue

        # Wrap in expected report.json format
        report_data = {"success": True, "report": report}

        # Save report
        output_dir = os.path.join(JOBS_DIR, project_key)
        os.makedirs(output_dir, exist_ok=True)
        report_path = os.path.join(output_dir, "report.json")
        with open(report_path, "w", encoding="utf-8") as f:
            json.dump(report_data, f, indent=2)
        console.print(f"[green]Report saved to {report_path}[/green]")

        # Score if benchmark data exists and scoring not skipped
        if skip_scoring:
            results_summary.append(
                {
                    "project": project_key,
                    "findings": report.get("total_vulnerabilities", 0),
                    "scored": False,
                }
            )
            continue

        expected_findings = benchmark_map.get(project_key)
        if not expected_findings:
            console.print(
                f"[yellow]No benchmark data for {project_key}, "
                f"skipping scoring[/yellow]"
            )
            results_summary.append(
                {
                    "project": project_key,
                    "findings": report.get("total_vulnerabilities", 0),
                    "scored": False,
                    "reason": "no benchmark data",
                }
            )
            continue

        # Import scorer here to avoid import errors when not scoring
        from validator.scorer import ScaBenchScorerV2
        from config import settings

        scorer_config = {
            "api_key": settings.chutes_api_key,
            "api_url": inference_api,
            "debug": True,
            "verbose": True,
            "confidence_threshold": 0.75,
            "strict_matching": False,
        }

        try:
            scorer = ScaBenchScorerV2(scorer_config)
        except Exception as e:
            console.print(f"[red]Failed to initialize scorer: {e}[/red]")
            console.print(
                "[yellow]Ensure CHUTES_API_KEY is set in .env[/yellow]"
            )
            results_summary.append(
                {
                    "project": project_key,
                    "findings": report.get("total_vulnerabilities", 0),
                    "scored": False,
                    "reason": f"scorer init failed: {e}",
                }
            )
            continue

        agent_findings = report.get("vulnerabilities", [])
        console.print(
            f"\n[bold]Scoring {project_key}: "
            f"{len(expected_findings)} expected vs "
            f"{len(agent_findings)} found[/bold]"
        )

        scoring_result = scorer.score_project(
            expected_findings=expected_findings,
            tool_findings=agent_findings,
            project_name=project_key,
        )

        # Save evaluation
        eval_path = os.path.join(output_dir, "evaluation.json")
        with open(eval_path, "w", encoding="utf-8") as f:
            json.dump(asdict(scoring_result), f, indent=2)
        console.print(f"[green]Evaluation saved to {eval_path}[/green]")

        results_summary.append(
            {
                "project": project_key,
                "findings": len(agent_findings),
                "scored": True,
                "detection_rate": scoring_result.detection_rate,
                "precision": scoring_result.precision,
                "f1_score": scoring_result.f1_score,
                "true_positives": scoring_result.true_positives,
                "false_negatives": scoring_result.false_negatives,
                "false_positives": scoring_result.false_positives,
            }
        )

    # Print aggregate summary
    _print_summary(results_summary)


def _print_summary(results):
    """Print a summary table of all project results."""
    console.print(f"\n[bold]{'=' * 60}[/bold]")
    console.print("[bold]SUMMARY[/bold]")
    console.print(f"[bold]{'=' * 60}[/bold]\n")

    table = Table(box=box.ROUNDED)
    table.add_column("Project", style="cyan")
    table.add_column("Findings", justify="right")
    table.add_column("Detection", justify="right")
    table.add_column("Precision", justify="right")
    table.add_column("F1", justify="right")
    table.add_column("TP/FN/FP", justify="right")

    total_tp = 0
    total_fn = 0
    total_fp = 0
    scored_count = 0

    for r in results:
        if "error" in r:
            table.add_row(r["project"], "[red]ERROR[/red]", "-", "-", "-", "-")
            continue

        findings = str(r.get("findings", 0))

        if not r.get("scored"):
            table.add_row(r["project"], findings, "-", "-", "-", "-")
            continue

        scored_count += 1
        tp = r["true_positives"]
        fn = r["false_negatives"]
        fp = r["false_positives"]
        total_tp += tp
        total_fn += fn
        total_fp += fp

        table.add_row(
            r["project"],
            findings,
            f"{r['detection_rate'] * 100:.1f}%",
            f"{r['precision'] * 100:.1f}%",
            f"{r['f1_score'] * 100:.1f}%",
            f"{tp}/{fn}/{fp}",
        )

    # Aggregate row
    if scored_count > 1:
        agg_det = (
            total_tp / (total_tp + total_fn)
            if (total_tp + total_fn) > 0
            else 0.0
        )
        agg_prec = (
            total_tp / (total_tp + total_fp)
            if (total_tp + total_fp) > 0
            else 0.0
        )
        agg_f1 = (
            2 * agg_prec * agg_det / (agg_prec + agg_det)
            if (agg_prec + agg_det) > 0
            else 0.0
        )
        table.add_row(
            "[bold]TOTAL[/bold]",
            "",
            f"[bold]{agg_det * 100:.1f}%[/bold]",
            f"[bold]{agg_prec * 100:.1f}%[/bold]",
            f"[bold]{agg_f1 * 100:.1f}%[/bold]",
            f"[bold]{total_tp}/{total_fn}/{total_fp}[/bold]",
        )

    console.print(table)
