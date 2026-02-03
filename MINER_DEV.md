# Miner Development Guide

Local development workflow for testing the miner agent and scorer without the full Docker-based validator pipeline.

## Prerequisites

- Python 3.10+ with venv
- `CHUTES_API_KEY` set in `.env` (required for both inference and scoring)

## Setup

```bash
python -m venv env && source env/bin/activate
pip install -U pip
pip install -r requirements.txt
```

## Starting the Inference Proxy

The miner agent calls an inference proxy that routes requests to the Chutes LLM API. Start it locally before running the miner.

### Option A: Run directly (no Docker)

```bash
source env/bin/activate
export CHUTES_API_KEY=$(grep CHUTES_API_KEY .env | cut -d= -f2)
cd validator/proxy
uvicorn api:app --host 0.0.0.0 --port 8087 --workers 1
```

### Option B: Run via Docker

```bash
docker build -f validator/proxy/Dockerfile validator/proxy \
  -t bitsec-proxy:latest --build-context loggers=loggers

docker run -d --name bitsec_proxy \
  -p 8087:8000 \
  -e CHUTES_API_KEY=$(grep CHUTES_API_KEY .env | cut -d= -f2) \
  bitsec-proxy:latest
```

### Verify the proxy is running

```bash
curl http://localhost:8087/
# Should return: {"service":"Chutes Proxy","status":"running",...}
```

## Running the Miner Locally

The `test-local` command runs the miner agent directly against project source code (no Docker containers), then scores findings against the benchmark.

### Single project

```bash
python bitsec.py miner test-local --project code4rena_secondswap_2025_02
```

### All projects

```bash
python bitsec.py miner test-local
```

### Miner only (skip scoring)

```bash
python bitsec.py miner test-local --skip-scoring --project code4rena_secondswap_2025_02
```

### Custom inference endpoint

```bash
python bitsec.py miner test-local --inference-api http://localhost:8087
```

### CLI Options

| Option | Default | Description |
|---|---|---|
| `--project` | all projects | Run a single project key from `miner/projects.json` |
| `--inference-api` | `http://localhost:8087` | Inference proxy URL |
| `--skip-scoring` | `False` | Skip the scorer phase (miner only) |

## Available Projects

Defined in `miner/projects.json`:

| Key | Name |
|---|---|
| `code4rena_superposition_2025_01` | Superposition |
| `code4rena_lambowin_2025_02` | Lambo.win |
| `code4rena_loopfi_2025_02` | LoopFi |
| `code4rena_secondswap_2025_02` | SecondSwap |

Projects are automatically downloaded from GitHub on first run.

## Output

Results are saved to `jobs/local_test/<project_key>/`:

| File | Contents |
|---|---|
| `report.json` | Miner findings wrapped in `{"success": true, "report": {...}}` format |
| `evaluation.json` | Scorer results with detection rate, precision, F1, matched/missed findings |

A summary table is printed to the console after all projects complete:

```
Project          Findings  Detection  Precision    F1  TP/FN/FP
secondswap_2025       28      33.3%       3.6%  6.5%    1/2/27
```

## Architecture

```
bitsec.py miner test-local
  -> miner/test_local.py: run_local_test()
       -> scripts/projects.py: fetch project source from GitHub
       -> miner/agent.py: agent_main() analyzes .sol files via inference proxy
       -> validator/scorer.py: ScaBenchScorerV2 scores findings against benchmark
```

- **Miner agent** (`miner/agent.py`): Sends each source file to the LLM via the inference proxy, parses vulnerability findings
- **Inference proxy** (`validator/proxy/`): FastAPI app that forwards requests to Chutes API (`https://llm.chutes.ai`)
- **Scorer** (`validator/scorer.py`): Uses LLM to match agent findings against curated benchmark (`validator/curated-highs-only-2025-08-08.json`)
- **Model**: `deepseek-ai/DeepSeek-V3-0324` (hardcoded in agent config)

## Troubleshooting

### "Connection refused" on all files

The inference proxy is not running. Start it with the commands above.

### "CHUTES_API_KEY not set"

Add your key to `.env`:

```
CHUTES_API_KEY=cpk_...
```

### Scorer fails to initialize

The scorer also needs `CHUTES_API_KEY`. Use `--skip-scoring` to test the miner without scoring.

### Agent exits with code 1

Check the proxy logs for Chutes API errors (rate limits, invalid key, model unavailable). The test runner catches per-project failures and continues to the next project.
