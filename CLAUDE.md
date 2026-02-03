# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Bitsec Subnet v2 is a Bittensor-based security audit subnet that creates an incentive mechanism for AI-powered security analysis of code repositories. It consists of three main components:
- **Miner**: Generates security analysis for code projects (`miner/agent.py`)
- **Validator**: Evaluates and scores submitted agents (`validator/manager.py`, `validator/executor.py`, `validator/scorer.py`)
- **Platform Client**: Manages API communication (`validator/platform_client.py`)

## Commands

### Setup
```bash
python -m venv env && source env/bin/activate
pip install -U pip
pip install -r requirements.txt
```

### Testing
```bash
pytest                                    # Run all tests
pytest tests/test_run_sandbox.py -v       # Run specific test file
```

### Code Formatting & Linting
```bash
black --line-length 79 .                  # Format code
black --line-length 79 --check .          # Check formatting (CI uses this)
pylint --fail-on=W,E,F .                  # Lint (CI uses this)
```

### Running Locally
```bash
python bitsec.py miner execute-agent      # Run miner agent on single project
python bitsec.py miner run                # Run miner with Docker
python bitsec.py validator run            # Run validator with Docker
python -m validator.manager               # Run validator directly
```

## Architecture

### Execution Flow
1. **SandboxManager** (`validator/manager.py`) polls the platform API for jobs, manages a thread pool (max 12 workers), and orchestrates Docker containers
2. **AgentExecutor** (`validator/executor.py`) runs agents in isolated Docker containers, collecting execution reports
3. **Scorer** (`validator/scorer.py`) classifies vulnerabilities (Critical/High/Medium/Low) using LangChain and LLM integration
4. **PlatformClient** (`validator/platform_client.py`) handles all REST API communication, job polling, and heartbeat mechanism

### Key Data Models
- `validator/models/platform.py` contains `User`, `AgentCode`, and job-related models using Pydantic

### Agent Sandbox
- `validator/agent_sandbox/run_sandbox.py` handles timeout-controlled agent execution
- Agents are executed in Docker containers with resource limits

## Code Style

- **Line length**: 79 characters (enforced by Black)
- **Python versions**: 3.8, 3.9, 3.10, 3.11 supported
- **Imports**: Group as stdlib, third-party, local

## Git Workflow

- **main**: Production branch (protected)
- **staging**: Active development branch
- **Feature branches**: `feature/<ticket>/<description>` from staging
- **Release branches**: `release/<version>/<message>/<creator>` from staging
- **Hotfix branches**: `hotfix/<version>/<message>/<creator>` from main

PRs should target the staging branch. Squash commits when merging.
