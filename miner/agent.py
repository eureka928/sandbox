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
from rich.progress import (
    Progress,
    SpinnerColumn,
    TextColumn,
    BarColumn,
    TimeRemainingColumn,
)
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
    attack_trace: list[str] = []
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


PHASE_0_BLOCK = """\
## PHASE 0 — DESIGN INFERENCE (mandatory)
Before looking for vulnerabilities, understand what this code does:
1. What is the contract's role in the protocol?
   (vault, router, token, oracle, staking, governance, etc.)
2. What are the critical invariants?
   (e.g., "total shares must equal sum of user shares",
    "only owner can withdraw", "price must be positive")
3. What external protocols does it interact with?
   (Uniswap, Aave, Chainlink, custom contracts, etc.)
4. What are the trust boundaries?
   (who can call what, what inputs are user-controlled
    vs admin-controlled vs computed)

Use this understanding to guide your vulnerability search.
Do NOT report this analysis — use it internally only.
"""

DO_NOT_REPORT = """\
## DO NOT REPORT (these are NOT vulnerabilities)
- Gas optimizations (unless causes actual DoS)
- Code style or naming issues
- Theoretical issues without a concrete exploit path
- Missing zero-address checks on constructor/initializer/admin parameters
- Missing input validation that has no security impact
- Centralization risks or admin trust assumptions (admin privileges \
are by design)
- Events not being emitted
- Reentrancy where the contract uses ReentrancyGuard or \
checks-effects-interactions correctly
- Issues in interface definitions (interfaces have no implementation)
- Known patterns from OpenZeppelin or other audited libraries
- Speculative overflow/underflow in Solidity >=0.8.0 (has built-in \
overflow checks)
- "Missing access control" on functions protected by modifiers \
(onlyOwner, onlyAdmin)
- Ownership renouncement or immutability patterns (these are \
intentional design choices)
- Error message text inconsistencies
- Issues requiring admin/owner compromise as a precondition
- Issues requiring miner/validator collusion or block manipulation
- Uninitialized state that is set during initialize() or constructor
- Generic MEV/front-running/sandwich on functions that do NOT \
interact with AMMs, DEXes, or price oracles
- Slippage concerns where minOut/minAmount is a caller-controlled \
parameter — the function provides the option, it is the \
caller's responsibility to set a safe value
- Claims that code contradicts comments or NatSpec — comments \
can be outdated; audit the CODE, not the comments
- Claims a boolean condition is inverted without a concrete \
trace proving the correct behavior
- Memory vs storage confusion — only report if you can show \
concrete state corruption
- "Uninitialized mapping/storage" claims — Solidity \
zero-initializes all storage by default
- Front-running initialize()/init() of clone/proxy contracts \
deployed via factories (factory calls init atomically)
- Cooldown mechanisms, time delays, conversion rate functions, \
or emergency governance functions as vulnerabilities — these \
are intentional protocol design patterns
- "Unchecked return value" for internal calls or SafeERC20 \
patterns in Solidity >=0.8
"""

SHARED_FORMAT_HEADER = """\
## CRITICAL: QUALITY OVER QUANTITY
Only report vulnerabilities where you can describe a specific, \
step-by-step exploit.
A good finding has: attacker action -> vulnerable code path -> \
concrete impact (fund loss, state corruption, DoS).
If you cannot describe the exploit steps, do NOT report it.

## DESCRIPTION REQUIREMENTS (CRITICAL FOR MATCHING)
Each finding description MUST include these elements:
1. **Filename**: Include the source filename
2. **Function call pattern**: Reference functions as \
`functionName()`
3. **Core mechanism**: The specific flaw
4. **Impact**: Concrete consequence
5. **Exploit path**: Brief step-by-step attack scenario

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

## ATTACK TRACE (REQUIRED)
Each finding MUST include an `attack_trace` field: a JSON array \
of 2-4 concrete steps showing how an attacker exploits the flaw.
Example:
"attack_trace": [
  "Step 1: Attacker calls deposit() with 1 wei to become first depositor",
  "Step 2: Attacker donates 1e18 tokens directly to inflate share price",
  "Step 3: Victim deposits 1.5e18 tokens but receives 0 shares due to rounding",
  "Step 4: Attacker withdraws, stealing victim funds"
]
Each step must reference a specific function or action. \
If you cannot write concrete steps, do NOT report the finding.

## CRITICAL: AVOID DUPLICATES
Do NOT report multiple variations of the same underlying issue.
If a bug affects multiple functions, report it ONCE at the root \
cause location.
Report at most 3-4 findings per file.

## BEFORE REPORTING, VERIFY EACH FINDING
For every potential finding, ask yourself:
1. Did I trace the FULL execution path, including modifiers
   and callers, not just one function in isolation?
2. Is the "vulnerable" parameter actually controlled by an
   attacker, or only by the caller/admin?
3. Does a modifier, require(), or earlier check already
   prevent the attack I am describing?
4. Am I flagging a DESIGN CHOICE (cooldown, conversion
   rate, emergency function) as a bug?
5. Am I trusting a CODE COMMENT over the actual code?
If ANY answer disqualifies the finding, do NOT report it.
"""

APPROACH_A_LOGIC_FUNDS = """\
## HIGH-VALUE PATTERNS — Logic & Fund Flows
Focus on financial logic, reward math, and state accounting:

1. **Reward/fee distribution rounding**: When dividing \
accumulated rewards by total shares, check if rounding to \
zero causes permanent loss. If `deltaIndex = accrued / \
totalShares` rounds to zero but `lastBalance` still advances, \
rewards are silently lost. Index and balance must advance \
in lockstep or not at all.
2. **Incorrect formula after partial state changes**: When \
transferring, splitting, or migrating positions (vesting, \
staking, etc.), check if recalculations use ORIGINAL totals \
instead of REMAINING amounts. E.g., `releaseRate = \
totalAmount / steps` is wrong if some amount was already \
claimed; should be `(totalAmount - amountClaimed) / \
(steps - stepsClaimed)`.
3. **Share dilution / first-depositor inflation**: Can the \
first depositor manipulate the exchange rate by depositing \
1 wei then donating a large amount, causing subsequent \
depositors to receive 0 shares? Check for minimum deposit \
or virtual offset.
4. **Profit vs loss accounting errors**: When calculating \
PnL across contracts, verify credits and debits sum \
correctly. Check sign handling (positive vs negative) and \
whether profit/loss paths are handled symmetrically.
5. **Fee avoidance via public harvest/sync**: If harvest(), \
sync(), or update functions are public and reset accounting \
state, can a caller time these calls to avoid performance \
fees or inflate their share of rewards?
6. **Precision loss in intermediate calculations**: Check \
for multiply-before-divide patterns. Division followed by \
multiplication loses precision; the reverse preserves it.
7. **Liquidation threshold errors**: Is the liquidation \
condition checking the right ratio? Can healthy positions \
be liquidated or unhealthy ones escape? Can a user \
self-liquidate to extract the liquidation bonus?
8. **Inconsistent refund logic**: In multi-step swap/transfer \
flows, trace: amount taken -> amount used -> refund. If the \
taken amount already accounts for partial fills, an \
additional refund double-counts and drains the protocol.
9. **State synchronization in function chains**: When \
functions call other internal functions that depend on shared \
state, verify state modifications complete BEFORE the \
dependent function executes. If dependent function reads \
state before reset, it uses stale values.
10. **Cancel/reverse operation completeness**: When operations \
can be cancelled/reversed, verify ALL state changes are \
undone. If operation A decrements buffer/reserve, does \
cancel(A) restore it? If cancelled amounts are tracked for \
later processing, verify funds exist where processing \
expects them.
11. **Multi-component calculation completeness**: When \
calculating adjustments from values with multiple components \
(base + accrued + pending), verify ALL components are \
included in comparisons, not just partial amounts.
12. **Recomputation correctness after state changes**: When \
computed values are recalculated after state changes, verify \
formulas account for all categories of state mutations and \
accumulated progress.

## OMISSION BUGS — Logic & Fund Flows
1. **Return value unit mismatch**: Does the function return \
shares when callers expect underlying assets, or vice versa?
2. **Missing state update after mutation**: After withdraw/ \
undeploy/transfer, is the tracking variable updated?
3. **Missing accrual before claim**: Are pending rewards \
accrued before allowing a claim?
4. **Missing index update before share change**: When \
minting or burning shares, is the reward index updated \
first?
5. **Return value unit mismatch (extended)**: Trace full \
call chain — identify what unit the function returns, what \
unit callers expect, and which calculations break. Units \
encompass semantic meaning AND numeric scaling. When systems \
use internal vs external representations, verify conversions \
at function boundaries.
6. **Missing state update in function chain ordering**: When \
a function reduces state and then calls a dependent function, \
verify state is set to final intended value BEFORE the \
dependent call. Stale reads allow incorrect calculations.
"""

APPROACH_B_ACCESS_SAFETY = """\
## HIGH-VALUE PATTERNS — Access Control & Safety
Focus on access control, reentrancy, and external interactions:

1. **Reentrancy**: State updated AFTER external calls \
(transfers, low-level calls) without ReentrancyGuard or \
checks-effects-interactions pattern.
2. **Access control gaps on critical functions**: Public/ \
external functions that modify critical state without \
onlyOwner/onlyRole/auth modifiers. Trace internal helpers \
to their external callers.
3. **Privileged role abuse (coordinator/operator/keeper)**: \
Check if roles can set parameters enabling theft (100% fees, \
manipulated price bounds, forced liquidations). Look for \
updateParameter(), setFee(), updateRiskParameter().
4. **Missing access control on privilege-granting functions**: \
Functions like updateExtension(), setOperator(), \
registerExtension() that grant protocol-wide privileges \
MUST have access control.
5. **Public function abuse / allowance drain**: When a \
contract holds ERC20 allowances from users, check if any \
public function lets a third party trigger transferFrom() \
with another user's address as `from`.
6. **Missing slippage protection**: Any function that removes \
liquidity, burns positions, or calls update_position() with \
negative delta MUST have minimum output amount parameters. \
Without them, MEV sandwich attacks extract value.
7. **Front-runnable deterministic deployments**: Factory \
contracts using CREATE2 or Clones.clone() produce predictable \
addresses. If subsequent calls depend on that address, an \
attacker can front-run and DoS the factory.
8. **Wrong token ordering assumptions**: DEX interactions \
that assume a token is always token0 or token1 instead of \
querying pool.token0(). Tokens are sorted lexicographically; \
hardcoded assumptions produce wrong swap directions.
9. **Unvalidated critical parameters**: Functions performing \
swaps, rebalances, or liquidations with user-supplied \
parameters that have a specific valid range but no validation.
10. **State commitment timing with external operations**: \
For operations with replay protection (nonces, signatures, \
flags), verify state is committed ONLY AFTER all operations \
succeed. Pattern: nonce consumed → external call fails → \
nonce wasted, operation didn't complete.
11. **Resource-controlled execution (63/64 gas rule)**: \
Subcalls receive only 63/64 of remaining gas. Can attacker \
craft gas limits so parent completes but subcall OOGs? \
Combined with non-revert error handling (try/catch, \
low-level call), subcall fails silently, parent succeeds, \
state consumed.
12. **Signature execution context binding**: For \
signature-based authorization, check if the executor/ \
submitter address is part of the signed digest. If not, \
anyone with a valid signature can submit it with hostile \
execution context (front-running).
13. **Interface compatibility with external protocols**: \
When integrating with external protocols (DEXes, AMMs, \
gauges, routers), verify declared interface definitions \
match actual contracts — function names, parameter \
types/counts, struct field definitions, return types must \
match exactly. Different protocol versions/forks may be \
incompatible.
14. **Partial execution analysis**: For functions with \
multiple operations or subcalls, what happens if some \
succeed while others fail? Can high-level operations succeed \
while low-level subcalls fail? If partial execution is \
possible, what state gets committed? Are users protected \
from unfavorable partial outcomes?

## OMISSION BUGS — Access Control & Safety
1. **Missing access control on destructive functions**: \
selfdestruct, delegatecall targets, or upgrade functions \
without auth modifiers.
2. **Missing validation on public entry points**: If a \
function is public/external without access control, can an \
arbitrary caller trigger unintended economic effects?
3. **Missing state update after external interaction**: After \
a token transfer or external call succeeds, is the tracking \
variable updated?
4. **Missing existence check before deterministic resource \
creation**: When deploying via CREATE opcode (clone, new), \
addresses are predictable. Verify resources at those \
addresses can't be front-run created, causing permanent DoS.
"""

APPROACH_C_ATTACK_LIFECYCLE = """\
## HIGH-VALUE PATTERNS — Attack Flows & Operation Lifecycle
Focus on fund flow tracing, automatic function triggers, \
operation lifecycle, and type integrity:

1. **Automatic processing of withdrawal funds**: When contracts \
have receive()/fallback() that trigger deposit/stake operations, \
withdrawal funds returned from external systems get automatically \
re-invested. Users cannot collect withdrawals because funds are \
immediately processed through unintended paths.
2. **Mixed fund sources in accounting**: Contract cannot \
distinguish between user deposits and system-returned funds \
(validator rewards, withdrawal returns). Withdrawal funds \
treated as new deposits inflate accounting without actual \
user action.
3. **Missing caller verification in automatic handlers**: \
receive()/fallback() functions don't verify caller identity \
or tx.origin before executing operations. System operations \
(withdrawals, rewards) can trigger user-facing logic paths.
4. **Incomplete withdrawal flow**: Withdrawal requests \
processed but funds not held for user collection — immediately \
routed through unintended paths. Withdrawal confirmation fails \
due to insufficient balance.
5. **State commitment before operation verification**: \
Operations modify replay-protection state (nonces, signatures, \
flags) before verifying all subcalls succeed. External call \
fails → state consumed → operation didn't complete. Check: \
non-revert error handling (try/catch, low-level call) that \
allows parent to continue.
6. **Authorization context bypass in funds destination**: \
Functions allow multiple entities to call, but destination \
determination doesn't account for caller identity. One entity \
claims funds meant for another because access control and \
destination logic are inconsistent.
7. **Value representation and comparison errors**: Custom \
types with multiple bit representations (different precision \
levels, normalization states) compared via raw bits instead \
of semantic values. Equal values compare unequal.
8. **Silent precision truncation in packing/conversion**: \
When converting between precision formats, format selection \
based on only partial factors (e.g., exponent range but not \
digit count). Actual value's magnitude silently truncated.
9. **Assembly/Yul control flow halts**: Edge case handlers \
in assembly (zero, infinity, special values) use opcodes \
that halt execution without returning a value, disrupting \
the entire calling context.

## OMISSION BUGS — Attack Flows & Lifecycle
1. **Missing buffer/reserve restoration on cancel**: \
Operation decrements buffer, cancel returns tokens but \
doesn't restore buffer counter. Accounting permanently \
desynchronized.
2. **Missing success verification before state commitment**: \
No check that external call succeeded before consuming \
nonce/flag.
3. **Missing mathematical domain validation**: Math functions \
(ln, log, sqrt) don't validate inputs are within valid \
domain. Zero/negative inputs produce meaningless results \
without error.
"""

AUDIT_APPROACHES = [
    ("logic_funds", APPROACH_A_LOGIC_FUNDS),
    ("access_safety", APPROACH_B_ACCESS_SAFETY),
    ("attack_lifecycle", APPROACH_C_ATTACK_LIFECYCLE),
]


def _build_audit_prompt(domain_section: str, format_instructions: str) -> str:
    """Build a complete audit prompt from domain-specific section."""
    return (
        "You are an expert smart contract security auditor. "
        "Find EXPLOITABLE vulnerabilities with concrete attack "
        "paths.\n\n"
        + PHASE_0_BLOCK
        + "\n"
        + SHARED_FORMAT_HEADER
        + "\n"
        + domain_section
        + "\n"
        + DO_NOT_REPORT
        + "\n"
        + format_instructions
        + "\n\n"
        + "IMPORTANT: Output ONLY valid JSON. Begin with "
        + '`{"vulnerabilities":`'
    )


class BaselineRunner:
    def __init__(
        self, config: dict[str, Any] | None = None, inference_api: str = None
    ):
        self.config = config or {}
        self.model = self.config["model"]
        self.inference_api = inference_api or os.getenv(
            "INFERENCE_API", "http://bitsec_proxy:8000"
        )
        self.project_id = os.getenv("PROJECT_ID", "local")
        self.job_id = os.getenv("JOB_ID", "local")

        console.print(f"Inference: {self.inference_api}")

    def inference(self, messages: dict[str, Any]) -> dict[str, Any]:
        payload = {
            "model": self.config["model"],
            "messages": messages,
            "temperature": 0,
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
                    error_detail = (
                        resp.text if hasattr(resp, "text") else str(resp)
                    )
            else:
                error_detail = "No response received"
            console.print(f"Inference Proxy Error: {e} {error_detail}")
            raise

        except requests.exceptions.RequestException as e:
            if resp is not None:
                try:
                    error_detail = resp.json()
                except (ValueError, AttributeError):
                    error_detail = (
                        resp.text if hasattr(resp, "text") else str(resp)
                    )
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
        if response_content.startswith("```") and response_content.endswith(
            "```"
        ):
            lines = response_content.splitlines()

            if lines[0].startswith("```"):
                lines = lines[1:]

            if lines and lines[-1].strip() == "```":
                lines = lines[:-1]

            response_content = "\n".join(lines).strip()

        resp_json = json.loads(response_content)

        return resp_json

    def analyze_cross_contract(
        self, files_content: dict[str, str]
    ) -> tuple[Vulnerabilities, int, int]:
        """Analyze all project files together for cross-contract vulnerabilities.

        Returns:
            Tuple of (vulnerabilities, input_tokens, output_tokens)
        """
        console.print("\n[bold cyan]Cross-contract analysis pass[/bold cyan]")
        console.print(
            f"[dim]  → Analyzing {len(files_content)} files " f"together[/dim]"
        )

        # Build concatenated source
        combined_source = ""
        for path, content in sorted(files_content.items()):
            combined_source += f"// ===== FILE: {path} =====\n{content}\n\n"

        parser = PydanticOutputParser(pydantic_object=Vulnerabilities)
        format_instructions = parser.get_format_instructions()

        system_prompt = dedent(f"""
            You are an expert smart contract security auditor performing a whole-project review.

            You are given ALL source files of a project concatenated together. Analyze them as a complete system. Look for vulnerabilities that require understanding how multiple components interact, as well as subtle bugs that benefit from full-project context.

            ## WHAT TO LOOK FOR

            ### Cross-Contract State Flows
            1. **Incorrect state propagation**: When Contract A sets state that Contract B reads, verify correctness. Example: vesting contract tracks `stepsClaimed` and `amountClaimed`, but transfer function recalculates `releaseRate` using original `totalAmount / numOfSteps` instead of `(totalAmount - amountClaimed) / (numOfSteps - stepsClaimed)`, letting sellers unlock more tokens than locked.
            2. **Accounting errors across boundaries**: Trace profit/loss, fee, or balance calculations that span contracts. Check that credits and debits sum correctly. Example: liquidation function in CDPVault.sol incorrectly handles profit vs loss accounting when calling pool functions.
            3. **Ordering dependencies**: Operations whose outcome depends on ordering of prior operations. Example: listing order in a marketplace affecting array indices, causing state corruption.

            ### External Protocol Dependencies
            4. **Front-runnable deterministic deployments**: Factory contracts using CREATE2 or Clones.clone() produce predictable addresses. If subsequent calls (e.g., `uniswapFactory.createPair()`) depend on that address, an attacker can predict the address and call the external protocol first, permanently DoS-ing the factory.
            5. **Wrong token ordering assumptions**: DEX interactions that assume a token is always token0 or token1 instead of querying `pool.token0()`. Uniswap sorts tokens lexicographically; hardcoded assumptions produce wrong swap directions.

            ### Reward & Distribution Systems
            6. **Rounding-induced reward loss**: When distributing rewards, if `deltaIndex = accrued.divDown(totalShares)` rounds to zero but `lastBalance` is still advanced, those rewards are permanently lost. Index and balance must advance together or not at all.

            ### Missing Safety Mechanisms
            7. **Missing slippage protection**: Any function that removes liquidity, withdraws from pools, burns positions, or calls `update_position()` with negative delta MUST have minimum output amount parameters. Without them, MEV sandwich attacks extract value. Flag if slippage params are absent.
            8. **Unvalidated critical parameters**: Functions performing swaps, rebalances, or liquidations with user-supplied parameters (direction masks, amounts, etc.) that have a specific valid range but no validation. Anyone can call with arbitrary values to disrupt the protocol.

            ### Fund Flow Errors
            9. **Inconsistent refund logic**: In swap functions, trace: amount taken from user -> amount actually swapped -> refund. If the taken amount already equals the swap amount (adjusted for liquidity), an additional refund is double-counting and drains the protocol.

            ### Privileged Role Abuse (CRITICAL)
            10. **Coordinator/operator excessive power**: Check if roles like coordinator, operator, keeper, or market can set parameters that enable theft (100% fees, manipulated price bounds, forced liquidations). The role may be "trusted" but if they can steal ALL funds, it's a vulnerability.
            11. **Missing access control on privilege-granting functions**: Functions like updateExtension(), setOperator(), registerExtension() that grant protocol-wide privileges must have access control. If anyone can call them, anyone can become an operator.

            ### Protocol Integration Issues
            12. **AMO/DEX integration mismatch**: When AMO contracts integrate with DEXes (Aerodrome, Velodrome, UniV3), verify the liquidity math matches the specific DEX. Different DEX versions have different formulas.
            13. **Validator/delegator reward bypass**: In staking systems, check if validators can claim rewards that should go to delegators, or if slashing can be circumvented.

            ### Interface Compatibility
            14. **External protocol interface mismatch**: When contracts declare interfaces for external protocols (DEXes, AMMs, gauges, routers), verify definitions match actual contracts. Function names, parameter types/counts, struct fields, and return types must match exactly. Different protocol versions or forks may have incompatible interfaces despite similar names.

            ### Fund Destination Determination
            15. **Authorization bypass in funds destination**: When functions allow multiple entities to call, verify destination determination accounts for caller identity. Access control may allow multiple entities, but destination logic must restrict who receives funds based on who calls.

            ### Operation Lifecycle
            16. **State commitment timing across contracts**: When operations span contracts and consume replay protection state (nonces, signatures), verify state is committed only after all cross-contract operations succeed. Partial execution across contract boundaries can consume state without completing the operation.

            ## DESCRIPTION REQUIREMENTS
            Each finding MUST include:
            1. **All files/contracts involved** (e.g., "In StepVesting.sol and VestingManager.sol...")
            2. **The specific functions** using `functionName()` notation
            3. **Step-by-step exploit scenario** with concrete attacker actions
            4. **Concrete impact** (fund loss, permanent DoS, state corruption)

            ## ATTACK TRACE (REQUIRED)
            Each finding MUST include an `attack_trace` field: a JSON \
array of 2-4 concrete steps.
            Example: "attack_trace": ["Step 1: Attacker calls X()", \
"Step 2: State Y changes", "Step 3: Attacker profits"]
            Each step must reference a specific function or action.

            ## SEVERITY
            - critical: Direct fund loss, no preconditions
            - high: Fund loss with conditions, protocol disruption, permanent DoS
            - medium: Limited loss, multiple steps required
            - low: Minor issues, theoretical only

            ## CONFIDENCE (0.0-1.0)
            - 0.9+: Definite vulnerability with clear exploit
            - 0.8-0.9: High confidence, minor uncertainty
            - 0.75-0.8: Confident but needs specific conditions
            - Report if confidence >= 0.75

            ## LOCATION FORMAT
            Use: `ContractName.functionName` for the primary location.
            Set `file` to the file where the root cause is.

            ## VULNERABILITY TYPES (use exact names)
            reentrancy, access-control, integer-overflow, flash-loan-attack,
            front-running, denial-of-service, logic-error, oracle-manipulation,
            precision-loss, unchecked-external-call, storage-collision

            ## CRITICAL: QUALITY CONTROLS
            - Report at most 5-6 findings total. Only the highest-impact, highest-confidence issues.
            - Do NOT repeat issues already obvious from single-file analysis (missing zero checks, basic reentrancy, admin access control).
            - Do NOT report multiple variations of the same bug. One finding per root cause.
            - Each finding MUST have a concrete, self-contained exploit path. No "if admin is compromised" or "if oracle is manipulated" assumptions.

            ## DO NOT REPORT
            - Missing zero-address checks on constructor/initializer/admin parameters
            - Centralization risks or admin trust assumptions
            - Gas optimizations without actual DoS impact
            - Events not being emitted
            - Speculative overflow/underflow in Solidity >=0.8.0
            - Known OpenZeppelin patterns
            - Code style or naming issues
            - Ownership renouncement or immutability patterns
            - Issues requiring admin/owner compromise as precondition
            - Error message inconsistencies
            - Generic MEV/front-running/sandwich on functions that do NOT
              interact with AMMs, DEXes, or price oracles
            - Slippage concerns where minOut/minAmount is a caller-controlled
              parameter — the function provides the option, it is the
              caller's responsibility to set a safe value
            - Claims that code contradicts comments or NatSpec — comments
              can be outdated; audit the CODE, not the comments
            - Claims a boolean condition is inverted without a concrete
              trace proving the correct behavior
            - Memory vs storage confusion — only report if you can show
              concrete state corruption
            - "Uninitialized mapping/storage" claims — Solidity
              zero-initializes all storage by default
            - Front-running initialize()/init() of clone/proxy contracts
              deployed via factories (factory calls init atomically)
            - Cooldown mechanisms, time delays, conversion rate functions,
              or emergency governance functions as vulnerabilities — these
              are intentional protocol design patterns
            - "Unchecked return value" for internal calls or SafeERC20
              patterns in Solidity >=0.8

            {format_instructions}

            IMPORTANT: Output ONLY valid JSON. Begin with `{{"vulnerabilities":`
        """)

        user_prompt = dedent(f"""
            Analyze this complete project for security vulnerabilities. You have all source files below.

            Focus on:
            - Bugs requiring understanding of how multiple contracts interact
            - State propagation errors between contracts
            - Missing safety mechanisms (slippage, parameter validation)
            - Incorrect assumptions about external protocols (DEX token ordering, deterministic addresses)
            - Reward distribution rounding errors that lose funds
            - Inconsistent fund flows (double refunds, wrong accounting)

            {combined_source}

            Report all high-impact vulnerabilities you find. Include the specific files and functions involved.
        """)

        try:
            messages = [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt},
            ]

            response = self.inference(messages=messages)
            response_content = response["content"].strip()

            msg_json = self.clean_json_response(response_content)

            vulnerabilities = Vulnerabilities(**msg_json)
            for v in vulnerabilities.vulnerabilities:
                v.reported_by_model = self.config["model"]

            # Post-process each vulnerability
            processed = []
            for v in vulnerabilities.vulnerabilities:
                single = Vulnerabilities(vulnerabilities=[v])
                single = self.post_process_vulnerabilities(single, v.file)
                processed.extend(single.vulnerabilities)

            vulnerabilities = Vulnerabilities(vulnerabilities=processed)

            if vulnerabilities.vulnerabilities:
                console.print(
                    f"[green]  → Cross-contract pass found "
                    f"{len(vulnerabilities.vulnerabilities)} "
                    f"vulnerabilities[/green]"
                )
            else:
                console.print(
                    "[yellow]  → No cross-contract vulnerabilities "
                    "found[/yellow]"
                )

            input_tokens = response.get("input_tokens", 0)
            output_tokens = response.get("output_tokens", 0)

            return vulnerabilities, input_tokens, output_tokens

        except Exception as e:
            console.print(f"[red]Error in cross-contract analysis: {e}[/red]")
            return Vulnerabilities(vulnerabilities=[]), 0, 0

    def _is_noise_finding(self, v: Vulnerability) -> bool:
        """Check if a finding matches known false-positive patterns."""
        title_lower = v.title.lower()
        desc_lower = v.description.lower()
        combined = f"{title_lower} {desc_lower}"

        # Missing zero-address / input validation noise
        zero_check_patterns = [
            r"missing zero[- ]address",
            r"missing address validation",
            r"no zero[- ]address check",
            r"missing input validation.*(constructor|initializ)",
        ]
        if any(re.search(p, combined) for p in zero_check_patterns):
            return True

        # Admin/owner compromise assumptions
        admin_patterns = [
            r"(compromised|malicious)\s+(admin|owner|deployer)",
            r"if\s+(the\s+)?(admin|owner)\s+(is|were|becomes)",
            r"admin\s+can\s+(set|change|update).*malicious",
            r"requires?\s+(admin|owner)\s+compromise",
        ]
        if any(re.search(p, combined) for p in admin_patterns):
            return True

        # Design choices reported as vulnerabilities
        design_patterns = [
            r"ownership\s+renounce",
            r"permanent(ly)?\s+immutable",
            r"(constructor|deployer)\s+sets.*zero",
            r"error\s+message\s+inconsisten",
            r"inconsistent\s+(error|revert)\s+message",
        ]
        if any(re.search(p, combined) for p in design_patterns):
            return True

        # Block manipulation / miner collusion
        miner_patterns = [
            r"(miner|validator|block\s+producer)\s+(control|manipulat)",
            r"block\s+(timestamp|number)\s+manipulat",
        ]
        if any(re.search(p, combined) for p in miner_patterns):
            return True

        # Generic slippage/MEV on non-AMM code
        slippage_noise = [
            r"(mev|sandwich|front.?run).*(slippage|min.?out)",
            r"slippage.*(not\s+set|set\s+to\s+0|zero)",
            r"no\s+(slippage|minimum\s+output)\s+protection",
        ]
        amm_keywords = (
            r"(uniswap|sushiswap|curve|balancer|amm|dex" r"|swap.?router)"
        )
        # Oracle/price-feed contexts — not actual swaps
        oracle_context = (
            r"(oracle|price.?feed|aggregator|chainlink"
            r"|update.?price|get.?price)"
        )
        if any(re.search(p, combined) for p in slippage_noise):
            # Reject if no AMM keyword present
            if not re.search(amm_keywords, combined):
                return True
            # Reject if AMM keyword only appears in an
            # oracle/price-feed context (not an actual swap)
            if re.search(oracle_context, combined) and not re.search(
                r"(swap|liquidity|remove.?liquidity"
                r"|add.?liquidity|exchange\s*\(|router\.)",
                combined,
            ):
                return True

        # Comment-vs-code mismatch
        comment_patterns = [
            r"(comment|natspec|documentation)\s+"
            r"(say|state|indicate)s?"
            r".{0,60}(but|however|incorrect)",
            r"(contradicts?|inconsistent\s+with)\s+(the\s+)?"
            r"(comment|natspec|documentation)",
        ]
        if any(re.search(p, combined) for p in comment_patterns):
            return True

        # Uninitialized storage/mapping
        uninit_patterns = [
            r"uninitialized\s+(mapping|storage|state|variable)",
            r"default\s+value.*mapping.*exploit",
        ]
        if any(re.search(p, combined) for p in uninit_patterns):
            return True

        # Front-running initialize on proxy/clone
        frontrun_init_patterns = [
            r"front.?run.*(initializ|init\s*\()",
            r"anyone\s+can\s+call\s+(initializ|init\b)",
        ]
        if any(re.search(p, combined) for p in frontrun_init_patterns):
            return True

        # Unsafe block.timestamp deadline (not a real vuln)
        deadline_patterns = [
            r"block\.timestamp\s+(as|for)\s+deadline",
            r"(unsafe|stale)\s+deadline.*block\.timestamp",
            r"deadline.*block\.timestamp.*front.?run",
        ]
        if any(re.search(p, combined) for p in deadline_patterns):
            return True

        # Immutable variable can't be updated (design choice)
        immutable_patterns = [
            r"immutable.*cannot\s+be\s+(updated|changed|modified)",
            r"no\s+(setter|update).*immutable",
        ]
        if any(re.search(p, combined) for p in immutable_patterns):
            return True

        # Unbounded loop DoS on view/read-only functions
        if re.search(r"unbounded.*(loop|iteration)", combined):
            if re.search(r"(view|pure|read.?only|getter)", combined):
                return True

        # Commented-out / stub / placeholder code as vulnerability
        commented_code_patterns = [
            r"(commented\s+out|stub|placeholder|empty\s+body)",
            r"always\s+return(s)?\s+(a\s+)?1:1\s+ratio",
            r"(function|logic)\s+(is\s+)?(commented|disabled|not\s+implemented)",
        ]
        if any(re.search(p, combined) for p in commented_code_patterns):
            return True

        # Admin misconfiguration: admin/owner sets parameter
        # to invalid value — design/operational issue, not vuln
        admin_misconfig_patterns = [
            r"(admin|owner|deployer|governance)\s+"
            r"(could|can|may)\s+(mistakenly|accidentally)",
            r"(admin|owner|deployer)\s+sets?\s+.{0,40}"
            r"(to\s+zero|to\s+0\b|invalid)",
            r"(can|could)\s+be\s+set\s+to\s+zero\s+"
            r"(by|causing|breaking|making)",
        ]
        if any(re.search(p, combined) for p in admin_misconfig_patterns):
            return True

        # Missing input validation on admin/privileged functions
        # where "attacker" would need admin role
        if re.search(
            r"missing\s+(input\s+)?validation", combined
        ) and re.search(
            r"(addVault|setOracle|setParameter|setConfig"
            r"|register|add.?Pool|set.?Address)",
            combined,
        ):
            # Only filter if the function is admin-gated
            if re.search(
                r"(onlyOwner|onlyAdmin|onlyRole|authorized"
                r"|access\s+control|admin|owner\s+can)",
                combined,
            ):
                return True

        # Proxy/delegatecall address(this) approval confusion
        # In delegatecall context, address(this) is the proxy
        # so approve(address(this)) + transferFrom is correct
        if re.search(
            r"(forceApprove|approve)\s*\(\s*address\s*\(" r"\s*this\s*\)",
            combined,
        ) and re.search(
            r"(proxy|action|delegatecall|position\s*action"
            r"|swap\s*action|pool\s*action)",
            combined,
        ):
            return True

        # Single point of failure / centralization risk
        if re.search(
            r"single.?point\s+(of\s+)?failure", combined
        ) or re.search(r"(centralization|centralized)\s+risk", combined):
            return True

        # Zero-address validation inconsistency — low impact
        if re.search(
            r"(inconsistent|missing)\s+zero.?address" r"\s+(validation|check)",
            combined,
        ):
            return True

        # Whitelist / allowlist bypass when empty or
        # unconfigured — design choice
        if re.search(
            r"(whitelist|allowlist)\s+bypass\s+" r"(when|if)\s+empty",
            combined,
        ):
            return True

        # Oracle staleness check missing / insufficient —
        # known config issue, not exploitable vuln
        if re.search(
            r"(staleness|stale.?ness)\s+(check|validation)"
            r"\s+(missing|insufficient|absent)",
            combined,
        ):
            return True

        # Missing slippage on non-swap operations (withdraw,
        # redeem, deposit, cooldown) — these are not swaps
        if (
            re.search(
                r"(missing|no|without|lack)\s+(of\s+)?slippage",
                combined,
            )
            and re.search(
                r"(withdraw|redeem|deposit|cooldown|unstake"
                r"|undelegate|claim)",
                combined,
            )
            and not re.search(
                r"(swap|exchange|amm|dex|uniswap|curve" r"|aerodrome|router)",
                combined,
            )
        ):
            return True

        # Unchecked return value with SafeERC20 / safe transfer
        # SafeERC20 already reverts on failure
        if re.search(r"unchecked\s+(return\s+)?value", combined) and re.search(
            r"(safe.?transfer|safe.?approve|safeERC20" r"|forceApprove)",
            combined,
        ):
            return True

        # Incorrect approval / allowance pattern where the
        # description claims "will fail" or "revert" but
        # doesn't demonstrate actual exploit impact
        if (
            re.search(
                r"(incorrect|wrong|flawed)\s+(token\s+)?"
                r"(approval|allowance)",
                combined,
            )
            and re.search(
                r"(will\s+(fail|revert)|cause.*revert"
                r"|transaction\s+to\s+revert)",
                combined,
            )
            and not re.search(
                r"(steal|drain|theft|loss\s+of\s+funds"
                r"|attacker\s+(can|could)\s+transfer)",
                combined,
            )
        ):
            return True

        # Oracle staleness / heartbeat without concrete duration
        # These are often generic warnings without proof of impact
        if re.search(
            r"(oracle|chainlink|price\s*feed).*(stale|staleness"
            r"|heartbeat|outdated|old\s+price)",
            combined,
        ):
            # Only filter if no concrete time duration mentioned
            if not re.search(
                r"\d+\s*(second|minute|hour|day|block)", combined
            ):
                return True

        # Token ordering assumptions without concrete swap impact
        # Generic "token0/token1 ordering" without demonstrating
        # actual wrong swap direction
        if re.search(
            r"(token\s*ordering|token0.*token1|incorrect.*ordering"
            r"|wrong.*token.*order)",
            combined,
        ):
            # Keep if there's a concrete swap direction issue
            if not re.search(
                r"(swap.*wrong.*direction|reversed.*swap"
                r"|buy.*instead.*sell|sell.*instead.*buy)",
                combined,
            ):
                return True

        # Predictable / deterministic IDs without exploit path
        if re.search(
            r"(predictable|deterministic)\s*(order\s*)?(id|identifier)",
            combined,
        ):
            # Keep if there's actual front-running/collision exploit
            if not re.search(
                r"(front.?run|collision|overwrite|hijack|steal)",
                combined,
            ):
                return True

        # Generic "incorrect" findings without attacker/exploit
        if re.search(
            r"incorrect\s+(state|calculation|update|handling"
            r"|validation|conversion|price)",
            combined,
        ):
            # Only filter if no exploit path mentioned
            if not re.search(
                r"(attacker|exploit|steal|drain|manipulat|arbitrage"
                r"|profit|loss\s+of\s+fund|fund\s+loss)",
                combined,
            ):
                return True

        # Missing validation on view/getter functions
        if re.search(r"missing\s+(input\s+)?validation", combined):
            if re.search(r"(view|pure|getter|read.?only)", combined):
                return True

        # Circuit breaker / emergency function as vulnerability
        if re.search(
            r"(circuit\s*breaker|emergency|pause|unpause)",
            combined,
        ):
            if re.search(r"(can\s+be\s+called|missing\s+access)", combined):
                if re.search(
                    r"(only.?owner|only.?admin|authorized)", combined
                ):
                    return True

        # Event emission order / missing events — low impact
        if re.search(
            r"(missing|incorrect|wrong)\s+event\s+(emission|emit)",
            combined,
        ) or re.search(r"event.*(not\s+emitted|order|sequence)", combined):
            return True

        # Gas optimization / inefficiency reports
        if re.search(
            r"(gas\s+inefficien|gas\s+optimiz|redundant\s+storage"
            r"|unnecessary\s+(sload|sstore|call))",
            combined,
        ):
            return True

        # Self-transfer / self-approval patterns (often intentional)
        if re.search(
            r"(self.?transfer|transfer.*to.*itself"
            r"|approve.*self|self.?approval)",
            combined,
        ):
            if not re.search(r"(infinite|loop|drain|steal)", combined):
                return True

        # Return value not checked for internal/known-safe calls
        if re.search(r"(return\s+value|returndata)\s+not\s+checked", combined):
            if re.search(
                r"(internal|private|trusted|known|safe)",
                combined,
            ):
                return True

        # Reentrancy on view/pure/read-only or non-state-changing
        if re.search(r"reentr", combined):
            if re.search(
                r"(view|pure|read.?only|no\s+state\s+change"
                r"|external\s+view|constant)",
                combined,
            ):
                return True

        # "Anyone can call" on public utility functions
        # (execute, fill, liquidate, etc. are designed to be public)
        if re.search(r"anyone\s+can\s+call", combined):
            if re.search(
                r"(execute|fill.?order|liquidat|settle|claim.?reward"
                r"|compound|harvest|poke|sync|update.?price)",
                combined,
            ):
                return True

        # Lack of two-step ownership transfer — low impact design
        if re.search(
            r"(two.?step|2.?step)\s+(ownership|admin)\s+transfer",
            combined,
        ) or re.search(r"ownership\s+transfer\s+in\s+one\s+step", combined):
            return True

        # DoS by external call failure on non-critical paths
        if re.search(r"(dos|denial\s+of\s+service)", combined):
            if re.search(
                r"(callback|hook|notification|event|log)",
                combined,
            ):
                if not re.search(
                    r"(fund|withdraw|transfer|critical|core)",
                    combined,
                ):
                    return True

        # Signature replay across chains — often has chainId
        if re.search(r"signature\s+replay", combined):
            if re.search(
                r"(chainid|chain.?id|domain.?separator)",
                combined,
            ):
                return True

        # Missing access control on non-critical/utility functions
        if re.search(r"missing\s+access\s+control", combined):
            if re.search(
                r"(view|pure|getter|query|check|verify|validate"
                r"|compute|calculate"
                r"|execute|fill|liquidat|settle|claim|harvest"
                r"|compound|sync|update|notify|callback|hook"
                r"|receive|fallback|permit|multicall)",
                combined,
            ):
                return True

        # Privileged role can do privileged action (tautology)
        if re.search(
            r"(owner|admin|operator|governance)\s+(can|could|may)\s+"
            r"(call|invoke|execute|trigger)",
            combined,
        ):
            if not re.search(
                r"(steal|drain|rug|manipulat|exploit|bypass)",
                combined,
            ):
                return True

        # Potential DoS on arrays without size proof
        if re.search(r"(dos|denial).*(array|loop|iteration)", combined):
            if not re.search(r"\d+\s*(element|item|iteration)", combined):
                return True

        # ERC20 approve race condition (well-known, not high sev)
        if re.search(
            r"(approve|allowance)\s+(race|front.?run)",
            combined,
        ):
            return True

        # Hardcoded address/value without impact
        if re.search(r"hardcoded\s+(address|value|constant)", combined):
            if not re.search(
                r"(exploit|attack|steal|drain|manipulat)",
                combined,
            ):
                return True

        # "Incorrect X calculation" without concrete exploit path
        if re.search(
            r"incorrect\s+(fee|balance|share|reward|token|amount)"
            r"\s+(calculation|update|check)",
            combined,
        ):
            if not re.search(
                r"(steal|drain|theft|profit|arbitrage|manipulat"
                r"|attacker\s+(can|could|gains?|receives?))",
                combined,
            ):
                return True

        # Generic slippage on non-swap context
        if re.search(r"(missing|no)\s+slippage", combined):
            if not re.search(
                r"(swap|exchange|amm|uniswap|curve|dex|router"
                r"|liquidity\s+add|liquidity\s+remove)",
                combined,
            ):
                return True

        # ERC721/ERC1155 receiver callback issues (standard pattern)
        if re.search(
            r"(erc721|erc1155|nft)\s+(receiver|callback)",
            combined,
        ):
            if not re.search(r"(reentran|steal|drain)", combined):
                return True

        # Emergency/upgrade function access (design choice)
        if re.search(
            r"(emergency|upgrade|migration)\s+(function|access)",
            combined,
        ):
            if re.search(r"(owner|admin|governance)", combined):
                return True

        # Unchecked return in safe contexts
        if re.search(r"unchecked\s+(return|call|result)", combined):
            if re.search(
                r"(safe.?transfer|safe.?call|try.?catch"
                r"|internal|trusted|known)",
                combined,
            ):
                return True

        # Token ordering without swap direction proof
        if re.search(r"token\s*ordering", combined):
            if not re.search(
                r"(swap.*wrong|reverse.*direction|loss\s+of)",
                combined,
            ):
                return True

        return False

    def consensus_filter(
        self,
        runs: list[list[Vulnerability]],
        min_appearances: int = 2,
    ) -> list[Vulnerability]:
        """Keep only findings that appear in >= min_appearances runs.

        Matches by (file, vulnerability_type) key. When matched,
        keeps the highest-confidence version.
        """
        from collections import defaultdict

        # Count appearances and track best version per key
        appearances = defaultdict(int)
        best_by_key = {}

        for run in runs:
            # Deduplicate within a single run first
            seen_in_run = set()
            for v in run:
                key = (v.file, v.vulnerability_type)
                if key in seen_in_run:
                    continue
                seen_in_run.add(key)
                appearances[key] += 1

                if key not in best_by_key or (
                    v.confidence > best_by_key[key].confidence
                ):
                    best_by_key[key] = v

        # Keep findings appearing in enough runs
        consensus = []
        for key, count in appearances.items():
            if count >= min_appearances:
                consensus.append(best_by_key[key])

        total = sum(len(r) for r in runs)
        filtered = total - len(consensus)
        if filtered > 0:
            console.print(
                f"[dim]  → Consensus filter: {len(consensus)} "
                f"findings confirmed across {len(runs)} runs "
                f"({filtered} not confirmed)[/dim]"
            )

        return consensus

    def rerank_findings(
        self,
        vulnerabilities: list[Vulnerability],
        files_content: dict[str, str],
    ) -> tuple[list[Vulnerability], int, int]:
        """Re-rank findings by sending them back to the LLM
        with source code for verification.

        Groups findings by file and verifies each group.

        Returns:
            Tuple of (verified_vulnerabilities, input_tokens,
            output_tokens)
        """
        from collections import defaultdict

        if not vulnerabilities:
            return [], 0, 0

        console.print("\n[bold cyan]Re-ranking verification pass[/bold cyan]")
        console.print(
            f"[dim]  → Verifying {len(vulnerabilities)} "
            f"findings against source code[/dim]"
        )

        # Group findings by file
        by_file = defaultdict(list)
        for v in vulnerabilities:
            by_file[v.file].append(v)

        verified = []
        total_in = 0
        total_out = 0

        for file_path, file_vulns in by_file.items():
            source_code = files_content.get(file_path, "")
            if not source_code:
                # No source available, keep findings (fail-safe)
                verified.extend(file_vulns)
                continue

            # Build related files context for cross-reference
            related_sources = self._resolve_related_files(
                file_path, source_code, file_vulns, files_content
            )

            batch_verified, in_tok, out_tok = self._rerank_batch(
                file_vulns, file_path, source_code, related_sources
            )
            verified.extend(batch_verified)
            total_in += in_tok
            total_out += out_tok

        rejected = len(vulnerabilities) - len(verified)
        if rejected > 0:
            console.print(
                f"[dim]  → Re-ranking rejected {rejected} "
                f"findings, kept {len(verified)}[/dim]"
            )
        else:
            console.print(
                f"[dim]  → Re-ranking kept all "
                f"{len(verified)} findings[/dim]"
            )

        return verified, total_in, total_out

    def _resolve_related_files(
        self,
        file_path: str,
        source_code: str,
        file_vulns: list[Vulnerability],
        files_content: dict[str, str],
    ) -> dict[str, str]:
        """Resolve imported and referenced files for context.

        Returns up to 3 related files within a ~30K char budget.
        """
        MAX_RELATED_CHARS = 30_000
        MAX_RELATED_FILES = 3

        candidates = set()

        # Extract Solidity import paths
        for m in re.finditer(r'import\s+"([^"]+)"', source_code):
            candidates.add(m.group(1))
        for m in re.finditer(
            r'import\s+\{[^}]+\}\s+from\s+"([^"]+)"',
            source_code,
        ):
            candidates.add(m.group(1))

        # Scan finding descriptions for references to other
        # filenames in the project
        all_filenames = {p.rsplit("/", 1)[-1]: p for p in files_content}
        for v in file_vulns:
            combined = f"{v.title} {v.description}"
            for fname, fpath in all_filenames.items():
                if fname in combined and fpath != file_path:
                    candidates.add(fpath)

        # Resolve import paths to actual project files
        resolved = {}
        for candidate in candidates:
            # Try direct match
            if candidate in files_content:
                resolved[candidate] = files_content[candidate]
                continue
            # Try matching by filename suffix
            cname = candidate.rsplit("/", 1)[-1]
            for proj_path, content in files_content.items():
                if proj_path.endswith(cname) and proj_path != file_path:
                    resolved[proj_path] = content
                    break

        # Trim to budget
        selected = {}
        total_chars = 0
        for path, content in sorted(resolved.items(), key=lambda x: len(x[1])):
            if len(selected) >= MAX_RELATED_FILES:
                break
            if total_chars + len(content) > MAX_RELATED_CHARS:
                continue
            selected[path] = content
            total_chars += len(content)

        return selected

    def _rerank_batch(
        self,
        vulnerabilities: list[Vulnerability],
        file_path: str,
        source_code: str,
        related_sources: dict[str, str] | None = None,
    ) -> tuple[list[Vulnerability], int, int]:
        """Verify a batch of findings for one file against its
        source code.

        Returns:
            Tuple of (verified_vulnerabilities, input_tokens,
            output_tokens)
        """
        # Build findings summary for the prompt
        findings_text = ""
        for i, v in enumerate(vulnerabilities):
            trace_text = ""
            if v.attack_trace:
                steps = "\n".join(
                    f"  {j}. {s}" for j, s in enumerate(v.attack_trace, 1)
                )
                trace_text = f"- **Attack Trace**:\n{steps}\n"
            findings_text += (
                f"\n### Finding {i + 1}\n"
                f"- **ID**: {v.id}\n"
                f"- **Title**: {v.title}\n"
                f"- **Type**: {v.vulnerability_type}\n"
                f"- **Severity**: {v.severity.value}\n"
                f"- **Confidence**: {v.confidence}\n"
                f"- **Location**: {v.location}\n"
                f"- **Description**: {v.description}\n"
                f"{trace_text}"
            )

        system_prompt = dedent("""
            You are verifying smart contract security findings.
            Your goal is to KEEP valid findings and only reject
            clear false positives.

            ## VERIFICATION METHOD
            1. Find the function/code mentioned in the finding.
               If no matching code exists, REJECT.
            2. Check if the finding's claim is supported by
               the actual code behavior.
            3. When uncertain, KEEP the finding — false
               negatives are worse than false positives.

            ## ONLY REJECT IF (clear false positives):
            1. The described function/pattern does NOT exist
               in the source file at all
            2. The finding claims "anyone can call" but the
               function has a direct access modifier like
               onlyOwner, onlyAdmin, onlyRole on it
            3. The finding claims reentrancy but the code
               uses ReentrancyGuard or nonReentrant modifier
            4. The finding targets a pure interface file
               with no implementation
            5. The finding targets a Mock/Test contract
            6. The finding claims admin trust issues (e.g.,
               "owner could rug") which are design choices

            ## KEEP IF (assume valid unless clearly wrong):
            A. The finding describes a plausible attack path
               even if you cannot fully verify all steps
            B. The finding identifies missing validation,
               incorrect calculation, or state inconsistency
            C. The finding describes privilege escalation,
               unauthorized access, or fund manipulation
            D. The finding describes protocol-specific logic
               errors (coordinator abuse, AMO integration,
               reward distribution, vesting calculations)
            E. The finding describes cross-contract issues
               that require understanding multiple files
            F. You are uncertain whether the finding is valid
               — when in doubt, KEEP it

            ## IMPORTANT
            - Do NOT reject findings just because they are
              complex or hard to verify
            - Do NOT reject findings about privileged roles
              (coordinator, operator) unless the role is
              clearly trusted by design
            - Do NOT reject findings about math/precision
              errors unless you can prove the math is correct
            - Protocol-specific findings (AMO, coordinator,
              validator rewards) are often valid — KEEP them

            ## OUTPUT FORMAT
            Output valid JSON:
            {
              "verified": [
                {
                  "id": "<finding ID>",
                  "keep": true/false,
                  "reason": "<brief reason>"
                }
              ]
            }

            IMPORTANT: Output ONLY valid JSON. Include ALL
            finding IDs. Default to keep=true when uncertain.
        """)

        # Build related files section
        related_section = ""
        if related_sources:
            related_section = (
                "\n\n## Related Source Files " "(for cross-reference)\n"
            )
            for rpath, rcontent in related_sources.items():
                related_section += f"### {rpath}\n```\n{rcontent}\n```\n\n"

        user_prompt = dedent(f"""
            Verify these findings against the source code.

            ## Source Code ({file_path})
            ```
            {source_code}
            ```
            {related_section}
            ## Findings to Verify
            {findings_text}

            For each finding, check if the described
            vulnerability actually exists in the code above.
            Use the related source files to verify cross-file
            claims (e.g., access control modifiers defined in
            base contracts).
        """)

        try:
            messages = [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt},
            ]

            response = self.inference(messages=messages)
            response_content = response["content"].strip()
            result = self.clean_json_response(response_content)

            input_tokens = response.get("input_tokens", 0)
            output_tokens = response.get("output_tokens", 0)

            # Build lookup of kept IDs
            kept_ids = set()
            for item in result.get("verified", []):
                if item.get("keep", False):
                    kept_ids.add(item.get("id", ""))
                else:
                    console.print(
                        f"[dim]  → Rejected: {item.get('id')} "
                        f"- {item.get('reason', 'no reason')}"
                        f"[/dim]"
                    )

            verified = [v for v in vulnerabilities if v.id in kept_ids]
            return verified, input_tokens, output_tokens

        except Exception as e:
            console.print(
                f"[red]Error in re-ranking for {file_path}: " f"{e}[/red]"
            )
            # Fail-safe: keep all findings on error
            return vulnerabilities, 0, 0

    def deduplicate_by_type(
        self, vulnerabilities: list[Vulnerability]
    ) -> list[Vulnerability]:
        """Deduplicate findings: keep top finding per
        (file, vulnerability_type) or (file, location) group."""
        from collections import defaultdict

        severity_order = {
            "critical": 0,
            "high": 1,
            "medium": 2,
            "low": 3,
        }

        def sort_key(x):
            return (
                severity_order.get(x.severity.value, 4),
                -x.confidence,
            )

        # First pass: deduplicate by (file, location) to catch
        # same root cause reported under different vuln types
        loc_groups = defaultdict(list)
        for v in vulnerabilities:
            loc_key = (v.file, v.location)
            loc_groups[loc_key].append(v)

        loc_deduped = []
        loc_dedup_count = 0
        for key, group in loc_groups.items():
            group.sort(key=sort_key)
            loc_deduped.append(group[0])
            loc_dedup_count += len(group) - 1

        # Second pass: deduplicate by (file, vulnerability_type)
        type_groups = defaultdict(list)
        for v in loc_deduped:
            type_key = (v.file, v.vulnerability_type)
            type_groups[type_key].append(v)

        deduped = []
        type_dedup_count = 0
        for key, group in type_groups.items():
            group.sort(key=sort_key)
            deduped.append(group[0])
            type_dedup_count += len(group) - 1

        total_dedup = loc_dedup_count + type_dedup_count
        if total_dedup > 0:
            console.print(
                f"[dim]  → Deduplicated {total_dedup} "
                f"redundant findings[/dim]"
            )

        return deduped

    def post_process_vulnerabilities(
        self,
        vulnerabilities: Vulnerabilities,
        file_path: str,
    ) -> Vulnerabilities:
        """Post-process vulnerabilities: filter by confidence
        and standardize locations."""
        confidence_threshold = 0.90
        filtered = []
        filtered_count = 0
        noise_count = 0

        for v in vulnerabilities.vulnerabilities:
            # Filter known noise patterns first
            if self._is_noise_finding(v):
                noise_count += 1
                continue

            calibrated_confidence = v.confidence

            # Penalize findings with missing or weak attack traces
            if not v.attack_trace:
                calibrated_confidence = max(0.0, calibrated_confidence - 0.06)
            elif len(v.attack_trace) == 1:
                calibrated_confidence = max(0.0, calibrated_confidence - 0.03)

            # Boost confidence for well-formed Contract.function locations
            location_parts = v.location.replace(":", ".").split(".")
            if len(location_parts) >= 2:
                # Check if first part looks like a contract name (capitalized)
                if location_parts[0] and location_parts[0][0].isupper():
                    calibrated_confidence = min(
                        1.0, calibrated_confidence + 0.05
                    )

            # Reduce confidence for vague/speculative language
            vague_patterns = [
                r"\bmight\b",
                r"\bpossibly\b",
                r"\bcould potentially\b",
                r"\bmay be\b",
                r"\bmay cause\b",
                r"\bmay lead\b",
                r"\btheoretically\b",
                r"\bin theory\b",
                r"\bif .{0,30} is compromised\b",
                r"\bassuming .{0,30} (fails|is malicious)\b",
                r"\bcould be manipulated\b",
                r"\bin certain (conditions|scenarios|cases)\b",
                r"\bunder (certain|specific) " r"(conditions|circumstances)\b",
                r"\bif .{0,30} sets? .{0,20} to zero\b",
            ]
            # Use title + description for penalty matching
            desc_lower = f"{v.title} {v.description}".lower()
            vague_hits = sum(
                1 for p in vague_patterns if re.search(p, desc_lower)
            )
            calibrated_confidence = max(
                0.0, calibrated_confidence - (0.1 * vague_hits)
            )

            # Penalize inflated severity: critical/high claims
            # with only bounded/theoretical impact
            if v.severity.value in ("critical", "high"):
                low_impact_patterns = [
                    r"\b(1\s+wei|dust|negligible|rounding)\b",
                    r"\bonly\s+(the\s+)?(owner|admin|deployer)\b",
                    r"\b(view|pure|read.?only)\s+function\b",
                    r"\bno\s+(direct\s+)?fund\s+loss\b",
                ]
                severity_hits = sum(
                    1 for p in low_impact_patterns if re.search(p, desc_lower)
                )
                if severity_hits > 0:
                    calibrated_confidence = max(
                        0.0,
                        calibrated_confidence - (0.15 * severity_hits),
                    )

            # Penalize admin/operator misconfiguration framing
            admin_framing = [
                r"\b(admin|owner|deployer|operator)\s+"
                r"(could|can|may)\s+(mistakenly|accidentally"
                r"|inadvertently)",
                r"\bby\s+mistake\b",
                r"\bif\s+(the\s+)?(admin|owner)\s+"
                r"(sets?|configures?|passes?)\b",
            ]
            admin_hits = sum(
                1 for p in admin_framing if re.search(p, desc_lower)
            )
            if admin_hits > 0:
                calibrated_confidence = max(
                    0.0,
                    calibrated_confidence - (0.15 * admin_hits),
                )

            # Penalize transferFrom-in-proxy-context FPs
            # where the description claims approval will fail
            # but the contract operates via delegatecall
            if (
                re.search(
                    r"(will\s+fail|revert|cause.*fail)",
                    desc_lower,
                )
                and re.search(
                    r"(approv|allowance|transferfrom)",
                    desc_lower,
                )
                and re.search(
                    r"(proxy|action|delegatecall)",
                    desc_lower,
                )
            ):
                calibrated_confidence = max(0.0, calibrated_confidence - 0.15)

            # Penalize "unvalidated external call" on targets
            # set via constructor/admin (immutable or storage)
            if re.search(
                r"unvalidated\s+(external\s+)?(call|staticcall)",
                desc_lower,
            ) and re.search(
                r"(constructor|immutable|admin|owner|set\s+by"
                r"|configured|initialized)",
                desc_lower,
            ):
                calibrated_confidence = max(0.0, calibrated_confidence - 0.15)

            # Penalize "incorrect" claims without exploit path
            if re.search(
                r"\b(incorrect|wrong|flawed)\s+"
                r"(calculation|computation|formula|logic"
                r"|handling|comparison|validation)\b",
                desc_lower,
            ) and not re.search(
                r"(attacker|exploit|steal|drain|loss\s+of"
                r"|profit|arbitrage|manipulat)",
                desc_lower,
            ):
                calibrated_confidence = max(0.0, calibrated_confidence - 0.1)

            # Penalize "potential precision loss" findings
            if re.search(
                r"(potential|possible)\s+precision\s+loss",
                desc_lower,
            ):
                calibrated_confidence = max(0.0, calibrated_confidence - 0.15)

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

        if noise_count > 0:
            console.print(
                f"[dim]  → Filtered {noise_count} noise findings[/dim]"
            )
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

    def triage_files(
        self, files, source_dir
    ) -> tuple[dict[str, str], list, list, int, int]:
        """Classify files as core, supporting, or skip via LLM.

        Returns:
            (files_content, core_files, supporting_files,
             input_tokens, output_tokens)
        """
        console.print("\n[bold cyan]LLM file triage[/bold cyan]")

        # Read all files into dict
        files_content: dict[str, str] = {}
        for file_path in files:
            try:
                with open(file_path, "r", encoding="utf-8") as f:
                    content = f.read()
                if content.strip():
                    rel = str(file_path.relative_to(source_dir))
                    files_content[rel] = content
            except Exception:
                pass

        if not files_content:
            return {}, [], [], 0, 0

        # Infer main contract names from codebase directory name
        codebase_name = source_dir.name
        forced_core_files: set[str] = set()
        try:
            file_list = "\n".join(sorted(files_content.keys()))
            infer_prompt = (
                "Given a codebase named "
                f"'{codebase_name}' with these files:\n"
                f"{file_list}\n\n"
                "Which file paths are the MAIN contract "
                "files (the primary protocol logic)? "
                "Return ONLY a JSON list of relative "
                'paths, e.g. ["src/Vault.sol"]. '
                "Pick at most 5 files."
            )
            infer_resp = self.inference(
                messages=[{"role": "user", "content": infer_prompt}]
            )
            infer_text = infer_resp["content"].strip()
            infer_result = self.clean_json_response(infer_text)
            if isinstance(infer_result, list):
                forced_core_files = {
                    f for f in infer_result if f in files_content
                }
            if forced_core_files:
                console.print(
                    f"[dim]  → Inferred main files: "
                    f"{forced_core_files}[/dim]"
                )
        except Exception:
            pass

        # Build file summaries (path, size, first ~50 lines)
        summaries = []
        for rel_path, content in sorted(files_content.items()):
            lines = content.splitlines()[:50]
            preview = "\n".join(lines)
            summaries.append(
                f"### {rel_path} ({len(content)} bytes)\n"
                f"```\n{preview}\n```"
            )
        summaries_text = "\n\n".join(summaries)

        triage_prompt = dedent("""\
            You are a smart contract security triage assistant.
            Classify each file into one of three categories:

            - **core**: Main protocol logic — handles funds,
              state mutations, access control, liquidations,
              rewards, swaps, vaults, routers, staking.
            - **supporting**: Helper libraries, utility contracts,
              data structures, simple wrappers, math libraries.
            - **skip**: Pure interfaces with no implementation,
              abstract bases with no logic, empty/stub contracts.

            Output ONLY valid JSON:
            {"classifications": [
              {"file": "<relative_path>", "class": "core"},
              ...
            ]}
        """)

        user_prompt = "Classify these source files:\n\n" + summaries_text

        try:
            messages = [
                {"role": "system", "content": triage_prompt},
                {"role": "user", "content": user_prompt},
            ]
            response = self.inference(messages=messages)
            response_content = response["content"].strip()
            result = self.clean_json_response(response_content)

            input_tokens = response.get("input_tokens", 0)
            output_tokens = response.get("output_tokens", 0)

            # Parse classifications
            classifications = {}
            for item in result.get("classifications", []):
                file_name = item.get("file", "")
                file_class = item.get("class", "core")
                classifications[file_name] = file_class

            # Map back to Path objects
            path_by_rel = {str(f.relative_to(source_dir)): f for f in files}

            # Force inferred main files to core
            for fp in forced_core_files:
                classifications[fp] = "core"

            core_files = []
            supporting_files = []
            skip_count = 0
            for rel_path in files_content:
                cls = classifications.get(rel_path, "core")
                path_obj = path_by_rel.get(rel_path)
                if not path_obj:
                    continue
                if cls == "skip":
                    skip_count += 1
                elif cls == "supporting":
                    supporting_files.append(path_obj)
                else:
                    core_files.append(path_obj)

            console.print(
                f"[dim]  → Triage: {len(core_files)} core, "
                f"{len(supporting_files)} supporting, "
                f"{skip_count} skipped[/dim]"
            )

            return (
                files_content,
                core_files,
                supporting_files,
                input_tokens,
                output_tokens,
            )

        except Exception as e:
            console.print(
                f"[yellow]Triage failed ({e}), treating "
                f"all files as core[/yellow]"
            )
            all_files = [
                f
                for f in files
                if str(f.relative_to(source_dir)) in files_content
            ]
            return files_content, all_files, [], 0, 0

    def analyze_file(
        self,
        relative_path: str,
        content: str,
        prompt_name: str = "",
        system_prompt: str = "",
    ) -> tuple[Vulnerabilities, int, int]:
        """Analyze a single file for security vulnerabilities.

        Args:
            relative_path: Path to the file relative to source dir
            content: File content
            prompt_name: Name of the audit prompt domain
            system_prompt: Pre-built system prompt to use

        Returns:
            Tuple of (vulnerabilities, input_tokens, output_tokens)
        """
        file_path = Path(relative_path)

        label = f" [{prompt_name}]" if prompt_name else ""
        console.print(
            f"[dim]  → Analyzing {relative_path}{label} "
            f"({len(content)} bytes)[/dim]"
        )

        if not system_prompt:
            parser = PydanticOutputParser(pydantic_object=Vulnerabilities)
            format_instructions = parser.get_format_instructions()
            system_prompt = _build_audit_prompt(
                APPROACH_A_LOGIC_FUNDS, format_instructions
            )

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
            response_content = response["content"].strip()

            msg_json = self.clean_json_response(response_content)

            vulnerabilities = Vulnerabilities(**msg_json)
            for v in vulnerabilities.vulnerabilities:
                v.reported_by_model = self.config["model"]

            # Post-process vulnerabilities
            vulnerabilities = self.post_process_vulnerabilities(
                vulnerabilities, relative_path
            )

            if vulnerabilities.vulnerabilities:
                console.print(
                    f"[green]  → Found {len(vulnerabilities.vulnerabilities)} vulnerabilities[/green]"
                )
            else:
                console.print("[yellow]  → No vulnerabilities found[/yellow]")

            input_tokens = response.get("input_tokens", 0)
            output_tokens = response.get("output_tokens", 0)

            return vulnerabilities, input_tokens, output_tokens

        except Exception as e:
            console.print(f"[red]Error analyzing {file_path.name}: {e}[/red]")
            return Vulnerabilities(vulnerabilities=[]), 0, 0

    def process_file(self, file_path, source_dir, approaches=None):
        relative_path = str(file_path.relative_to(source_dir))

        try:
            with open(file_path, "r", encoding="utf-8") as f:
                content = f.read()

            if not content.strip():
                return "skipped", None

            if approaches is None:
                approaches = AUDIT_APPROACHES

            parser = PydanticOutputParser(pydantic_object=Vulnerabilities)
            format_instructions = parser.get_format_instructions()

            all_findings = []
            total_input_tokens = 0
            total_output_tokens = 0

            for prompt_name, domain_section in approaches:
                sys_prompt = _build_audit_prompt(
                    domain_section, format_instructions
                )
                vulns, in_tok, out_tok = self.analyze_file(
                    relative_path,
                    content,
                    prompt_name=prompt_name,
                    system_prompt=sys_prompt,
                )
                all_findings.extend(vulns.vulnerabilities)
                total_input_tokens += in_tok
                total_output_tokens += out_tok

            # Deduplicate by ID across approaches
            unique = {v.id: v for v in all_findings}
            confirmed = list(unique.values())

            return "ok", (
                confirmed,
                total_input_tokens,
                total_output_tokens,
            )

        except Exception as e:
            return "error", (file_path.name, e)

    def analyze_project(
        self,
        source_dir: Path,
        project_name: str,
        file_patterns: list[str] | None = None,
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
            patterns = [
                "**/*.sol",
                "**/*.vy",
                "**/*.cairo",
                "**/*.rs",
                "**/*.move",
            ]
            files = []
            for pattern in patterns:
                files.extend(source_dir.glob(pattern))

        # Remove duplicates and filter out non-auditable files
        exclude_dirs = {
            "test",
            "tests",
            "testing",
            "mocks",
            "mock",
            "examples",
            "scripts",
            "script",
            "vendor",
            "lib",
            "node_modules",
            "artifacts",
            "cache",
            "deploy",
            "deployment",
            "migrations",
            ".git",
            "out",
            "dist",
            "build",
            "node",
            "external",
            "libraries",
        }
        exclude_prefixes = ("test", "mock", "fake", "stub")
        exclude_suffixes = (".t.sol",)
        interface_prefix = "i"

        files = set(files)
        filtered = []
        for f in files:
            if not f.is_file():
                continue
            # Skip very large files (>500KB)
            if f.stat().st_size > 500_000:
                continue
            # Skip multi-extension files (e.g., file.s.sol,
            # file.t.sol deploy scripts / test scripts)
            if "." in f.stem:
                continue
            name_lower = f.name.lower()
            stem_lower = f.stem.lower()
            # Skip test and mock files
            if any(name_lower.startswith(p) for p in exclude_prefixes):
                continue
            if any(name_lower.endswith(s) for s in exclude_suffixes):
                continue
            # Skip files in excluded directories
            parts_lower = {part.lower() for part in f.parts}
            if parts_lower & exclude_dirs:
                continue
            # Skip Solidity interface files (IFoo.sol pattern)
            if (
                f.suffix == ".sol"
                and len(stem_lower) > 1
                and stem_lower[0] == interface_prefix
                and f.stem[1].isupper()
            ):
                continue
            filtered.append(f)
        files = filtered

        # Respect project-level out_of_scope.txt
        scope_file = source_dir / "out_of_scope.txt"
        if scope_file.exists():
            try:
                scope_lines = scope_file.read_text().strip().splitlines()
                out_of_scope = set()
                for line in scope_lines:
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    out_of_scope.add(line)

                if out_of_scope:
                    before = len(files)
                    files = [
                        f
                        for f in files
                        if not any(
                            str(f.relative_to(source_dir)).startswith(oos)
                            or f.name == oos
                            for oos in out_of_scope
                        )
                    ]
                    excluded = before - len(files)
                    if excluded > 0:
                        console.print(
                            f"[dim]  Excluded {excluded} "
                            f"files via "
                            f"out_of_scope.txt[/dim]"
                        )
            except Exception:
                pass

        if not files:
            console.print("[yellow]No files found to analyze[/yellow]")
            return AnalysisResult(
                project=project_name,
                timestamp=datetime.now().isoformat(),
                files_analyzed=0,
                files_skipped=0,
                total_vulnerabilities=0,
                vulnerabilities=[],
                token_usage={
                    "input_tokens": 0,
                    "output_tokens": 0,
                    "total_tokens": 0,
                },
            )

        console.print(f"[dim]Found {len(files)} files to analyze[/dim]")

        # LLM file triage
        (
            files_content,
            core_files,
            supporting_files,
            triage_in,
            triage_out,
        ) = self.triage_files(files, source_dir)

        total_input_tokens = triage_in
        total_output_tokens = triage_out

        # Build work items: core gets all approaches,
        # supporting gets approach A only
        work_items = []
        for fp in core_files:
            work_items.append((fp, AUDIT_APPROACHES))
        for fp in supporting_files:
            work_items.append((fp, [AUDIT_APPROACHES[0]]))

        # Analyze files
        all_vulnerabilities = []
        files_analyzed = 0
        files_skipped = 0

        total_work = len(work_items)
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
            TimeRemainingColumn(),
            console=console,
            transient=False,
        ) as progress:
            task = progress.add_task(
                f"Analyzing {total_work} files...",
                total=total_work,
            )

            with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
                futures = {
                    executor.submit(
                        self.process_file,
                        fp,
                        source_dir,
                        approaches,
                    ): fp
                    for fp, approaches in work_items
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
                        console.print(
                            f"[red]Error processing "
                            f"{filename}: {err}[/red]"
                        )
                        files_skipped += 1

                    progress.advance(task)

        # Pass 2: Cross-contract analysis
        # (reuse files_content from triage)
        MAX_CROSS_CONTRACT_TOKENS = 100_000
        total_chars = sum(len(c) for c in files_content.values())
        estimated_tokens = total_chars // 4

        if estimated_tokens > MAX_CROSS_CONTRACT_TOKENS:
            console.print(
                f"[yellow]Skipping cross-contract pass: "
                f"~{estimated_tokens:,} tokens exceeds "
                f"{MAX_CROSS_CONTRACT_TOKENS:,} limit[/yellow]"
            )
        elif files_content:
            console.print(
                f"[dim]Cross-contract pass: ~{estimated_tokens:,} "
                f"tokens across {len(files_content)} files[/dim]"
            )
            cc_vulns, cc_in, cc_out = self.analyze_cross_contract(
                files_content
            )
            all_vulnerabilities.extend(cc_vulns.vulnerabilities)
            total_input_tokens += cc_in
            total_output_tokens += cc_out

        # Deduplicate vulnerabilities by ID, then by (file, type)
        unique_vulnerabilities = {v.id: v for v in all_vulnerabilities}
        vulns = list(unique_vulnerabilities.values())
        vulns = self.deduplicate_by_type(vulns)

        # Pass 3: Re-ranking verification
        vulns, rerank_in, rerank_out = self.rerank_findings(
            vulns, files_content
        )
        total_input_tokens += rerank_in
        total_output_tokens += rerank_out

        # Cap total findings to reduce false positive noise
        MAX_FINDINGS = 5
        if len(vulns) > MAX_FINDINGS:
            sev_order = {
                "critical": 0,
                "high": 1,
                "medium": 2,
                "low": 3,
            }
            vulns.sort(
                key=lambda x: (
                    sev_order.get(x.severity.value, 4),
                    -x.confidence,
                )
            )
            dropped = len(vulns) - MAX_FINDINGS
            vulns = vulns[:MAX_FINDINGS]
            console.print(
                f"[dim]  → Capped to top {MAX_FINDINGS} "
                f"findings (dropped {dropped})[/dim]"
            )

        result = AnalysisResult(
            project=project_name,
            timestamp=datetime.now().isoformat(),
            files_analyzed=files_analyzed,
            files_skipped=files_skipped,
            total_vulnerabilities=len(vulns),
            vulnerabilities=vulns,
            token_usage={
                "input_tokens": total_input_tokens,
                "output_tokens": total_output_tokens,
                "total_tokens": total_input_tokens + total_output_tokens,
            },
        )

        self.print_summary(result)

        return result

    def print_summary(self, result: AnalysisResult):
        """Print analysis summary."""
        console.print(f"\n[bold]Summary for {result.project}:[/bold]")
        console.print(f"  Files analyzed: {result.files_analyzed}")
        console.print(f"  Files skipped: {result.files_skipped}")
        console.print(
            f"  Total vulnerabilities: {result.total_vulnerabilities}"
        )
        console.print(f"  Token usage: {result.token_usage['total_tokens']:,}")
        console.print(
            f"    Input tokens: {result.token_usage['input_tokens']:,}"
        )
        console.print(
            f"    Output tokens: {result.token_usage['output_tokens']:,}"
        )

        if result.vulnerabilities:
            # Count by severity
            severity_counts = {}
            for vulnerability in result.vulnerabilities:
                sev = vulnerability.severity
                severity_counts[sev] = severity_counts.get(sev, 0) + 1

            console.print("  By severity:")
            for sev in [
                Severity.CRITICAL,
                Severity.HIGH,
                Severity.MEDIUM,
                Severity.LOW,
            ]:
                if sev.value in severity_counts:
                    color = {
                        Severity.CRITICAL: "red",
                        Severity.HIGH: "orange1",
                        Severity.MEDIUM: "yellow",
                        Severity.LOW: "green",
                    }[sev]
                    console.print(
                        f"    [{color}]{sev.value.capitalize()}:[/{color}] {severity_counts[sev.value]}"
                    )

    def save_result(
        self, result: AnalysisResult, output_file: str = "agent_report.json"
    ):
        result_dict = result.model_dump()

        with open(output_file, "w", encoding="utf-8") as f:
            json.dump(result_dict, f, indent=2)

        console.print(f"\n[green]Results saved to: {output_file}[/green]")
        return output_file


def agent_main(project_dir: str = None, inference_api: str = None):
    config = {"model": "deepseek-ai/DeepSeek-V3.2"}

    if not project_dir:
        project_dir = "/app/project_code"

    console.print(
        Panel.fit(
            "[bold cyan]SCABENCH BASELINE RUNNER[/bold cyan]\n"
            f"[dim]Model: {config['model']}[/dim]\n",
            border_style="cyan",
        )
    )

    try:
        runner = BaselineRunner(config, inference_api)

        source_dir = Path(project_dir) if project_dir else None
        if (
            not source_dir
            or not source_dir.exists()
            or not source_dir.is_dir()
        ):
            console.print(
                f"[red]Error: Invalid source directory: {project_dir}[/red]"
            )
            sys.exit(1)

        result = runner.analyze_project(
            source_dir=source_dir,
            project_name=project_dir,
        )

        output_file = runner.save_result(result)

        # Final summary
        console.print("\n" + ("=" * 60))
        console.print(
            Panel.fit(
                f"[bold green]ANALYSIS COMPLETE[/bold green]\n\n"
                f"Project: {result.project}\n"
                f"Files analyzed: {result.files_analyzed}\n"
                f"Total vulnerabilities: {result.total_vulnerabilities}\n"
                f"Results saved to: {output_file}",
                border_style="green",
            )
        )

        return result.model_dump(mode="json")

    except ValueError as e:
        console.print(f"[red]Configuration error: {e}[/red]")
        sys.exit(1)

    except Exception as e:
        console.print(f"[red]Error: {e}[/red]")
        print(traceback.print_exc())
        sys.exit(1)


if __name__ == "__main__":
    from scripts.projects import fetch_projects
    from validator.manager import SandboxManager

    SandboxManager(is_local=True)
    time.sleep(10)  # wait for proxy to start
    fetch_projects()
    inference_api = "http://localhost:8087"
    report = agent_main(
        "projects/code4rena_secondswap_2025_02", inference_api=inference_api
    )
