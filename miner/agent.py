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

## CRITICAL: AVOID DUPLICATES
Do NOT report multiple variations of the same underlying issue.
If a bug affects multiple functions, report it ONCE at the root \
cause location.
Report at most 2-3 findings for this prompt domain.

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


AUDIT_DOMAIN_1_CORE_SAFETY = """\
## HIGH-VALUE PATTERNS — Core Safety
Focus on fundamental smart contract safety issues:

1. **Reentrancy**: State updated AFTER external calls \
(transfers, low-level calls). Check if ReentrancyGuard or \
checks-effects-interactions is missing.
2. **Access control gaps**: Public/external functions that \
modify critical state without onlyOwner/onlyRole/auth \
modifiers. Trace internal helpers to their external callers.
3. **Integer overflow in Solidity <0.8**: Unchecked math in \
contracts using older pragma. In >=0.8, only flag unchecked{} \
blocks with actual overflow risk.
4. **Unchecked external calls**: Low-level call/delegatecall \
where return value is not checked, leading to silent failures \
that corrupt state.
5. **Storage collision**: Proxy/upgrade patterns where storage \
layouts conflict between implementation versions.

## OMISSION BUGS — Core Safety
1. **Missing state update after external interaction**: After \
a token transfer or external call succeeds, is the tracking \
variable updated? If not, replay or double-spend is possible.
2. **Missing access control on destructive functions**: \
selfdestruct, delegatecall targets, or upgrade functions \
without auth modifiers.
"""

AUDIT_DOMAIN_2_VESTING_CLAIMS = """\
## HIGH-VALUE PATTERNS — Vesting & Claims
Focus on token vesting, release schedules, and claiming logic:

1. **Incorrect formula after partial claim**: When \
transferring or splitting vesting positions, check if \
recalculations use ORIGINAL totals instead of REMAINING \
amounts. E.g., `releaseRate = totalAmount / steps` is wrong \
if some amount was already claimed; should be \
`(totalAmount - amountClaimed) / (steps - stepsClaimed)`.
2. **Claim amount exceeds available**: Can a beneficiary \
claim more tokens than they are entitled to? Check the \
calculation of claimable amount vs total allocation.
3. **Transfer-after-partial-claim errors**: When a vesting \
position is transferred, does the new owner inherit the \
correct remaining amount, or can they re-claim already-\
claimed tokens?
4. **Cliff/step boundary off-by-one**: Check if vesting \
cliff or step calculations have off-by-one errors allowing \
early or late claims.

## OMISSION BUGS — Vesting & Claims
1. **Missing amountClaimed update**: After a successful \
claim, is the claimed amount properly tracked?
2. **Missing revocation of unvested tokens**: In revocable \
vesting, are unvested tokens properly returned?
"""

AUDIT_DOMAIN_3_REWARD_DISTRIBUTION = """\
## HIGH-VALUE PATTERNS — Reward Distribution
Focus on fee/reward math, distribution indexes, and share \
accounting:

1. **Rounding-induced reward loss**: When distributing \
rewards, if `deltaIndex = accrued / totalShares` rounds to \
zero but `lastBalance` is still advanced, those rewards are \
permanently lost. Index and balance must advance together \
or not at all.
2. **Share dilution attacks**: Can an early depositor with \
1 wei of shares manipulate the reward index to steal from \
later depositors?
3. **Fee avoidance via public harvest/sync**: If harvest(), \
sync(), or update functions are public and reset accounting \
state, can a caller time these calls to avoid performance \
fees or inflate their share of rewards?
4. **Incorrect fee-on-transfer handling**: Does the contract \
account for tokens that take a fee on transfer, or does it \
assume received == sent?

## OMISSION BUGS — Reward Distribution
1. **Missing index update before share change**: When \
minting or burning shares, is the reward index updated \
first? If not, the new/removed shares earn/lose rewards \
they shouldn't.
2. **Missing accrual before claim**: Are pending rewards \
accrued before allowing a claim?
"""

AUDIT_DOMAIN_4_LIQUIDATION_PNL = """\
## HIGH-VALUE PATTERNS — Liquidation & PnL
Focus on liquidation thresholds, profit/loss accounting, \
and collateral handling:

1. **Incorrect liquidation threshold**: Is the liquidation \
condition checking the right ratio? Can healthy positions \
be liquidated or unhealthy ones escape liquidation?
2. **Profit vs loss accounting errors**: When calculating \
PnL across contracts, verify credits and debits sum \
correctly. Check sign handling (positive vs negative).
3. **Collateral not released after liquidation**: After a \
position is liquidated, is remaining collateral returned \
to the user?
4. **Liquidation bonus overflow**: Can the liquidation \
bonus exceed the available collateral, causing underflow?
5. **Self-liquidation for profit**: Can a user liquidate \
their own position to extract the liquidation bonus?

## OMISSION BUGS — Liquidation & PnL
1. **Missing bad debt handling**: When liquidation doesn't \
cover the debt, is the shortfall socialized or does it \
corrupt protocol accounting?
2. **Missing position deletion after full liquidation**: \
Is the position struct cleaned up, or can it be \
re-liquidated?
"""

AUDIT_DOMAIN_5_DEPOSIT_MINTING = """\
## HIGH-VALUE PATTERNS — Deposit & Minting
Focus on deposit/withdraw flows, share minting/burning, \
and exchange rate manipulation:

1. **First-depositor / inflation attack**: Can the first \
depositor manipulate the exchange rate by depositing 1 wei \
then donating a large amount, causing subsequent depositors \
to receive 0 shares? Check if there's a minimum deposit \
or virtual offset.
2. **Exchange rate manipulation via direct transfer**: Can \
sending tokens directly to the vault inflate the share \
price, causing rounding theft?
3. **Withdraw more than deposited**: Does the withdraw \
path correctly calculate the user's entitlement based on \
shares, not on deposit amount?
4. **Deposit/withdraw reentrancy**: In deposit() or \
withdraw(), is state updated before the external token \
transfer?

## OMISSION BUGS — Deposit & Minting
1. **Return value unit mismatch**: Does the function \
return shares when callers expect underlying assets, or \
vice versa? Check _deploy(), _undeploy(), _getBalance() \
for consistency.
2. **Missing _deployedAmount update**: After undeploy or \
withdraw, is the tracking variable updated?
3. **Missing totalSupply check**: Can withdraw/redeem \
proceed when totalSupply is zero, causing division by zero?
"""

AUDIT_DOMAIN_6_INTERFACE_COMPAT = """\
## HIGH-VALUE PATTERNS — Interface Compatibility
Focus on ERC standards compliance, callback handling, and \
token interaction patterns:

1. **Wrong token ordering assumptions**: When interacting \
with DEX pools (Uniswap V2/V3), verify the code queries \
actual token ordering via `token0()`/`token1()` rather \
than assuming a fixed position. Tokens are sorted \
lexicographically; hardcoded assumptions break.
2. **Missing ERC20 approval reset**: Some tokens (USDT) \
require approval to be set to 0 before setting a new \
value. Check if the contract handles this.
3. **Callback reentrancy via ERC721/ERC1155**: \
safeTransferFrom triggers onERC721Received/onERC1155\
Received callbacks. Is state updated before the transfer?
4. **Front-runnable deterministic deployments**: Factory \
contracts using CREATE2 produce predictable addresses. If \
subsequent calls (e.g., `createPair()`) depend on that \
address, an attacker can front-run and DoS the factory.
5. **Public function abuse / allowance drain**: When a \
contract holds ERC20 allowances from users, check if any \
public function lets a third party trigger transferFrom() \
with another user's address as `from`.

## OMISSION BUGS — Interface Compatibility
1. **Missing approval before transferFrom**: Does the \
contract approve tokens before calling transferFrom on \
behalf of users?
2. **Missing callback support**: If the contract should \
accept ERC721/ERC1155 tokens, does it implement the \
required receiver interfaces?
"""

AUDIT_PROMPTS = [
    ("core_safety", AUDIT_DOMAIN_1_CORE_SAFETY),
    ("vesting_claims", AUDIT_DOMAIN_2_VESTING_CLAIMS),
    ("reward_distribution", AUDIT_DOMAIN_3_REWARD_DISTRIBUTION),
    ("liquidation_pnl", AUDIT_DOMAIN_4_LIQUIDATION_PNL),
    ("deposit_minting", AUDIT_DOMAIN_5_DEPOSIT_MINTING),
    ("interface_compat", AUDIT_DOMAIN_6_INTERFACE_COMPAT),
]


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

            ## DESCRIPTION REQUIREMENTS
            Each finding MUST include:
            1. **All files/contracts involved** (e.g., "In StepVesting.sol and VestingManager.sol...")
            2. **The specific functions** using `functionName()` notation
            3. **Step-by-step exploit scenario** with concrete attacker actions
            4. **Concrete impact** (fund loss, permanent DoS, state corruption)

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
        """Use LLM to select related files for context.

        Returns up to 3 related files within a ~30K char budget.
        """
        MAX_RELATED_CHARS = 30_000
        MAX_RELATED_FILES = 3

        # Build list of available files (exclude current)
        available = [p for p in files_content if p != file_path]
        if not available:
            return {}

        # Ask LLM which files are most relevant
        file_list = "\n".join(f"- {p}" for p in available)
        findings_summary = "\n".join(
            f"- {v.title} ({v.vulnerability_type})" for v in file_vulns
        )

        messages = [
            {
                "role": "system",
                "content": (
                    "You select related source files for "
                    "security audit context. Output ONLY a "
                    "JSON array of file paths."
                ),
            },
            {
                "role": "user",
                "content": (
                    f"File being audited: {file_path}\n\n"
                    f"Findings to verify:\n"
                    f"{findings_summary}\n\n"
                    f"Available files:\n{file_list}\n\n"
                    f"Select up to {MAX_RELATED_FILES} files "
                    f"most relevant for verifying these "
                    f"findings (parent contracts, imported "
                    f"dependencies, contracts that interact "
                    f"with this one). Output JSON array of "
                    f"paths."
                ),
            },
        ]

        try:
            response = self.inference(messages=messages)
            content = response["content"].strip()
            selected_paths = json.loads(
                self.clean_json_response(content)
                if not content.startswith("[")
                else content
            )
        except Exception:
            # Fallback to regex-based resolution
            return self._resolve_related_files_regex(
                file_path, source_code, file_vulns, files_content
            )

        # Collect within budget
        result = {}
        total_chars = 0
        for p in selected_paths:
            if p in files_content and p != file_path:
                file_content = files_content[p]
                if total_chars + len(file_content) <= MAX_RELATED_CHARS:
                    result[p] = file_content
                    total_chars += len(file_content)
        return result

    def _resolve_related_files_regex(
        self,
        file_path: str,
        source_code: str,
        file_vulns: list[Vulnerability],
        files_content: dict[str, str],
    ) -> dict[str, str]:
        """Regex-based fallback for related file resolution.

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
            findings_text += (
                f"\n### Finding {i + 1}\n"
                f"- **ID**: {v.id}\n"
                f"- **Title**: {v.title}\n"
                f"- **Type**: {v.vulnerability_type}\n"
                f"- **Severity**: {v.severity.value}\n"
                f"- **Confidence**: {v.confidence}\n"
                f"- **Location**: {v.location}\n"
                f"- **Description**: {v.description}\n"
            )

        system_prompt = dedent("""
            You are an adversarial smart contract security
            reviewer. Your job is to separate real
            vulnerabilities from false positives.

            ## VERIFICATION METHOD — follow these steps:
            1. Find the function/code mentioned in the
               finding in the source. If the function or
               pattern does not exist, REJECT.
            2. Check if the function has access control
               modifiers ON THE FUNCTION ITSELF (onlyOwner,
               onlyAdmin, onlyRole, auth, etc.). Do NOT
               assume access control exists — verify it by
               reading the function signature.
            3. If the finding describes a multi-step attack,
               trace the full execution path: external
               entry point -> internal calls -> state changes.
               An internal function is reachable if any
               external/public function calls it.
            4. Verify the described impact against the actual
               code. If the finding claims "fund loss" or
               "fee avoidance", check whether the state
               change actually affects balances or fees.

            ## AUTOMATIC REJECT — discard immediately if:
            1. The described code pattern does NOT exist in
               the source file
            2. The function ITSELF has access control
               modifiers (onlyOwner, onlyAdmin,
               creditManagerOnly, onlyRole, auth, etc.)
               AND the finding claims "anyone can call" —
               but ONLY reject if the modifier is directly
               on that function, not assumed from context
            3. The finding mentions missing slippage /
               price-manipulation protection but no swap,
               AMM, or price oracle interaction exists in
               the code
            4. The finding claims reentrancy risk but the
               code uses ReentrancyGuard, nonReentrant, or
               follows checks-effects-interactions (state
               updated before external call)
            5. The finding targets a pure interface (no
               implementation). But DO NOT reject findings
               on abstract or base contracts if they have
               implemented functions with real logic
            6. The finding is about admin/owner trust
               assumptions (e.g., "owner could rug") —
               these are design choices, not vulnerabilities
            7. The description uses vague language like
               "could potentially", "might allow", or
               "may lead to" WITHOUT a concrete exploit
               sequence
            8. The described function or contract name does
               not appear in the source code
            9. The vulnerability is in dead code or
               unreachable paths
            10. The finding claims slippage/MEV risk but the
                function does not perform a swap, liquidity
                operation, or interact with a price-dependent
                external protocol
            11. The finding cites a comment, NatSpec, or
                documentation mismatch as evidence the code
                is wrong — only code behavior matters
            12. The finding claims a boolean/comparison is
                inverted but does not trace the correct
                expected behavior
            13. The finding claims "uninitialized" storage or
                mapping — Solidity zero-initializes all storage
            14. The finding flags a cooldown, time delay, or
                emergency governance function as a vulnerability
            15. The finding claims a function can be front-run
                but it is called atomically by a factory or
                within a batch transaction
            16. The finding claims a math formula is wrong
                (e.g., missing division, overflow) but you
                can verify the formula IS correct by reading
                the actual code
            17. The finding targets a mock or test contract
                (file/contract name contains Mock, Test, or
                is in a test directory)

            ## KEEP IF any of these patterns are confirmed:
            A. You can quote vulnerable line(s) AND there is
               a concrete exploit path with no existing guard
            B. A public/external function modifies state
               (storage writes, token transfers) WITHOUT
               access control, and an attacker calling it
               causes economic harm (fee avoidance, balance
               manipulation, token theft)
            C. A function accepts an attacker-controlled
               address parameter (e.g., `from`, `to`,
               `recipient`) and uses it in token transfers
               without verifying msg.sender == parameter
            D. A missing state update causes downstream
               accounting errors (e.g., _deployedAmount not
               updated, index not advanced with balance)
            E. An internal function called by an external
               entry point without access control can
               transfer tokens using third-party allowances

            ## IMPORTANT ANALYSIS RULES
            - Do NOT assume access control exists — read the
              actual function signature and modifiers
            - Trace internal functions to their external
              callers: if an internal function handles funds
              and its external caller has no access control,
              the internal function IS reachable by anyone
            - For base/abstract contracts: vulnerabilities
              in implemented functions are real even if the
              contract is abstract — subclasses inherit them
            - Verify claims against the code: if a finding
              says "fee calculation is wrong", check the
              actual formula in the code before deciding

            ## OUTPUT FORMAT
            Output valid JSON with this structure:
            {
              "verified": [
                {
                  "id": "<finding ID>",
                  "keep": true/false,
                  "reason": "<brief reason>",
                  "vulnerable_lines": "<quoted line(s) or null>"
                }
              ]
            }

            IMPORTANT: Output ONLY valid JSON. Include ALL
            finding IDs.
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
        self, vulnerabilities: Vulnerabilities, file_path: str
    ) -> Vulnerabilities:
        """Post-process vulnerabilities: filter by confidence and standardize locations."""
        confidence_threshold = 0.87
        filtered = []
        filtered_count = 0
        noise_count = 0

        for v in vulnerabilities.vulnerabilities:
            # Filter known noise patterns first
            if self._is_noise_finding(v):
                noise_count += 1
                continue

            calibrated_confidence = v.confidence

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
                AUDIT_DOMAIN_1_CORE_SAFETY, format_instructions
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

    def process_file(self, file_path, source_dir):
        relative_path = str(file_path.relative_to(source_dir))

        try:
            with open(file_path, "r", encoding="utf-8") as f:
                content = f.read()

            if not content.strip():
                return "skipped", None

            parser = PydanticOutputParser(pydantic_object=Vulnerabilities)
            format_instructions = parser.get_format_instructions()

            all_findings = []
            total_input_tokens = 0
            total_output_tokens = 0

            for prompt_name, domain_section in AUDIT_PROMPTS:
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

            # Deduplicate by ID across prompts
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
        }
        exclude_prefixes = ("test", "mock", "fake", "stub")
        exclude_suffixes = (".t.sol",)
        interface_prefix = "i"

        files = set(files)
        filtered = []
        for f in files:
            if not f.is_file():
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
            transient=False,
        ) as progress:
            task = progress.add_task(
                f"Analyzing {len(files)} files...", total=len(files)
            )

            with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
                futures = {
                    executor.submit(
                        self.process_file, file_path, source_dir
                    ): file_path
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
                        console.print(
                            f"[red]Error processing {filename}: {err}[/red]"
                        )
                        files_skipped += 1

                    progress.advance(task)

        # Pass 2: Cross-contract analysis
        MAX_CROSS_CONTRACT_TOKENS = 100_000
        files_content = {}
        for file_path in files:
            try:
                with open(file_path, "r", encoding="utf-8") as f:
                    content = f.read()
                if content.strip():
                    relative_path = str(file_path.relative_to(source_dir))
                    files_content[relative_path] = content
            except Exception:
                pass

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
        MAX_FINDINGS = 8
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
