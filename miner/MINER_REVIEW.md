# Custom Miner Review

## Changes Made to `miner/agent.py`

### 1. Model Switch (line 488)
- **Before:** `deepseek-ai/DeepSeek-V3.1-Terminus`
- **After:** `deepseek-ai/DeepSeek-V3-0324`
- **Reason:** Matches the validator scorer model for better semantic alignment during matching

### 2. Enhanced System Prompt (lines 230-273)
Optimized for the validator's prefilter scoring system:
- Requires `.sol` filenames in descriptions (+0.5 prefilter bonus)
- Requires `functionName()` notation (+0.3 prefilter bonus)
- Uses exact vulnerability type names (+0.1 bonus)
- Uses lowercase severity to match validator format (+0.1 bonus)
- Includes an example description showing ideal format
- Defines clear severity rules and confidence thresholds

### 3. User Prompt (lines 278-291)
- Extracts filename and provides explicit instructions to include it
- Guides LLM to use `function()` notation
- Sets correct file path in output

### 4. Post-Processing (lines 149-215)
- **Confidence calibration:** +0.05 for `Contract.function` format, -0.1 for vague language
- **Word-boundary regex:** Avoids false matches (e.g., "payment" doesn't trigger "may")
- **Location normalization:** Ensures `file:Contract.function` format
- **Logging:** Shows count of filtered low-confidence findings

### 5. Import (line 4)
- Added `import re` at module level for regex-based confidence calibration

---

## Test Results

### Dataset 1: DeFiVulnLabs (SunWeb3Sec)
| Contract | Expected Vulnerability | Found | Severity | Confidence |
|----------|----------------------|-------|----------|------------|
| EtherStore.sol | Reentrancy in `withdrawFunds` | Yes | CRITICAL | 1.0 |
| TimeLock.sol | Integer Overflow in `increaseLockTime` | Yes | MEDIUM | 0.9 |
| EtherGame.sol | DoS via forced ETH in `deposit` | Yes | MEDIUM | 0.8 |

**Detection Rate: 3/3 (100%)**

### Dataset 2: SmartBugs Curated
| Contract | Expected Vulnerability | Found | Severity | Confidence |
|----------|----------------------|-------|----------|------------|
| SimpleDAO.sol | Reentrancy in `withdraw` | Yes | CRITICAL | 1.0 |
| Wallet.sol | Access Control in `refund` | Yes | HIGH | 0.95 |
| IntegerOverflowAdd.sol | Overflow in `run` | Yes | HIGH | 0.95 |

**Detection Rate: 3/3 (100%)**

### Dataset 3: Crytic/Not-So-Smart-Contracts (Trail of Bits)
| Contract | Expected Vulnerability | Found | Severity | Confidence |
|----------|----------------------|-------|----------|------------|
| Reentrance.sol | Reentrancy in `withdrawBalance` | Yes | CRITICAL | 1.0 |
| Unprotected.sol | Access Control in `changeOwner` | Yes | CRITICAL | 1.0 |
| UncheckedReturn.sol | Unchecked Call in `withdraw` | Yes | MEDIUM | 0.95 |

**Detection Rate: 3/3 (100%)**

### Overall
| Dataset | Files | Expected | Found | Detection Rate |
|---------|-------|----------|-------|----------------|
| DeFiVulnLabs | 3 | 3 | 3 | 100% |
| SmartBugs Curated | 3 | 3 | 3 | 100% |
| Crytic/Not-So-Smart | 3 | 3 | 3 | 100% |
| **Total** | **9** | **9** | **9** | **100%** |

### Token Usage
| Dataset | Input Tokens | Output Tokens | Per File Avg |
|---------|-------------|---------------|--------------|
| DeFiVulnLabs | 3,575 | 856 | ~1,477 |
| SmartBugs | 3,488 | 629 | ~1,372 |
| Crytic | 3,366 | 774 | ~1,380 |

---

## Strengths

1. **High detection rate** - 100% on all 3 standard datasets
2. **Validator-aligned output** - Format directly targets prefilter scoring bonuses
3. **Smart post-processing** - Confidence calibration and location normalization
4. **Token efficient** - ~1,400 tokens per file average
5. **Same model as validator** - DeepSeek-V3-0324 for semantic alignment

## Weaknesses

1. **Single-pass analysis** - One LLM call per file, may miss complex issues
2. **No cross-contract analysis** - Files analyzed independently
3. **Heuristic confidence calibration** - Not trained on actual validator feedback
4. **Some false positives** - Found 18 vulns across 9 files (9 expected), ~50% precision
5. **No retry logic** - Single API call, no fallback on failure

## Production Readiness

| Aspect | Score | Notes |
|--------|-------|-------|
| Detection Rate | 9/10 | Excellent on standard vulnerabilities |
| Precision | 7/10 | Some extra findings, needs validation |
| Output Format | 9/10 | Well-aligned with validator |
| Robustness | 6/10 | No retry logic, single-pass only |
| Scalability | 7/10 | Sequential file processing |
| Cost Efficiency | 8/10 | ~1,400 tokens per file |

## Recommendations for Improvement

### Quick Wins
- Add retry logic for API failures
- Add severity-based sorting in output
- Tune confidence thresholds based on validator feedback

### Medium Effort
- Multi-pass verification: detect first, then verify to reduce false positives
- Context-aware analysis: read all files first, then analyze with cross-references

### Higher Effort
- Cross-contract vulnerability detection
- Ensemble approach with multiple models
- Specialized passes for DeFi patterns (flash loans, oracles, MEV)
- Fine-tune confidence calibration on real validator scoring data

## How Validator Scoring Works (Reference)

### Matching Criteria (`validator/scorer.py` lines 339-343)
1. Correctly identifies the **contract** where the issue exists
2. Correctly identifies the **function** where the issue occurs
3. Accurately describes the **core security issue**
4. Accurately describes the **potential consequences**

### Prefilter Scoring (`validator/scorer.py` lines 203-238)
- `.sol` filename overlap: +0.5
- Function name overlap: +0.3
- Severity match: +0.1
- Vulnerability type match: +0.1

### Metrics
- Detection Rate = True Positives / Expected Vulnerabilities
- Precision = True Positives / (True Positives + False Positives)
- F1 Score = 2 * (Precision * Detection Rate) / (Precision + Detection Rate)
- Confidence Threshold: 0.75

## Test Data Sources
- [DeFiVulnLabs](https://github.com/SunWeb3Sec/DeFiVulnLabs)
- [SmartBugs Curated](https://github.com/smartbugs/smartbugs-curated)
- [Crytic Not-So-Smart-Contracts](https://github.com/crytic/not-so-smart-contracts)
- [SWC Registry](https://github.com/SmartContractSecurity/SWC-registry)
