#!/usr/bin/env python3
"""
Tests for validator/agent_sandbox/run_sandbox.py

These tests verify the multiprocessing timeout handling in run_sandbox.py.
"""

import os
import sys
import tempfile
import pytest
from pathlib import Path

# Add project root to path
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

from validator.agent_sandbox.run_sandbox import run_with_timeout


class TestRunSandboxTimeout:
    """Tests for timeout handling in run_sandbox.py"""

    def create_mock_agent(self, sleep_time: float, temp_dir: str) -> str:
        """Create a temporary agent file that sleeps and returns a result.

        Args:
            sleep_time: How long the agent should sleep (seconds)
            temp_dir: Directory to create the agent file in

        Returns:
            Path to the created agent file
        """
        agent_code = f'''
import time

def agent_main():
    """Mock agent that sleeps then returns success."""
    time.sleep({sleep_time})
    return {{"vulnerabilities": [], "test": "success"}}
'''
        agent_path = os.path.join(temp_dir, "test_agent.py")
        with open(agent_path, "w") as f:
            f.write(agent_code)
        return agent_path

    @pytest.mark.parametrize("timeout,sleep_time", [
        (5, 3),    # 5s timeout, agent sleeps 3s (plenty of margin for spawn overhead)
        (5, 4),    # 5s timeout, agent sleeps 4s (tighter margin)
        (10, 8),   # 10s timeout, agent sleeps 8s
    ])
    def test_no_false_timeout_near_boundary(self, timeout: int, sleep_time: int):
        """Test that agents completing before timeout don't get false timeout.

        This test verifies the basic timeout behavior - an agent that finishes
        well before the timeout should return success, not a timeout error.

        Args:
            timeout: Timeout in seconds
            sleep_time: How long the agent sleeps (should be < timeout)
        """

        with tempfile.TemporaryDirectory() as temp_dir:
            agent_path = self.create_mock_agent(sleep_time, temp_dir)

            # Force multiprocessing mode (the path where the bug exists)
            original_force = os.environ.get("FORCE_MULTIPROCESSING")
            os.environ["FORCE_MULTIPROCESSING"] = "true"

            try:
                result = run_with_timeout(agent_path, timeout_seconds=timeout)

                # The agent completed successfully and put result in queue
                # It should NOT be reported as a timeout
                assert result.get("success") is True, (
                    f"Expected success=True but got {result}. "
                    f"This indicates the race condition bug: agent finished in {sleep_time}s "
                    f"(under {timeout}s timeout) but was falsely reported as timeout."
                )
                assert result.get("error") != "Agent timeout", (
                    f"Got false 'Agent timeout' error. Agent finished in {sleep_time}s "
                    f"which is under the {timeout}s timeout. The result was in the queue "
                    f"but process.is_alive() was checked before queue.get()."
                )

            finally:
                # Restore original environment
                if original_force is None:
                    os.environ.pop("FORCE_MULTIPROCESSING", None)
                else:
                    os.environ["FORCE_MULTIPROCESSING"] = original_force

    def test_real_timeout_detected(self):
        """Test that a real timeout (agent runs too long) is correctly detected.

        This is a sanity check to ensure the timeout mechanism works at all.
        """
        timeout = 2
        sleep_time = timeout + 2  # Agent will definitely exceed timeout

        with tempfile.TemporaryDirectory() as temp_dir:
            agent_path = self.create_mock_agent(sleep_time, temp_dir)

            original_force = os.environ.get("FORCE_MULTIPROCESSING")
            os.environ["FORCE_MULTIPROCESSING"] = "true"

            try:
                result = run_with_timeout(agent_path, timeout_seconds=timeout)

                # This should be a real timeout
                assert result.get("success") is False, (
                    f"Expected success=False for real timeout but got {result}"
                )
                assert result.get("error") == "Agent timeout", (
                    f"Expected 'Agent timeout' error but got: {result.get('error')}"
                )

            finally:
                if original_force is None:
                    os.environ.pop("FORCE_MULTIPROCESSING", None)
                else:
                    os.environ["FORCE_MULTIPROCESSING"] = original_force

    @pytest.mark.parametrize("iterations", [5])
    def test_race_condition_multiple_runs(self, iterations: int):
        """Run the boundary test multiple times to increase chance of hitting race.

        The race condition is timing-dependent, so running multiple iterations
        increases the probability of observing the bug.

        Args:
            iterations: Number of times to run the test
        """
        timeout = 6
        sleep_time = 5  # 5s sleep with 6s timeout - 1s margin

        false_timeouts = 0
        successes = 0

        with tempfile.TemporaryDirectory() as temp_dir:
            agent_path = self.create_mock_agent(sleep_time, temp_dir)

            original_force = os.environ.get("FORCE_MULTIPROCESSING")
            os.environ["FORCE_MULTIPROCESSING"] = "true"

            try:
                for i in range(iterations):
                    result = run_with_timeout(agent_path, timeout_seconds=timeout)

                    if result.get("success") is True:
                        successes += 1
                    elif result.get("error") == "Agent timeout":
                        false_timeouts += 1

            finally:
                if original_force is None:
                    os.environ.pop("FORCE_MULTIPROCESSING", None)
                else:
                    os.environ["FORCE_MULTIPROCESSING"] = original_force

        # Report results
        print(f"\nRace condition test results ({iterations} iterations):")
        print(f"  Successes: {successes}")
        print(f"  False timeouts: {false_timeouts}")

        # All runs should succeed - agent finishes before timeout
        assert false_timeouts == 0, (
            f"Got {false_timeouts} false timeouts out of {iterations} runs. "
            f"This confirms the race condition bug exists. "
            f"Agent finished in {sleep_time}s (under {timeout}s timeout) "
            f"but process.is_alive() was checked before queue.get()."
        )


    def test_boundary_race_condition(self):
        """Test the exact race condition at the timeout boundary.

        This test creates an agent that finishes at EXACTLY the timeout boundary
        to maximize the chance of hitting the race condition where:
        1. process.join(timeout) returns because timeout elapsed
        2. But the process ALSO just finished (within milliseconds)
        3. process.is_alive() may return True briefly
        4. Current code reports "Agent timeout" without checking queue

        The bug is that the code checks is_alive() BEFORE checking the queue.
        If the process finished and put result in queue, but is_alive() briefly
        returns True due to process cleanup timing, the result is lost.

        NOTE: This race condition is hard to reproduce reliably because it requires
        the process to finish at EXACTLY the timeout moment. In practice, the bug
        manifests when:
        - Agent takes ~1150s on a 1200s timeout (as reported in the issue)
        - System load causes timing variations
        - queue.put() takes time for large results

        This test uses aggressive timing to try to hit the window.
        """
        # Use a short timeout for faster testing
        timeout = 3

        false_timeouts = 0
        successes = 0
        other_errors = 0
        iterations = 20

        # Try different sleep times to find the race window
        # The race happens when: sleep_time + overhead ≈ timeout (within ~10ms)
        sleep_times = [
            timeout - 0.05,  # 50ms before timeout
            timeout - 0.02,  # 20ms before timeout
            timeout - 0.01,  # 10ms before timeout
            timeout,         # Exactly at timeout
            timeout + 0.01,  # 10ms after timeout (will definitely timeout)
        ]

        original_force = os.environ.get("FORCE_MULTIPROCESSING")
        os.environ["FORCE_MULTIPROCESSING"] = "true"

        try:
            for sleep_time in sleep_times:
                with tempfile.TemporaryDirectory() as temp_dir:
                    agent_path = self.create_mock_agent(sleep_time, temp_dir)

                    for i in range(iterations // len(sleep_times)):
                        result = run_with_timeout(agent_path, timeout_seconds=timeout)

                        if result.get("success") is True:
                            successes += 1
                        elif result.get("error") == "Agent timeout":
                            # Only count as false timeout if sleep_time < timeout
                            if sleep_time < timeout:
                                false_timeouts += 1
                                print(f"  FALSE TIMEOUT: sleep={sleep_time}s, timeout={timeout}s")
                        else:
                            other_errors += 1

        finally:
            if original_force is None:
                os.environ.pop("FORCE_MULTIPROCESSING", None)
            else:
                os.environ["FORCE_MULTIPROCESSING"] = original_force

        print(f"\nBoundary race condition test results ({iterations} iterations):")
        print(f"  Timeout: {timeout}s")
        print(f"  Successes: {successes}")
        print(f"  False timeouts: {false_timeouts}")
        print(f"  Other errors: {other_errors}")

        # If we get ANY false timeouts where agent finished before timeout, the bug is confirmed
        if false_timeouts > 0:
            pytest.fail(
                f"RACE CONDITION CONFIRMED: Got {false_timeouts} false timeouts. "
                f"Agent finished before {timeout}s timeout but was reported as timeout. "
                f"This is because process.is_alive() is checked BEFORE queue.get(). "
                f"The fix should check the queue FIRST before declaring timeout."
            )


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
