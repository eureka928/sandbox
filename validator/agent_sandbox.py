import importlib.util
import multiprocessing
import os
import json
import io
import contextlib
import traceback

TIMEOUT_SECONDS = 120
AGENT_FILE = "/app/agent.py"
REPORT_FILE = "/app/report.json"

def run_agent(agent_file, queue):
    stdout_capture = io.StringIO()
    stderr_capture = io.StringIO()

    try:
        with contextlib.redirect_stdout(stdout_capture), contextlib.redirect_stderr(stderr_capture):
            spec = importlib.util.spec_from_file_location("agent", agent_file)
            agent = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(agent)

            if not hasattr(agent, "agent_main"):
                raise AttributeError("agent.py does not define an 'agent_main()' function")

            result = agent.agent_main()
            resp = {"success": True, "result": result}

    except Exception as e:
        resp = {"success": False, "error": str(e)}

    resp.update({
        "stdout": stdout_capture.getvalue(),
        "stderr": stderr_capture.getvalue(),
    })

    queue.put(resp)

def run_with_timeout(agent_file, timeout_seconds=TIMEOUT_SECONDS):
    queue = multiprocessing.Queue()
    process = multiprocessing.Process(target=run_agent, args=(agent_file, queue))
    process.start()
    process.join(timeout_seconds)

    if process.is_alive():
        process.terminate()
        process.join()
        resp = {
            "success": False,
            "error": "Timeout",
        }

    elif not queue.empty():
        resp = queue.get()

    else:
        resp = {
            "success": False,
            "error": "No result returned",
        }

    resp.setdefault("stdout", "")
    resp.setdefault("stderr", "")

    return resp

if __name__ == "__main__":
    try:
        result = run_with_timeout(AGENT_FILE, TIMEOUT_SECONDS)

    except Exception as e:
        result = {
            "success": False,
            "error": f"Sandbox error",
            "exc": str(e),
            "traceback": traceback.format_exc(),
            "stdout": "",
            "stderr": "",
        }

    with open(REPORT_FILE, "w") as f:
        json.dump(result, f)
