import os

def agent_main():
    folder = "/app/project_code"
    for name in os.listdir(folder):
        print(name)

    return [{"response": "ok"}]
