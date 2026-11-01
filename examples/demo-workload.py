"""Demo agent workload for AgentCutter's live demo (see demo.sh).

A python "agent" matched by interpreter + argv token: writes files,
spawns child tools twice (re-run detection fodder), makes TCP + UDP
connects, with sleeps so the timeline has clear phases.
"""

import socket
import subprocess
import sys
import time

tag = sys.argv[1]

# Phase 1: file activity.
with open(f"/tmp/{tag}.txt", "w") as f:
    f.write("agentcutter live demo\n")
time.sleep(2)

# Phase 2: child tools, twice each.
for _ in range(2):
    subprocess.run(["true"], check=True)
    subprocess.run(["echo", tag], check=True, capture_output=True)
time.sleep(2)

# Phase 3: network (TCP to a local listener, UDP connect + send).
listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
listener.bind(("127.0.0.1", 0))
listener.listen(1)
s = socket.create_connection(listener.getsockname(), timeout=5)
s.close()
u = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
u.connect(("127.0.0.1", 53))
u.send(b"x")
u.close()
listener.close()
time.sleep(1)

with open(f"/tmp/{tag}.txt", "a") as f:
    f.write("done\n")
print("workload done:", tag, flush=True)
