## Session 400 — aider (`python3 -m aider --model test`)

### 1. One-line summary
Ran a single `git status` in `/work/beta`, opened `/tmp/beta.txt` and deleted `/tmp/beta-old.txt`, plus one local DNS lookup.

### 2. Timeline of phases
Offsets are capture offsets in ms (`offset_ms` / `start_ms` in report):

* **500–1200ms: agent alone.** `python3` pid 4000 started at 500ms. No child, no markers. 700ms = 1200-500.
* **1200–1600ms: `git status` spawn + network init.** `git` pid 4001 starts at 1200ms. First `socket/connect/mmap/read` cluster at 1500ms pid 4000.
* **1600–2000ms: file activity in child.** `file_open /tmp/beta.txt` at 1600ms pid 4001, `file_unlink /tmp/beta-old.txt` at 2000ms pid 4001.
* **2000–3000ms: DNS + second syscall cluster, child exit.** `net_connect udp 127.0.0.1:53 (DNS)` at 2600ms pid 4000. Second `first_seen` cluster at 2500ms (`clone/futex/openat/write`). `git` ends at 3000ms.
* **3000–4000ms: agent alone, truncated.** `python3` continues to 4000ms with `open_ended=true`; capture ends at 4000ms.

### 3. Where the time went
* `top_programs_by_wall_time`: `python3` 3500ms, `git` 1800ms.
* Session `duration_ms` is 2500ms (00:00:00.5Z to 00:00:03Z), but processes sum to 5300ms = 3500+1800 because they overlap.
* Overlap: `git` 1200–3000ms is fully inside `python3` 500–4000ms. Overlapped time = 1800ms. Python-only head = 700ms (1200-500).
* Child share of session window: 1800/2500 = 72%.
* CPU vs wall: `git` `cpu_user_ms` 8 + `cpu_sys_ms` 4 = 12ms vs 1800ms wall = 12/1800 = 0.67% CPU. Child was almost entirely blocked, not computing.
* `python3` has no `cpu_user_ms/cpu_sys_ms` because it is `open_ended` — CPU unknown.
* Syscalls total 36: `file` 17 (47.22%), `memory` 9 (25%), `sync/wait` 5 (13.89%), `network` 4 (11.11%), `process` 1 (2.78%). Attribution: `python3` 23 (63.89%), `git` 13 (36.11%).

### 4. Bottlenecks and waste
1. **`git status` wall time dominates with no CPU.** 1800ms wall for 12ms CPU. This is the session's largest wall-time cost — 72% of the 2500ms session. Evidence: `duration_ms` 1800, `max_rss_kb` only 12288, `futex` 5 + `openat` 4 + `write` 3 in git attribution suggests wait/block, not work.
2. **No re-run waste.** Verified: `find_repeated_commands` returns `distinct_commands: 2, repeated: []`. `exec_count` is 1 for both `git` and `python3`.
3. **No re-read waste.** `files_touched`: `/tmp/beta.txt` count 1, `/tmp/beta-old.txt` count 1.
4. **No connection-reuse issue.** One `connect` syscall, one destination `127.0.0.1:53 count 1, dns_count 1`. Verified by `network_activity`: `total_connects: 1`.

Ranked impact: #1 is the only material cost.

### 5. Optimizations
* **Investigate / eliminate the 1800ms `git status` block.** A normal `status` in a small repo should be tens of ms. Check if it blocked on DNS (DNS at 2600ms overlaps git lifetime), on `/tmp` I/O, or on a pager/lock. If status output is needed between steps, cache it for the session. Expected saving: ~1700ms if reduced to ~100ms (1800-100), i.e. ~68% of session window (1700/2500).

### 6. Notable behavior
* `file_unlink /tmp/beta-old.txt` at 2000ms by pid 4001 (`git` process, per markers) — deleting outside `/work/beta`.
* `file_open /tmp/beta.txt` at 1600ms pid 4001.
* `notable_syscalls`: only `connect count 1 first_seen 1500ms`. No `execve/unlink/ptrace/setuid/mount/bpf/kill` in summary; the unlink appears only as a marker, not as an `unlink` syscall in this session's distribution.
* Network only `udp 127.0.0.1:53` — local DNS, no port 443, so no likely model-call evidence in this window.

### 7. Data gaps
* Root `open_ended=true`, `end_ms` 4000 = `capture_end`; session `end` 00:00:03Z (offset 3000ms) disagrees with process end by 1000ms. Capture ended mid-run.
* No exit CPU/RSS for `python3` for that reason.
* Trimmed report omits `root_exit_ms/session_end_reason/orphan_gap_ms/still_running`, so orphan status cannot be assessed.
* `marker_total` 3 = `markers.length` 3, so no downsampling.

---

## Session 300 — claude-code (`claude --project alpha`)

### 1. One-line summary
Ran a single `echo alpha` in `/work/alpha`, opened `/tmp/alpha.txt`, and made one HTTPS connect to `93.184.216.34:443`.

### 2. Timeline of phases
* **0–1000ms: agent alone.** `claude` pid 3000 runs 0–4000ms. No child until 1000ms.
* **1000–1500ms: child spawn.** `echo alpha` pid 3001 runs 1000–2000ms. `first_seen` at 1000ms pid 3000: `connect/execve/futex/mmap/read/write`.
* **1500–2000ms: file + child work.** `file_open /tmp/alpha.txt` at 1500ms pid 3000. `unlink first_seen` at 2000ms pid 3001.
* **2000–2500ms: network.** `net_connect tcp 93.184.216.34:443` at 2500ms pid 3000. `openat` first seen at 2000ms pid 3000.
* **2500–4000ms: agent tail.** 1500ms with no child, no further markers — probably waiting on model/user.

### 3. Where the time went
* `top_programs_by_wall_time`: `claude` 4000ms, `echo` 1000ms. Sum 5000ms > `duration_ms` 4000ms due to overlap.
* Overlap 1000–2000ms = 1000ms parallel. Exclusive agent time = 3000ms (4000-1000) = 75% of session; overlapped = 25%.
* CPU vs wall: `claude` 150+40 = 190ms vs 4000ms wall = 4.75% CPU. `echo` 1+1 = 2ms vs 1000ms wall = 0.2% CPU. Both overwhelmingly idle/blocked.
* RSS: `claude max_rss_kb` 61440 vs `echo` 2048 — 30x (61440/2048=30).
* Syscalls total 94: `mmap` 40 (42.55%) + `futex` 30 (31.91%) = 70/94 = 74.47% memory+sync background. `file` 21 (22.34%), `network` 2 (2.13%), `process` 1 (1.06%). Attribution: `claude` 91 (96.81%), `echo` 3 (3.19%).

### 4. Bottlenecks and waste
1. **1000ms wall for `echo alpha`.** 1000ms wall for 2ms CPU = 500x overhead. Spawning `/bin/echo` as a full process (`execve count 1`) for a trivial builtin is heavy-tool-for-light-job. Cost: 25% of session window (1000/4000).
2. **3000ms exclusive agent idle.** `claude` runs 3000ms with no child active and only one file open + one connect in markers. Low syscall share for file/network (22.0% + 2.2% of claude's 91) with 190ms CPU suggests waiting, not working.
3. **No repeat / re-read waste.** Verified: `find_repeated_commands: distinct_commands 2, repeated []`. `files_touched`: `/tmp/alpha.txt count 1` only. Single destination `93.184.216.34:443 count 1`.
4. **Possible duplicate `connect`.** `syscall_distribution: connect count 2` but `network_destinations count 1` and verification `network_activity total_connects 1`. Two `connect` syscalls collapsed to one marker/destination — could be retry or `socket`+`connect` accounting, but impact is negligible (2 syscalls).

### 5. Optimizations
* **Don't fork/exec for `echo`.** Use shell builtin or in-process logging. Expected saving: ~1000ms minus ~few ms fork cost, i.e. ~25% of session wall time, plus elimination of the `execve` + 3 file syscalls attributed to `echo`.
* **Treat the 2500–4000ms tail as likely model wait.** If the 2500ms `93.184.216.34:443` connect is a model call, avoid polling during the wait — the 30 `futex` + 40 `mmap` background syscalls do no useful work. No code change to recommend without payload visibility, but instrument time-to-first-token after that connect to confirm.

### 6. Notable behavior
* `notable_syscalls`: `connect count 2 first_seen 1000ms`, `execve count 1 first_seen 1000ms`, `unlink count 1 first_seen 2000ms pid 3001`.
* Network `tcp 93.184.216.34:443` at 2500ms pid 3000 with `dns_count 0` — direct IP:port HTTPS with no prior DNS in capture; consistent with (but not proof of) a likely model/API call. No hostname available.
* `unlink` attributed to `echo` pid 3001 has no corresponding marker or `files_touched` entry — target unknown.

### 7. Data gaps
* Unlink target missing: syscall says `unlink` occurred, but markers/files list only `/tmp/alpha.txt`. Cannot tell what was deleted.
* `connect` count mismatch: 2 in syscalls vs 1 in destinations/markers/tools. Cannot resolve retry vs counting without raw events.
* No TLS payload/hostname, so 443 destination cannot be identified as model vs other HTTPS.
* `marker_total` 2 = `markers.length` 2, so no downsampling; session fully captured (`open_ended false` for both processes).

---

## Cross-session comparison
* **Wall time:** 300 ran longer — 4000ms vs 400's 2500ms (+1500ms, 60% longer).
* **CPU:** 300 used far more known CPU — 190+2 = 192ms vs 400's 12ms known (+180ms). 400's root CPU is unknown (open-ended). RSS: 300's root 61440 KB vs 400's child 12288 KB (5x: 61440/12288=5).
* **Processes:** Tie — 2 processes each, 1 child each, strictly sequential (no parallel children). Both `exec_count` 1+1.
* **Network:** 400: 1x local DNS `127.0.0.1:53`; 300: 1x remote HTTPS `93.184.216.34:443`. Neither shows reuse failure; 300's remote 443 is the only candidate model call.
* **Same patterns:** Both show (a) single short child with ~0.2–0.7% CPU but 1000–1800ms wall time dominating the session, (b) agent root mostly idle (4.75% CPU where measured), (c) no repeated commands (both `repeated: []`), no multi-open files (all counts 1), (d) memory+sync syscalls as background noise (25%+13.9% in 400, 42.6%+31.9% in 300) — ignore for optimization.
* **Difference:** 400's waste is a slow `git status` + out-of-workdir `/tmp` delete; 300's waste is a trivial `echo` fork + unexplained `unlink` + long post-connect tail.
