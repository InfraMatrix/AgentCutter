"""Choose the credentials and model for AgentCutter's analysis step.

Nothing is assumed about which service, key or model you have. At run time
AgentCutter looks at what is available, asks each key's own service which
models it offers, and lets you choose.

Analysis credentials are kept apart from AgentLoupe's coding-agent
credentials: AGENT_* variables (the agent being observed) are never used here.

What is discovered (each candidate has an id):

  env:<NAME>      any environment variable ending in _API_KEY or _AUTH_TOKEN
                  (except AGENT_*)
  key:<name>      <dir>/<name>.key files you create (mode 600); <dir> =
                  AGENTCUTTER_CREDENTIALS_DIR, default
                  ~/.config/agentcutter/model-credentials
  file:<path>     --api-key-file PATH (or AGENTCUTTER_API_KEY_FILE), one run
  prompt          a key typed in at the menu (hidden; one run, never saved)

Which service a key belongs to is worked out from the key's format, else its
variable/file name; a key file can also say so explicitly:

  <the key>               first line
  provider=anthropic      or: base_url=https://...  and  auth=bearer|x-api-key

A key is only ever sent to its own service. Keys whose service cannot be
told are listed as unusable with how to fix that; they are never tried
against other services.

Models: once credentials are chosen, the list comes from that service's
GET /v1/models. If the service cannot list them, you type a model id.

Which choice wins (credentials / model):
  1. --auth ID / --model M, else AGENTCUTTER_AUTH / AGENTCUTTER_MODEL
     (--api-key-file also counts as choosing credentials)
  2. the choice saved by `agentcutter session pick`
     (AGENTCUTTER_SESSION_FILE, default ~/.config/agentcutter/session:
     ids only, never a key), if still available
  3. the only option, else a menu
Then it always asks whether the choice is right before the analysis runs;
answering no prints how to set the ones you want. Without a terminal it
needs --yes or AGENTCUTTER_CONFIRM=1.

Keys are never printed (not even in part), never written to a file by
AgentCutter, and never put on a command line.
"""

from __future__ import annotations

import getpass
import os
import re
import stat
import sys
from dataclasses import dataclass, field
from pathlib import Path

MODEL_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:@/-]*$")
ENV_NAME_RE = re.compile(r"^[A-Z][A-Z0-9_]*_(API_KEY|AUTH_TOKEN)$")


class SessionError(Exception):
    """Stop before the analysis. `howto` is shown after the message."""

    def __init__(self, msg: str, howto: str = ""):
        super().__init__(msg)
        self.howto = howto


@dataclass(frozen=True)
class Service:
    name: str
    base_url: str
    auth: str  # "x-api-key" or "bearer"

    @property
    def endpoint(self) -> str:
        return self.base_url.rstrip("/") + "/v1/messages"


# Services that speak the Messages API AgentCutter uses. Only used to work
# out where a key belongs, never to pick one for you.
SERVICES = {
    "anthropic": Service("anthropic", "https://api.anthropic.com", "x-api-key"),
    "meta": Service("meta", "https://api.meta.ai", "bearer"),
}
# Key formats, then words in a variable/file name.
KEY_PREFIXES = [("sk-ant-", "anthropic"), ("LLM_", "meta")]
NAME_WORDS = [("ANTHROPIC", "anthropic"), ("CLAUDE", "anthropic"), ("META", "meta"),
              ("MUSE", "meta"), ("LLAMA", "meta")]


@dataclass
class Candidate:
    id: str
    label: str
    source: str               # "env:<NAME>", "prompt", or a file path
    service: Service | None   # None: cannot tell where this key belongs
    why_unusable: str = ""


@dataclass
class Choice:
    cred: Candidate
    cred_from: str
    model: str
    model_from: str
    key: str = field(default="", repr=False)

    @property
    def service(self) -> Service:
        assert self.cred.service is not None
        return self.cred.service


def credentials_dir() -> Path:
    return Path(
        os.environ.get("AGENTCUTTER_CREDENTIALS_DIR")
        or "~/.config/agentcutter/model-credentials"
    ).expanduser()


def session_file() -> Path:
    return Path(
        os.environ.get("AGENTCUTTER_SESSION_FILE") or "~/.config/agentcutter/session"
    ).expanduser()


def _err(msg: str) -> None:
    print(f"agentcutter: {msg}", file=sys.stderr)


def _warn_perms(path: Path) -> None:
    try:
        mode = stat.S_IMODE(path.stat().st_mode)
    except OSError:
        return
    if mode & 0o077:
        _err(f"WARNING: {path} is mode {mode:o} (should be 600)")


def _service_for(key: str, name: str) -> Service | None:
    for prefix, svc in KEY_PREFIXES:
        if key.startswith(prefix):
            return SERVICES[svc]
    upper = name.upper()
    for word, svc in NAME_WORDS:
        if word in upper:
            return SERVICES[svc]
    return None


def _parse_key_file(path: Path) -> tuple[str, dict[str, str]]:
    """First line is the key; later key=value lines are settings."""
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError as exc:
        raise SessionError(f"cannot read {path}: {exc.strerror}") from None
    key = lines[0].strip() if lines else ""
    if not key:
        raise SessionError(f"{path} is empty")
    opts = {}
    for line in lines[1:]:
        k, sep, v = line.partition("=")
        if sep:
            opts[k.strip().lower()] = v.strip()
    return key, opts


def _file_service(key: str, opts: dict[str, str], name: str) -> tuple[Service | None, str]:
    if "provider" in opts:
        svc = SERVICES.get(opts["provider"].lower())
        if svc is None:
            return None, f"unknown provider={opts['provider']} (known: {', '.join(SERVICES)})"
        return svc, ""
    if "base_url" in opts:
        auth = opts.get("auth", "bearer").lower()
        if auth not in ("bearer", "x-api-key"):
            return None, f"auth={auth} (use bearer or x-api-key)"
        if not opts["base_url"].startswith("https://"):
            return None, "base_url must be https://"
        return Service(opts["base_url"], opts["base_url"], auth), ""
    svc = _service_for(key, name)
    return svc, "" if svc else "cannot tell which service this key is for"


def _key_file(api_key_file: Path | None) -> Path | None:
    """--api-key-file, else AGENTCUTTER_API_KEY_FILE."""
    if api_key_file is None and os.environ.get("AGENTCUTTER_API_KEY_FILE"):
        return Path(os.environ["AGENTCUTTER_API_KEY_FILE"])
    return api_key_file


def _file_candidate(cid: str, path: Path, label: str) -> Candidate:
    _warn_perms(path)
    try:
        key, opts = _parse_key_file(path)
    except SessionError as exc:
        return Candidate(cid, label, str(path), None, str(exc))
    svc, why = _file_service(key, opts, path.stem)
    return Candidate(cid, label, str(path), svc, why)


def discover(api_key_file: Path | None = None) -> list[Candidate]:
    """Everything available, usable or not (unusable ones say why)."""
    cands: list[Candidate] = []
    for name in sorted(os.environ):
        if not ENV_NAME_RE.match(name) or name.startswith("AGENT_") or not os.environ[name]:
            continue
        svc = _service_for(os.environ[name], name)
        cands.append(Candidate(
            f"env:{name}", f"environment variable {name}", f"env:{name}", svc,
            "" if svc else "cannot tell which service this key is for"))
    d = credentials_dir()
    if d.is_dir():
        for f in sorted(d.glob("*.key")):
            cands.append(_file_candidate(f"key:{f.stem}", f, f"key file {f}"))
    api_key_file = _key_file(api_key_file)
    if api_key_file is not None:
        p = Path(api_key_file).expanduser()
        cands.append(_file_candidate(f"file:{p}", p, f"key file {p} (--api-key-file)"))
    return cands


def usable(cands: list[Candidate]) -> list[Candidate]:
    return [c for c in cands if c.service is not None]


def load_saved() -> tuple[str, str]:
    auth = model = ""
    try:
        text = session_file().read_text(encoding="utf-8")
    except OSError:
        return auth, model
    for line in text.splitlines():
        k, _, v = line.partition("=")
        if k == "auth":
            auth = v.strip()
        elif k == "model":
            model = v.strip()
    return auth, model


def save(choice: Choice) -> Path:
    if choice.cred.id == "prompt":
        raise SessionError("a typed-in key cannot be saved; add it as a key file", howto(""))
    path = session_file()
    path.parent.mkdir(parents=True, exist_ok=True)
    old = os.umask(0o077)
    try:
        path.write_text(f"auth={choice.cred.id}\nmodel={choice.model}\n", encoding="utf-8")
    finally:
        os.umask(old)
    return path


def _key_for(c: Candidate) -> str:
    if c.source.startswith("env:"):
        key = os.environ.get(c.source[4:], "")
        if not key:
            raise SessionError(f"{c.source[4:]} is empty")
        return key
    return _parse_key_file(Path(c.source))[0]


def client_for(service: Service, key: str):
    from agentcutter.agent import get_client

    return get_client(key, base_url=service.base_url, auth=service.auth)


def list_models(service: Service, key: str) -> tuple[list[str] | None, str]:
    """Ask the key's own service which models it offers.
    Returns (ids, "") or (None, reason)."""
    try:
        page = client_for(service, key).models.list(limit=100)
        ids = []
        for m in page:  # the SDK pages through the rest
            mid = getattr(m, "id", None)
            if mid and mid not in ids:
                ids.append(mid)
    except Exception as exc:  # any failure: fall back to typing an id
        why = describe_api_error(exc) or f"{type(exc).__name__}: {str(exc)[:120]}"
        return None, why
    if not ids:
        return None, "the service returned no models"
    return ids, ""


class _IO:
    """Terminal I/O; prompts go to stderr so stdout can be captured."""

    def isatty(self) -> bool:
        return sys.stdin.isatty()

    def ask(self, prompt: str) -> str:
        sys.stderr.write(prompt)
        sys.stderr.flush()
        line = sys.stdin.readline()
        if not line:
            raise SessionError("no answer (end of input)")
        return line.strip()

    def secret(self, prompt: str) -> str:
        return getpass.getpass(prompt, stream=sys.stderr)


def _cred_line(i: int | None, c: Candidate) -> str:
    where = f"-> {c.service.name}" if c.service else f"(unusable: {c.why_unusable})"
    num = f"{i:2d})" if i is not None else "  -"
    return f"  {num} {c.id:30} {c.label} {where}"


def list_lines(cands: list[Candidate]) -> list[str]:
    if not cands:
        return ["    (none found)"]
    ok = usable(cands)
    lines = [_cred_line(i, c) for i, c in enumerate(ok, 1)]
    lines += [_cred_line(None, c) for c in cands if c.service is None]
    return lines


def _choose_number(io: _IO, prompt: str, top: int) -> int:
    while True:
        a = io.ask(prompt)
        if a.isdigit() and 1 <= int(a) <= top:
            return int(a)


def _menu_creds(cands: list[Candidate], io: _IO, allow_typed: bool) -> tuple[Candidate, str]:
    ok = usable(cands)
    lines = ["Which credentials should AgentCutter's analysis use?"] + list_lines(cands)
    top = len(ok)
    if allow_typed:
        top += 1
        lines.append(f"  {top:2d}) {'(type a key)':30} enter a key now (this run only)")
    if top == 0:
        raise SessionError("no usable analysis credentials found", howto("", cands))
    print("\n".join(lines), file=sys.stderr)
    n = _choose_number(io, f"Choose [1-{top}]: ", top)
    if n <= len(ok):
        return ok[n - 1], ""
    key = io.secret("API key: ").strip()
    if not key:
        raise SessionError("no key entered")
    svc = _service_for(key, "")
    if svc is None:
        names = list(SERVICES)
        print("Which service is this key for?", file=sys.stderr)
        for i, s in enumerate(names, 1):
            print(f"  {i:2d}) {s}  ({SERVICES[s].base_url})", file=sys.stderr)
        svc = SERVICES[names[_choose_number(io, f"Choose [1-{len(names)}]: ", len(names)) - 1]]
    return Candidate("prompt", "typed in (this run only)", "prompt", svc), key


def _menu_models(models: list[str] | None, why: str, service: Service, io: _IO) -> str:
    if models is None:
        print(f"{service.name} could not list its models ({why}).", file=sys.stderr)
        m = io.ask("Model id: ")
        if not m:
            raise SessionError("no model entered")
        return m
    print(f"Models available from {service.name}:", file=sys.stderr)
    for i, m in enumerate(models, 1):
        print(f"  {i:2d}) {m}", file=sys.stderr)
    other = len(models) + 1
    print(f"  {other:2d}) (type a model id)", file=sys.stderr)
    n = _choose_number(io, f"Choose [1-{other}]: ", other)
    return models[n - 1] if n <= len(models) else io.ask("Model id: ")


def choose(
    mode: str,
    cands: list[Candidate],
    *,
    auth: str | None = None,
    model: str | None = None,
    api_key_file: Path | None = None,
    rerun: str = "agentcutter analyze CAPTURE",
    io: _IO | None = None,
) -> Choice:
    """mode "run": flags/env > saved > only option > menu.
    mode "pick": always the menus (for saving)."""
    io = io or _IO()
    api_key_file = _key_file(api_key_file)
    saved_auth, saved_model = load_saved()
    ok = usable(cands)
    by_id = {c.id: c for c in cands}

    # --- credentials
    want, want_from = "", ""
    if mode == "run":
        if auth:
            want, want_from = auth, "--auth"
        elif os.environ.get("AGENTCUTTER_AUTH"):
            want, want_from = os.environ["AGENTCUTTER_AUTH"], "AGENTCUTTER_AUTH"
        elif api_key_file is not None:
            want, want_from = f"file:{Path(api_key_file).expanduser()}", "--api-key-file"
        elif saved_auth:
            if saved_auth in by_id and by_id[saved_auth].service:
                want, want_from = saved_auth, f"saved in {session_file()}"
            else:
                _err(f"the saved credentials '{saved_auth}' are not available any more; choose again")
                saved_model = ""

    key = ""
    if want:
        c = by_id.get(want)
        if c is None:
            raise SessionError(f"{want_from}={want} is not available", howto(rerun, cands))
        if c.service is None:
            raise SessionError(f"{want} is not usable: {c.why_unusable}", howto(rerun, cands))
        cred, cred_from = c, want_from
    elif mode == "run" and len(ok) == 1:
        cred, cred_from = ok[0], "the only usable credentials"
    elif io.isatty():
        cred, key = _menu_creds(cands, io, allow_typed=(mode == "run"))
        cred_from = "chosen just now"
    elif not ok:
        raise SessionError("no usable analysis credentials found", howto(rerun, cands))
    else:
        raise SessionError(
            "several usable analysis credentials and no terminal to ask; set "
            f"AGENTCUTTER_AUTH to one of: {', '.join(c.id for c in ok)}",
            howto(rerun, cands),
        )
    key = key or _key_for(cred)
    svc = cred.service
    assert svc is not None

    # --- model: from what this service offers
    models, why = list_models(svc, key)
    m, m_from = "", ""
    if mode == "run":
        if model:
            m, m_from = model, "--model"
        elif os.environ.get("AGENTCUTTER_MODEL"):
            m, m_from = os.environ["AGENTCUTTER_MODEL"], "AGENTCUTTER_MODEL"
        elif saved_model:
            if models is None or saved_model in models:
                m, m_from = saved_model, f"saved in {session_file()}"
            else:
                _err(f"the saved model '{saved_model}' is not offered by {svc.name} any more; choose again")
        if m and m_from != f"saved in {session_file()}" and models is not None and m not in models:
            raise SessionError(
                f"{m_from}={m} is not offered by {svc.name} with {cred.id} "
                f"(offered: {', '.join(models)})", howto(rerun, cands))
    if not m:
        if mode == "run" and models is not None and len(models) == 1:
            m, m_from = models[0], f"the only model {svc.name} offers"
        elif io.isatty():
            m, m_from = _menu_models(models, why, svc, io), "chosen just now"
        elif models is None:
            raise SessionError(
                f"{svc.name} could not list its models ({why}) and there is no "
                "terminal to ask; set AGENTCUTTER_MODEL", howto(rerun, cands))
        else:
            raise SessionError(
                "no terminal to choose a model; set AGENTCUTTER_MODEL to one of: "
                + ", ".join(models), howto(rerun, cands))
    if not MODEL_RE.match(m):
        raise SessionError(f"not a model id: {m!r}")
    if models is None and m_from != "chosen just now":
        m_from += f"; {svc.name} could not list models to check it"
    return Choice(cred, cred_from, m, m_from, key=key)


def howto(rerun: str, cands: list[Candidate] | None = None) -> str:
    rerun = rerun or "agentcutter analyze CAPTURE"
    d = str(credentials_dir()).replace(str(Path.home()), "~", 1)
    if cands is None:
        cands = discover()
    found = "\n".join(list_lines(cands))
    return f"""
To run the analysis with the credentials you want:

  Analysis credentials found:
{found}

  Use one of them for this run:   AGENTCUTTER_AUTH=<id> {rerun}   (or --auth <id>)
  Save one as the default:        agentcutter session pick
  A key file for this run:        AGENTCUTTER_API_KEY_FILE=/path/to/key {rerun}

  Add a key, then it appears in the list above:
    install -D -m 600 /path/to/key {d}/<name>.key   -> key:<name>
  If it shows as unusable, say which service it is for by adding a line to
  that file:  provider=<{'|'.join(SERVICES)}>   or   base_url=https://...  (+ auth=bearer|x-api-key)

  Different model:                AGENTCUTTER_MODEL=<id> {rerun}   (or --model <id>)
  See credentials and models:     agentcutter session show
  Test a key + model (1 token):   agentcutter session check
  No key at all:                  agentcutter analyze CAPTURE --dry-run   (no API call)
"""


def confirm(choice: Choice, rerun: str, *, yes: bool = False, io: _IO | None = None) -> None:
    io = io or _IO()
    print(
        "\nAgentCutter's analysis will call:\n"
        f"  endpoint     {choice.service.endpoint}\n"
        f"  credentials  {choice.cred.id}: {choice.cred.label}\n"
        f"               ({choice.cred_from})\n"
        f"  model        {choice.model}   ({choice.model_from})",
        file=sys.stderr,
    )
    if yes or os.environ.get("AGENTCUTTER_CONFIRM") == "1":
        print("  (confirmed by --yes / AGENTCUTTER_CONFIRM=1)", file=sys.stderr)
        return
    if not io.isatty():
        raise SessionError(
            "no terminal to ask whether these are right; run from a terminal, "
            "or pass --yes / set AGENTCUTTER_CONFIRM=1",
            howto(rerun),
        )
    a = io.ask("Are these the right credentials and model? [y/N] ")
    if a.lower() not in ("y", "yes"):
        raise SessionError("Not running the analysis.", howto(rerun))


def check(choice: Choice) -> str:
    """One 1-token request: does this key work with this model?"""
    client_for(choice.service, choice.key).messages.create(
        model=choice.model, max_tokens=1, messages=[{"role": "user", "content": "ping"}]
    )
    return "ok"


def describe_api_error(exc: Exception) -> str | None:
    """Plain-language reason for an API failure that is about credentials or
    the model, or None for anything else."""
    name = type(exc).__name__
    status = getattr(exc, "status_code", None)
    if name == "AuthenticationError" or status == 401:
        return "the API rejected the key (401): it is wrong, inactive, or revoked"
    if name == "PermissionDeniedError" or status == 403:
        return "the key is not allowed to use this model or endpoint (403)"
    if name == "NotFoundError" or status == 404:
        return "not found (404): the model id, or this endpoint"
    return None
