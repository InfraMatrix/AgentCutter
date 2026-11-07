"""Analysis credentials + model: discovered at run time, then chosen.

No test touches the network: agentcutter.agent.get_client is replaced by a
fake that records which service each key was sent to.
"""

from __future__ import annotations

import os
from types import SimpleNamespace

import pytest

from agentcutter import session
from agentcutter.cli import main

ANTH_KEY = "sk-ant-api03-SECRET-anth"
META_KEY = "LLM_SECRET_meta"
ODD_KEY = "zz-SECRET-unknown"


class FakeIO:
    def __init__(self, answers=(), tty=True, secret=""):
        self.answers = list(answers)
        self.tty = tty
        self._secret = secret

    def isatty(self):
        return self.tty

    def ask(self, prompt):
        if not self.answers:
            raise session.SessionError("no answer (end of input)")
        return self.answers.pop(0)

    def secret(self, prompt):
        return self._secret


class FakeService:
    """Stands in for every remote service; records (base_url, auth, key)."""

    def __init__(self):
        self.models = {"https://api.anthropic.com": ["claude-a", "claude-b"],
                       "https://api.meta.ai": ["muse-x"]}
        self.calls: list[tuple] = []
        self.fail_list: Exception | None = None

    def get_client(self, api_key=None, base_url="", auth="bearer"):
        self.calls.append((base_url, auth, api_key))

        def list_(**kw):
            if self.fail_list:
                raise self.fail_list
            return [SimpleNamespace(id=m) for m in self.models.get(base_url, [])]

        return SimpleNamespace(models=SimpleNamespace(list=list_),
                               messages=SimpleNamespace(create=lambda **kw: None),
                               base_url=base_url)


@pytest.fixture
def env(tmp_path, monkeypatch):
    for name in list(os.environ):
        if session.ENV_NAME_RE.match(name) or name.startswith("AGENTCUTTER_"):
            monkeypatch.delenv(name)
    creds = tmp_path / "creds"
    creds.mkdir()
    monkeypatch.setenv("AGENTCUTTER_CREDENTIALS_DIR", str(creds))
    monkeypatch.setenv("AGENTCUTTER_SESSION_FILE", str(tmp_path / "session"))
    svc = FakeService()
    monkeypatch.setattr("agentcutter.agent.get_client", svc.get_client)
    return SimpleNamespace(creds=creds, tmp=tmp_path, mp=monkeypatch, svc=svc)


def add_key(env, name, secret, *extra):
    f = env.creds / f"{name}.key"
    f.write_text("\n".join([secret, *extra]) + "\n")
    f.chmod(0o600)
    return f


def test_discovers_whatever_is_there_and_where_each_key_belongs(env):
    env.mp.setenv("SOME_VENDOR_API_KEY", ANTH_KEY)    # by key format
    env.mp.setenv("META_MODEL_API_KEY", "opaque-1")   # by name
    env.mp.setenv("MYSTERY_API_KEY", ODD_KEY)         # cannot tell
    env.mp.setenv("AGENT_API_KEY", ANTH_KEY)          # coding agent's: ignored
    env.mp.setenv("PATH_NOT_A_KEY", "x")
    add_key(env, "work", ODD_KEY, "provider=anthropic")
    add_key(env, "self", ODD_KEY, "base_url=https://llm.example.com", "auth=x-api-key")
    add_key(env, "junk", ODD_KEY)
    cands = {c.id: c for c in session.discover()}
    assert set(cands) == {"env:META_MODEL_API_KEY", "env:MYSTERY_API_KEY",
                          "env:SOME_VENDOR_API_KEY", "key:junk", "key:self", "key:work"}
    assert cands["env:SOME_VENDOR_API_KEY"].service.name == "anthropic"
    assert cands["env:META_MODEL_API_KEY"].service.name == "meta"
    assert cands["key:work"].service.name == "anthropic"
    assert cands["key:self"].service.base_url == "https://llm.example.com"
    assert cands["key:self"].service.auth == "x-api-key"
    assert cands["env:MYSTERY_API_KEY"].service is None
    assert cands["key:junk"].service is None and "cannot tell" in cands["key:junk"].why_unusable
    assert env.svc.calls == []  # discovery sends nothing anywhere


def test_listing_never_shows_keys(env):
    env.mp.setenv("ANTHROPIC_API_KEY", ANTH_KEY)
    add_key(env, "m", META_KEY)
    cands = session.discover()
    blob = repr(cands) + "\n".join(session.list_lines(cands)) + session.howto("x", cands)
    assert ANTH_KEY not in blob and META_KEY not in blob


def test_unusable_keys_are_never_sent_or_offered(env):
    env.mp.setenv("MYSTERY_API_KEY", ODD_KEY)
    env.mp.setenv("ANTHROPIC_API_KEY", ANTH_KEY)
    c = session.choose("run", session.discover(), io=FakeIO(answers=["1"]))
    assert c.cred.id == "env:ANTHROPIC_API_KEY"  # the only usable one
    assert all(call[2] != ODD_KEY for call in env.svc.calls)
    with pytest.raises(session.SessionError, match="not usable"):
        session.choose("run", session.discover(), auth="env:MYSTERY_API_KEY", io=FakeIO(tty=False))


def test_key_goes_only_to_its_own_service(env):
    env.mp.setenv("ANTHROPIC_API_KEY", ANTH_KEY)
    env.mp.setenv("META_MODEL_API_KEY", META_KEY)
    session.choose("run", session.discover(), auth="env:META_MODEL_API_KEY",
                   io=FakeIO(tty=False))
    session.choose("run", session.discover(), auth="env:ANTHROPIC_API_KEY",
                   model="claude-a", io=FakeIO(tty=False))
    assert ("https://api.meta.ai", "bearer", META_KEY) in env.svc.calls
    assert ("https://api.anthropic.com", "x-api-key", ANTH_KEY) in env.svc.calls
    for base, _, key in env.svc.calls:
        assert (key == META_KEY) == (base == "https://api.meta.ai")


def test_models_come_from_the_service(env):
    env.mp.setenv("ANTHROPIC_API_KEY", ANTH_KEY)
    c = session.choose("run", session.discover(), io=FakeIO(answers=["2"]))
    assert (c.model, c.model_from) == ("claude-b", "chosen just now")
    env.mp.setenv("META_MODEL_API_KEY", META_KEY)
    c = session.choose("run", session.discover(), auth="env:META_MODEL_API_KEY", io=FakeIO(tty=False))
    assert (c.model, c.model_from) == ("muse-x", "the only model meta offers")


def test_model_not_offered_is_refused(env):
    env.mp.setenv("ANTHROPIC_API_KEY", ANTH_KEY)
    with pytest.raises(session.SessionError, match="not offered by anthropic.*claude-a, claude-b"):
        session.choose("run", session.discover(), model="muse-x", io=FakeIO(tty=False))


def test_service_that_cannot_list_models_asks_for_an_id(env):
    env.mp.setenv("ANTHROPIC_API_KEY", ANTH_KEY)
    env.svc.fail_list = RuntimeError("no /v1/models here")
    c = session.choose("run", session.discover(), io=FakeIO(answers=["claude-z"]))
    assert c.model == "claude-z"
    c = session.choose("run", session.discover(), model="claude-q", io=FakeIO(tty=False))
    assert c.model == "claude-q" and "could not list models" in c.model_from
    with pytest.raises(session.SessionError, match="could not list its models"):
        session.choose("run", session.discover(), io=FakeIO(tty=False))


def test_precedence_flag_env_saved(env):
    env.mp.setenv("ANTHROPIC_API_KEY", ANTH_KEY)
    add_key(env, "meta1", META_KEY)
    (env.tmp / "session").write_text("auth=key:meta1\nmodel=muse-x\n")
    cands = session.discover()
    io = FakeIO(tty=False)
    c = session.choose("run", cands, io=io)
    assert (c.cred.id, c.model) == ("key:meta1", "muse-x")
    env.mp.setenv("AGENTCUTTER_AUTH", "env:ANTHROPIC_API_KEY")
    env.mp.setenv("AGENTCUTTER_MODEL", "claude-b")
    c = session.choose("run", cands, io=io)
    assert (c.cred.id, c.model, c.cred_from) == ("env:ANTHROPIC_API_KEY", "claude-b", "AGENTCUTTER_AUTH")
    c = session.choose("run", cands, auth="key:meta1", model="muse-x", io=io)
    assert (c.cred.id, c.cred_from, c.model_from) == ("key:meta1", "--auth", "--model")


def test_stale_saved_choice_falls_back(env, capsys):
    env.mp.setenv("ANTHROPIC_API_KEY", ANTH_KEY)
    (env.tmp / "session").write_text("auth=key:gone\nmodel=old\n")
    c = session.choose("run", session.discover(), io=FakeIO(answers=["1"]))
    assert (c.cred.id, c.model) == ("env:ANTHROPIC_API_KEY", "claude-a")
    assert "not available any more" in capsys.readouterr().err
    (env.tmp / "session").write_text("auth=env:ANTHROPIC_API_KEY\nmodel=retired\n")
    c = session.choose("run", session.discover(), io=FakeIO(answers=["2"]))
    assert c.model == "claude-b"
    assert "not offered by anthropic any more" in capsys.readouterr().err


def test_menus_and_typed_key(env):
    env.mp.setenv("ANTHROPIC_API_KEY", ANTH_KEY)
    env.mp.setenv("META_MODEL_API_KEY", META_KEY)
    c = session.choose("run", session.discover(), io=FakeIO(answers=["2", "1"]))
    assert (c.cred.id, c.model) == ("env:META_MODEL_API_KEY", "muse-x")
    # typed key of unknown format: asked which service, then models from it
    io = FakeIO(answers=["3", "1", "2"], secret=ODD_KEY)
    c = session.choose("run", session.discover(), io=io)
    assert (c.cred.id, c.service.name, c.model, c.key) == ("prompt", "anthropic", "claude-b", ODD_KEY)
    with pytest.raises(session.SessionError, match="cannot be saved"):
        session.save(c)


def test_nothing_usable_or_no_terminal(env):
    with pytest.raises(session.SessionError, match="no usable"):
        session.choose("run", session.discover(), io=FakeIO(tty=False))
    env.mp.setenv("ANTHROPIC_API_KEY", ANTH_KEY)
    env.mp.setenv("META_MODEL_API_KEY", META_KEY)
    with pytest.raises(session.SessionError) as ei:
        session.choose("run", session.discover(), io=FakeIO(tty=False))
    assert "AGENTCUTTER_AUTH" in str(ei.value) and "agentcutter session pick" in ei.value.howto


def test_confirm_yes_no_and_no_terminal(env, capsys):
    env.mp.setenv("META_MODEL_API_KEY", META_KEY)
    c = session.choose("run", session.discover(), io=FakeIO(tty=False))
    session.confirm(c, "R", io=FakeIO(answers=["y"]))
    with pytest.raises(session.SessionError) as ei:
        session.confirm(c, "R", io=FakeIO(answers=["n"]))
    assert "Not running" in str(ei.value)
    assert "AGENTCUTTER_AUTH=<id> R" in ei.value.howto and "provider=" in ei.value.howto
    with pytest.raises(session.SessionError, match="no terminal"):
        session.confirm(c, "R", io=FakeIO(answers=["y"], tty=False))
    session.confirm(c, "R", yes=True, io=FakeIO(tty=False))
    err = capsys.readouterr().err
    assert "https://api.meta.ai/v1/messages" in err and META_KEY not in err


def test_save_writes_ids_only_mode_600(env):
    add_key(env, "work", ANTH_KEY)
    c = session.choose("pick", session.discover(), io=FakeIO(answers=["1", "2"]))
    path = session.save(c)
    assert path.read_text() == "auth=key:work\nmodel=claude-b\n"
    assert (path.stat().st_mode & 0o777) == 0o600


def test_describe_api_error():
    class AuthenticationError(Exception):
        status_code = 401

    assert "401" in session.describe_api_error(AuthenticationError())
    assert "404" in session.describe_api_error(SimpleNamespace(status_code=404))
    assert session.describe_api_error(ValueError()) is None


def test_analyze_asks_before_any_work(env, monkeypatch, capsys):
    env.mp.setenv("ANTHROPIC_API_KEY", ANTH_KEY)
    monkeypatch.setattr(session, "_IO", lambda: FakeIO(answers=["1", "n"]))
    import agentcutter.cli as cli

    monkeypatch.setattr(cli, "build_report", lambda *a, **k: pytest.fail("built report"))
    assert main(["analyze", "x.jsonl"]) == 1
    err = capsys.readouterr().err
    assert "Not running the analysis." in err
    assert "AGENTCUTTER_AUTH=<id> agentcutter analyze x.jsonl" in err
    assert ANTH_KEY not in err


def test_analyze_uses_chosen_service_key_and_model(env, monkeypatch, tmp_path):
    env.mp.setenv("ANTHROPIC_API_KEY", ANTH_KEY)
    import agentcutter.agent as agent_mod
    import agentcutter.cli as cli

    seen = {}
    monkeypatch.setattr(cli, "build_report", lambda *a, **k: ({"sessions": []}, tmp_path / "r.json"))
    monkeypatch.setattr(cli, "load_system_prompt", lambda p: "sys")

    def fake_run(report, system, capture, **kw):
        seen.update(base=kw["client"].base_url, model=kw["model"])
        return "analysis"

    monkeypatch.setattr(agent_mod, "run_analysis", fake_run)
    rc = main(["analyze", "x.jsonl", "--yes", "--model", "claude-b",
               "--output", str(tmp_path / "out.md")])
    assert rc == 0
    assert seen == {"base": "https://api.anthropic.com", "model": "claude-b"}
    assert env.svc.calls[-1] == ("https://api.anthropic.com", "x-api-key", ANTH_KEY)


def test_analyze_rejected_key_explains(env, monkeypatch, tmp_path, capsys):
    env.mp.setenv("META_MODEL_API_KEY", META_KEY)
    import agentcutter.agent as agent_mod
    import agentcutter.cli as cli

    class AuthenticationError(Exception):
        status_code = 401

    def boom(*a, **k):
        raise AuthenticationError("bad key")

    monkeypatch.setattr(cli, "build_report", lambda *a, **k: ({"sessions": []}, tmp_path / "r.json"))
    monkeypatch.setattr(cli, "load_system_prompt", lambda p: "sys")
    monkeypatch.setattr(agent_mod, "run_analysis", boom)
    assert main(["analyze", "x.jsonl", "--yes", "--output", str(tmp_path / "o.md")]) == 1
    err = capsys.readouterr().err
    assert "rejected the key (401)" in err and "agentcutter session pick" in err


def test_session_confirm_exit_codes(env, monkeypatch, capsys):
    monkeypatch.setattr(session, "_IO", lambda: FakeIO(tty=False))
    env.mp.setenv("MYSTERY_API_KEY", ODD_KEY)  # present but unusable
    assert main(["session", "confirm"]) == 3   # -> caller does a dry run
    assert "no usable analysis credentials" in capsys.readouterr().err
    env.mp.setenv("ANTHROPIC_API_KEY", ANTH_KEY)
    env.mp.setenv("AGENTCUTTER_CONFIRM", "1")
    assert main(["session", "confirm", "--model", "claude-a"]) == 0
    assert capsys.readouterr().out == "AGENTCUTTER_AUTH=env:ANTHROPIC_API_KEY\nAGENTCUTTER_MODEL=claude-a\n"
