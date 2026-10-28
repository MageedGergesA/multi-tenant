"""ctl-1 and the agent must agree on the catalog, the §8 timeouts and the
signed encoding; each side has its own copy."""
from nacl.signing import SigningKey

from ctlplane import canonical, catalog
from hostagent import canonical as agent_canonical
from hostagent import ops


def test_same_steps_for_every_operation():
    assert catalog.STEPS == {name: spec.steps for name, spec in ops.CATALOG.items()}
    assert set(catalog.NOT_EXCLUSIVE) == {n for n, s in ops.CATALOG.items() if not s.exclusive}


def test_same_agent_timeouts():
    assert catalog.AGENT_TIMEOUT == ops.STEP_TIMEOUTS
    assert catalog.DEFAULT_AGENT_TIMEOUT == ops.DEFAULT_STEP_TIMEOUT
    assert all(catalog.margin(step) > 0 for step in catalog.AGENT_TIMEOUT)


def test_same_signed_encoding():
    key = SigningKey.generate()
    obj = {'b': [1, 'ü', None], 'a': {'z': True, 'y': 2 ** 53 - 1}}
    assert canonical.canonical(obj) == agent_canonical.canonical(obj)
    assert agent_canonical.verify(obj, canonical.sign(obj, key), [key.verify_key])
    assert canonical.verify(obj, agent_canonical.sign(obj, key), key.verify_key)


def test_same_admission_rules():
    assert catalog.PARAMS == ops.PARAMS
    assert catalog.TENANT_STATES == {n: s.states for n, s in ops.CATALOG.items() if s.states is not None}
    assert set(catalog.CUSTODIAN) == {n for n, s in ops.CATALOG.items() if s.custodian}
    assert set(catalog.NEEDS_RELEASE) == {n for n, s in ops.CATALOG.items() if s.release}
    assert set(catalog.HOST_SCOPED) == {n for n, s in ops.CATALOG.items() if s.host_scoped}


def test_secret_steps_are_the_ones_that_open_secrets():
    import inspect
    from hostagent import steps
    opening = {step for (_, step), fn in steps.HANDLERS.items() if 'open_secrets(' in inspect.getsource(fn)}
    assert opening <= set(catalog.SECRET_STEPS)
