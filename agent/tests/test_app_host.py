"""The app host's configuration and firewall as the infra roles set them up (infra/ansible)."""
import base64

from nacl.signing import SigningKey

from hostagent import config
from hostagent.backends import AppHostConfig, DockerApp

SID = 'feedfacecafe'


def _key():
    return base64.b64encode(bytes(SigningKey.generate().verify_key)).decode()


def test_agentd_reads_the_remap_base(tmp_path):
    """The agent derives tenant host uids from it (base + uid); unread, every tenant was 10001-range on disk."""
    k = _key()
    path = tmp_path / 'agent.toml'
    path.write_text('host_id = "h"\nrole = "app"\nstate_dir = "%s"\nregistry_host = "r"\nctl_url = "https://x"\n'
                    'ctl_ca = "/c"\ntls_cert = "/t"\ntls_key = "/k"\nsubuid_base = 100000\n'
                    '[trust]\ndispatch = ["%s"]\nrelease = "%s"\ncustodian = ["%s"]\n' % (tmp_path, k, k, k))
    assert config.load(path).subuid_base == 100000


def test_a_tenant_table_is_replaced_in_one_transaction():
    text = DockerApp(AppHostConfig(nft_mode='dryrun'), client=object()).ruleset(SID, 'production')
    lines = [l for l in text.splitlines() if not l.startswith('#')]
    assert lines[:3] == ['table inet tenant_%s' % SID, 'delete table inet tenant_%s' % SID,
                         'table inet tenant_%s {' % SID]


def test_inspect_reads_the_kernel_not_the_file(tmp_path, monkeypatch):
    app = DockerApp(AppHostConfig(root=tmp_path), client=object())
    f = app._nft_file(SID)
    f.parent.mkdir(parents=True)
    f.write_text(app.ruleset(SID, 'production'))
    monkeypatch.setattr(app, '_nft_loaded', lambda sid: None)          # after a reboot without the include
    assert app.nft_inspect(SID)['applied'] is False
    monkeypatch.setattr(app, '_nft_loaded', lambda sid: 'table inet tenant_%s { iifname "br-%s" drop }' % (sid, sid))
    assert app.nft_inspect(SID)['applied'] is True
