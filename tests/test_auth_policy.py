"""Group name normalisation and group -> role resolution."""
import pytest

from auth import store
from auth.policy import group_form, group_matches, resolve_role

ADMINS_DN = "CN=VPN-Admins,OU=Groups,DC=corp,DC=example,DC=com"


def P(group, role, priority=100, provider="any"):
    return {"provider": provider, "group_name": group, "role": role, "priority": priority}


@pytest.mark.parametrize(
    "value, kind",
    [
        ("CN=VPN-Admins,OU=Groups,DC=corp,DC=local", "dn"),
        ("/corp/vpn-admins", "path"),
        ("vpn-admins", "name"),
        ("CORP\\VPN-Admins", "domain"),
    ],
)
def test_every_form_has_the_same_short_name(value, kind):
    form = group_form(value)
    assert form.kind == kind and form.name == "vpn-admins"


def test_dn_policy_matches_cn_only_group_and_vice_versa():
    policies = [P("CN=VPN-Users,OU=Groups,DC=corp,DC=local", "user")]
    assert resolve_role("ldap", ["VPN-Users"], policies) == "user"
    assert resolve_role("oidc", ["CN=VPN-Users,OU=Groups,DC=corp,DC=local"], [P("vpn-users", "user")]) == "user"


@pytest.mark.parametrize(
    "policy, group",
    [
        # same CN in another OU (a branch admin can create it)
        (ADMINS_DN, "CN=VPN-Admins,OU=Branch-Kazan,DC=corp,DC=example,DC=com"),
        # same last segment in another Keycloak subtree
        ("/corp/vpn-admins", "/partners/acme/vpn-admins"),
        # same name in a trusted domain
        ("CORP\\VPN-Admins", "PARTNER\\VPN-Admins"),
        # qualified values of different kinds never fall back to the short name
        (ADMINS_DN, "PARTNER\\VPN-Admins"),
        ("/corp/vpn-admins", ADMINS_DN),
    ],
)
def test_qualified_policy_does_not_match_a_same_named_group_elsewhere(policy, group):
    assert resolve_role("ldap", [group], [P(policy, "admin")]) is None


@pytest.mark.parametrize(
    "policy, group",
    [
        (ADMINS_DN, "cn=vpn-admins, ou=groups ,dc=CORP,dc=example,dc=com"),
        ("CN=VPN\\, Admins,OU=Groups,DC=corp", "cn=VPN\\2C admins,ou=groups,dc=corp"),
        ("CN=Группа VPN,OU=Группы,DC=corp", "cn=группа vpn,ou=группы,dc=corp"),
        ("/corp/vpn-admins", "/Corp/VPN-Admins/"),
        ("CORP\\VPN-Admins", "corp\\vpn-admins"),
    ],
)
def test_qualified_policy_matches_the_same_group_written_differently(policy, group):
    assert group_matches(policy, group)


def test_bare_policy_matches_that_name_anywhere():
    # documented: a bare name is "any OU / any subtree / any domain"
    for group in (ADMINS_DN, "CN=VPN-Admins,OU=Branch,DC=corp", "/partners/vpn-admins", "PARTNER\\VPN-Admins"):
        assert resolve_role("ldap", [group], [P("VPN-Admins", "admin")]) == "admin"


def test_no_match_returns_none():
    assert resolve_role("ldap", ["Accounting"], [P("VPN-Users", "user")]) is None
    assert resolve_role("ldap", [], [P("VPN-Users", "user")]) is None


def test_lower_priority_number_wins_then_higher_role():
    groups = ["VPN-Users", "VPN-Admins"]
    assert resolve_role("ldap", groups, [P("VPN-Users", "user", 10), P("VPN-Admins", "admin", 20)]) == "user"
    assert resolve_role("ldap", groups, [P("VPN-Users", "user", 10), P("VPN-Admins", "admin", 10)]) == "admin"


def test_provider_scoped_policy_only_applies_to_that_provider():
    policies = [P("vpn-admins", "admin", provider="oidc")]
    assert resolve_role("oidc", ["vpn-admins"], policies) == "admin"
    assert resolve_role("ldap", ["vpn-admins"], policies) is None


def test_group_name_is_not_a_substring_match():
    assert resolve_role("ldap", ["VPN-Admins-Old"], [P("VPN-Admins", "admin")]) is None


def test_seed_policies_only_when_empty(monkeypatch):
    import config

    monkeypatch.setattr(config, "AUTH_ADMIN_GROUPS", "VPN-Admins")
    monkeypatch.setattr(config, "AUTH_OPERATOR_GROUPS", "Helpdesk, IT-Support")
    monkeypatch.setattr(config, "AUTH_USER_GROUPS", "")
    assert store.seed_policies_from_config() == 3
    assert store.seed_policies_from_config() == 0
    roles = {p["group_name"]: p["role"] for p in store.list_policies()}
    assert roles == {"VPN-Admins": "admin", "Helpdesk": "operator", "IT-Support": "operator"}


def test_policy_validation():
    with pytest.raises(store.StoreError):
        store.create_policy("any", "x", "superuser")
    with pytest.raises(store.StoreError):
        store.create_policy("kerberos", "x", "user")
    store.create_policy("any", "VPN-Users", "user")
    with pytest.raises(store.StoreError):
        store.create_policy("any", "VPN-Users", "admin")
