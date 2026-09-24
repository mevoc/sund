"""System scenarios S5b/S5b2/S5b3 — the account administration model.

A `flat` account is PRD 0.3 behaviour: every device registers as an admin and
may do everything. A `managed` account restricts revoking another device,
minting an invitation and changing a role to admins. Two invariants hold in both
modes: a device may always revoke itself, and an account never loses its last
admin to an act performed on another device (PRD, decision 12).
"""

import beaconsim


def _managed_account_with_member(sund_server, new_account):
    """An admin (the account's first device) and a member it invited."""
    _, token = new_account(admin_mode="managed")
    admin = beaconsim.register_device(sund_server.base_url, token)
    member_token = admin.create_invitation(grants_role="member").token
    member = beaconsim.register_device(sund_server.base_url, member_token)
    return admin, member


def test_first_device_is_admin_even_in_a_managed_account(sund_server, new_account):
    """Otherwise the last-admin invariant would be unsatisfiable from the start."""
    admin, member = _managed_account_with_member(sund_server, new_account)
    roles = {d["id"]: d["role"] for d in admin.list_devices()}
    assert roles[admin.device_id] == "admin"
    assert roles[member.device_id] == "member"


def test_member_cannot_revoke_mint_or_promote(sund_server, new_account):
    """S5b — the three admin-only acts, refused for a member."""
    admin, member = _managed_account_with_member(sund_server, new_account)

    assert member.revoke_device_raw(admin.device_id).status_code == 403
    assert member.create_invitation_raw().status_code == 403
    assert member.set_role(member.device_id, "admin").status_code == 403

    # Nothing changed.
    roles = {d["id"]: d["role"] for d in admin.list_devices()}
    assert roles[member.device_id] == "member"
    assert not any(d["revoked"] for d in admin.list_devices())


def test_a_member_may_always_revoke_itself(sund_server, new_account):
    """The one remedy a member has against an admin, so it is unconditional."""
    admin, member = _managed_account_with_member(sund_server, new_account)
    assert member.revoke_device_raw(member.device_id).status_code == 200
    revoked = {d["id"]: d["revoked"] for d in admin.list_devices()}
    assert revoked[member.device_id] is True


def test_admin_may_revoke_a_member(sund_server, new_account):
    admin, member = _managed_account_with_member(sund_server, new_account)
    assert admin.revoke_device_raw(member.device_id).status_code == 200


def test_last_admin_cannot_be_demoted_or_revoked_by_another(sund_server, new_account):
    """S5b2 — the invariant, and the escape hatch it deliberately leaves open."""
    admin, member = _managed_account_with_member(sund_server, new_account)

    # Demoting the only admin would strand the member.
    assert admin.set_role(admin.device_id, "member").status_code == 409

    # Promote the member, and the demotion becomes possible.
    assert admin.set_role(member.device_id, "admin").status_code == 200
    assert admin.set_role(admin.device_id, "member").status_code == 200

    roles = {d["id"]: d["role"] for d in admin.list_devices()}
    assert roles[member.device_id] == "admin"
    assert roles[admin.device_id] == "member"


def test_the_last_admin_may_still_revoke_itself(sund_server, new_account):
    """Reachable by design: self-revocation has no exception, so the operator
    recovery path (`sund admin device promote`) is the way back in."""
    admin, _member = _managed_account_with_member(sund_server, new_account)
    assert admin.revoke_device_raw(admin.device_id).status_code == 200


def test_roles_are_refused_in_a_flat_account(sund_server, new_account):
    """S5b3 — flat means every device is an admin as a property of the account,
    so there is nothing to promote and no walking it into managed mode."""
    _, token = new_account()  # flat is the default
    a = beaconsim.register_device(sund_server.base_url, token)
    b = beaconsim.register_device(sund_server.base_url, a.create_invitation().token)

    assert [d["role"] for d in a.list_devices()] == ["admin", "admin"]
    assert a.set_role(b.device_id, "member").status_code == 409

    # And flat behaviour is unchanged: either device may revoke the other.
    assert b.revoke_device_raw(a.device_id).status_code == 200
