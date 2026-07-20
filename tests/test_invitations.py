"""System tests for invitation listing and revoke-before-use.

An authorized device can see its account's outstanding invitations and kill a
mis-shared one before it is used — the stolen-QR mitigation from the threat model.
"""

import httpx
import pytest

import beaconsim


def test_outstanding_invitation_is_listed(sund_server, new_account):
    _, token = new_account()
    device = beaconsim.register_device(sund_server.base_url, token)

    invitation = device.create_invitation()
    listed = device.list_invitations()

    assert [i["id"] for i in listed] == [invitation.id]
    # The secret token is never returned by the listing.
    assert all("token" not in i for i in listed)


def test_revoke_before_use_blocks_registration(sund_server, new_account):
    _, token = new_account()
    device = beaconsim.register_device(sund_server.base_url, token)
    invitation = device.create_invitation()

    device.revoke_invitation(invitation.id)

    # No longer listed...
    assert device.list_invitations() == []
    # ...and the token can no longer enroll a device.
    with pytest.raises(httpx.HTTPStatusError) as excinfo:
        beaconsim.register_device(sund_server.base_url, invitation.token)
    assert excinfo.value.response.status_code == 401


def test_consumed_invitation_drops_out_of_list(sund_server, new_account):
    _, token = new_account()
    device = beaconsim.register_device(sund_server.base_url, token)
    invitation = device.create_invitation()

    # Using the invitation removes it from the outstanding set.
    beaconsim.register_device(sund_server.base_url, invitation.token)
    assert device.list_invitations() == []


def test_revoke_is_account_scoped(sund_server, new_account):
    _, token_a = new_account()
    device_a = beaconsim.register_device(sund_server.base_url, token_a)
    invitation = device_a.create_invitation()

    # A device in another account cannot revoke A's invitation.
    _, token_other = new_account()
    stranger = beaconsim.register_device(sund_server.base_url, token_other)
    with pytest.raises(httpx.HTTPStatusError) as excinfo:
        stranger.revoke_invitation(invitation.id)
    assert excinfo.value.response.status_code == 404

    # A's invitation is untouched and still usable.
    assert [i["id"] for i in device_a.list_invitations()] == [invitation.id]
    beaconsim.register_device(sund_server.base_url, invitation.token)  # succeeds
