"""beaconsim — headless Family Beacon client mockup for Sund's system suite.

This is the embryo of the real client SDK (sund-client / beacon-protocol): the
system-test suite is Sund's first consumer, forcing API ergonomics before any
app exists (see docs/Sund-ImplementationGuide.md, Testing). It is deliberately
written in a different language from the server so it exercises the API as an
independent client, not a same-language mirror of the server's assumptions —
which is why the request-signing canonical form lives here in Python and must
match internal/sigauth byte-for-byte.
"""

from .client import Client, Invitation, Queue, Sender, register_device, signing_string
from .pinning import PinError, connect, parse_address, pinned_context

__all__ = [
    "Client", "Invitation", "Queue", "Sender",
    "register_device", "signing_string",
    "PinError", "connect", "parse_address", "pinned_context",
    "__version__",
]

__version__ = "0.4.0"
