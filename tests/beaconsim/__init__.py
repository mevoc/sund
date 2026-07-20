"""beaconsim — headless Family Beacon client mockup for Sund's system suite.

This is the embryo of the real client SDK (sund-client / beacon-protocol): the
system-test suite is Sund's first consumer, forcing API ergonomics before any
app exists (see docs/Sund-ImplementationGuide.md, Testing). It is deliberately
written in a different language from the server so it exercises the API as an
independent client, not a same-language mirror of the server's assumptions.

At this scaffold stage it holds only the version marker; device identity,
fingerprint pinning, pairing, queues and real E2E crypto arrive alongside the
endpoints they exercise.
"""

__all__ = ["__version__"]

__version__ = "0.0.0"
