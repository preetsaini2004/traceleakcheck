"""TraceLeakCheck: catch secrets leaking through OpenTelemetry exports."""

from .canary import Canary, make_canary
from .receiver import OTLPReceiver
from .scanner import Finding, scan

__all__ = ["Canary", "Finding", "OTLPReceiver", "make_canary", "scan"]
