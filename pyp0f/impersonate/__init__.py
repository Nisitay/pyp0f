from .mtu import impersonate as impersonate_mtu
from .tcp import impersonate as impersonate_tcp

__all__ = ["impersonate_mtu", "impersonate_tcp"]
