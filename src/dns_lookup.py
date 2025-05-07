import socket
from functools import lru_cache
from typing import Optional


@lru_cache(maxsize=1000)
def get_dns_info(addr: str) -> Optional[str]:
    """
    Get hostname from IP address as fast as possible.
    
    Args:
        addr: IP address string (IPv4 or IPv6)
        
    Returns:
        str: Hostname for the given IP address
        None: If reverse lookup fails
    """
    try:
        return socket.getfqdn(addr)
    except (socket.error, OSError):
        return None
