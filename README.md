# skinny-proxy
Skinny / SCCP Proxy

This is skinny-proxy.pl a SCCP/Skinny proxyserver to make them work behind NAT. This project was run in 2002.
It is here for legacy purposes and mostly informational.

skinny-proxy v1.48, proxy@ipphones.nl

    Usage: ./skinny-proxy.pl local_ip public_ip callmanager_ip
    Example: ./skinny-proxy.pl 192.168.1.1 24.24.24.24 25.25.25.25

    local_ip       Should correspond to a local TCP/IP interface
    public_ip      Should be an IP address that is reachable from the internet
    callmanager_ip The IP address of the CallManager, see
                   http://ipphone.patser.net/ (in Dutch)

    (c) 1999 Tkil
    (c) 2002 Cliff Albert, Gerard Oskamp, Jorrit Waalboer
    This proxy is free software; you can redistribute it and/or modify it under
    the same terms as Perl.
