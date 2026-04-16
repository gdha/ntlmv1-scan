# ntlmv1-scan

Linux command-line tool to detect NTLMv1 authentication traffic on SMB sessions.

## What it does

`ntlmv1scan` captures raw Ethernet frames from a live network interface using
a Linux AF_PACKET raw socket.  It filters TCP traffic on ports 139 and 445
(NetBIOS/SMB), searches TCP payloads for NTLMSSP AUTHENTICATE (Type 3)
messages, and reports any messages where both the LM and NT response lengths
are 24 bytes — the signature of NTLMv1. For each hit it also performs a
best-effort lookup of the local Linux process (PID/command) owning the
matching TCP socket.

Root privileges (or `CAP_NET_RAW`) are required.

## Build dependencies

```bash
# Debian / Ubuntu
apt-get install -y autoconf automake libtool gcc

# RHEL / Fedora / CentOS
dnf install -y autoconf automake libtool gcc
```

No extra libraries are needed: the scanner uses only standard Linux kernel
headers and C library functions.

## Building from source

```bash
autoreconf -vfi
./configure
make
sudo make install
```

## Usage

```bash
# Scan interface eth0 indefinitely
sudo ./ntlmv1scan -i eth0

# Scan first 10000 packets on ens3
sudo ./ntlmv1scan -i ens3 -c 10000

# Print help
./ntlmv1scan -h
```

The program exits **0** when no NTLMv1 traffic was seen, and **1** when at
least one potential NTLMv1 authentication was detected (also used for fatal
errors), making it suitable for use in scripts.

## Example output

```
Scanning interface 'eth0' for NTLMv1 authentication traffic...
[2026-04-16 07:25:11.003421] Potential NTLMv1 authentication detected (packet_index=42, lm_len=24, nt_len=24, process=src pid=2131 comm=smbclient)

Scan summary:
  packets processed          : 500
  NTLM authenticate messages : 1
  potential NTLMv1 hits      : 1
```

## Limitations

* Only IPv4 over Ethernet is decoded.  VLAN tags, tunnels, and IPv6 are not
  currently supported.
* The scanner identifies NTLMv1 heuristically by response lengths; it does
  not fully decode the NTLM message.

## License

GPL v3 — see `COPYING`.

## Bug reports

Send mail to the author — see `AUTHORS`.
