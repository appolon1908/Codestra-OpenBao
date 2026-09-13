# OpenBao memory protection

OpenBao v2.6.2 refuses to start when the legacy `disable_mlock` setting is
present. The upstream server reports that mlock support was removed and directs
operators to disable or encrypt swap. Codestra therefore does not silently set
`disable_mlock = true`; the directive is absent, `IPC_LOCK` is not granted, and
host preflight fails closed unless every active swap device is encrypted.

Run the read-only preflight with:

```text
python3 scripts/validate_host_memory.py
```

`OPENBAO_HOST_MEMORY=PASS` requires either `SWAP_MODE=disabled` or
`SWAP_MODE=encrypted`. A normal partition, RAID device, swapfile or unknown
device type fails. Changing host swap configuration is a separate reviewed
infrastructure operation and this repository must not perform it implicitly.

The requirement follows the OpenBao post-installation hardening guidance:
<https://openbao.org/docs/install/>.
