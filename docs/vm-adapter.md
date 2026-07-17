# Disposable Linux VM adapter

S5 and S6 are host-assisted labs. Run them only in a disposable, locally
hosted Linux VM—not on the macOS host, bare metal, a container, or a cloud VM.

## Provision the adapter

After creating a VM snapshot, run this inside the VM as root:

```bash
sudo scripts/provision-vm-adapter snapshot-001 --acknowledge-disposable-snapshot
```

The acknowledgement means the operator has created a disposable snapshot and
accepts that the lab may change the guest. Secure Learn detects supported local
virtualization evidence and writes `/etc/secure-learn/vm-adapter.json`. The
marker is root-owned, bounded, non-symlinked, and records its provider, snapshot
label, timestamp, and random provisioning nonce.

Supported provider evidence is QEMU/KVM, VMware, VirtualBox, Parallels, Apple
Virtualization, and UTM. Container and AWS, Google Cloud, or Azure signals are
rejected.

## Issue and check a lab receipt

Issue and validate a short-lived receipt inside the same booted VM:

```bash
scripts/issue-vm-receipt s5 snapshot-001 s5-readiness.json
export SECURE_LEARN_VM_RECEIPT=evidence/vm-receipts/s5-readiness.json
scripts/learn doctor s5
```

`scripts/learn doctor s5` must run inside that Linux VM. The macOS host cannot
read or revalidate the guest's root-owned marker. Host-to-guest verification
would require a separate authenticated adapter API, which is not implemented.

Receipt files must be direct `.json` children of the ignored
`evidence/vm-receipts/` directory. They bind the requested lab, current machine
and boot identifiers, adapter marker digest, provider, provisioning nonce, and
a validity window of at most four hours.

## Assurance boundary

This is an **operator-attested local VM readiness control**, not cryptographic
attestation and not proof that a hypervisor snapshot API was called. A root
operator can forge the marker or its inputs. The control is designed to prevent
accidental execution on the host, bare metal, containers, and unsupported cloud
VMs while making the disposable-snapshot decision explicit and reviewable.
