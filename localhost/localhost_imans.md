# IMA namespace activation and PCR value check for localhost

This document describes the steps for activating [IMA namespace](https://github.com/stefanberger/linux-ima-namespaces) and shows how to check the differences between runtime PCR values when a file gets modified.

0. [TPM access for the IMA namespace](#0-tpm-access-for-the-ima-namespace)

1. [Spawn a new user namespace, and activate IMA namespace](#1-spawn-a-new-user-namespace-and-activate-ima-namespace)

2. [Execute a file and get the runtime PCR value](#2-execute-a-file-and-get-the-runtime-pcr-value)

## Prerequisites for your system:

1. IMA-namespace enabled kernel. Kernel codes can be downloaded [here](https://github.com/stefanberger/linux-ima-namespaces).
2. Hardware TPM or [swtpm](https://github.com/stefanberger/swtpm) and its corresponding tools, `apt-get install tpm-tools` for TPM 1.0, or see [INSTALL](https://tpm2-tools.readthedocs.io/en/latest/INSTALL/) page for TPM 2.0. Don't forget to get ownership for your TPM.

In this repository, I use TPM 2.0 with `swtpm`. Therefore, all the TPM commands specified below are for TPM 2.0, hence there may be differences for TPM 1.0 commands.

## Demo video

<img src="https://github.com/hajeong815/ima_namespace_activation/blob/main/localhost/demo_videos/imans_localhost.gif">

You can find this video in different formats(`.webm`, `.mp4`) [here](https://github.com/hajeong815/ima_namespace_activation/tree/main/localhost/demo_videos).

## 0. TPM access for the IMA namespace

**To be able to access TPM chip inside a IMA namespace, this step should be done before the activation of the IMA namespace!**

Since the IMA namespace is spawned with a new user namespace, it is not possible to access the TPM chip directly from the IMA namespace.
TPM is accessible via the following character devices.
    `/dev/tpm0`: direct access to the TPM driver
    `/dev/tpmrm0`: access to the TPM driver via the in-kernel TPM resource manager

Changing the permissions of these devices is a temporary action(`chmod`), and if you want to do this permanently, you can create a `udev` rule by creating a file under `/etc/udev/rules.d/`. 
Below is the udev rule from [tpm2-tss](https://github.com/tpm2-software/tpm2-tss/blob/master/dist/tpm-udev.rules):
```
# tpm devices can only be accessed by the tss user but the tss
# group members can access tpmrm devices
KERNEL=="tpm[0-9]*", TAG+="systemd", MODE="0660", OWNER="tss"
KERNEL=="tpmrm[0-9]*", TAG+="systemd", MODE="0660", GROUP="tss"
```

In the demo video, temporal action using `chmod` is used.

## 1. Spawn a new user namespace, and activate IMA namespace

First, create a new user namespace with `unshare`:
```
unshare --user --map-root-user --mount-proc --pid --fork /bin/bash
```

In the new user namespace, mount `securityfs` and enable the IMA namespace:

```
mount -t securityfs /sys/kernel/security /sys/kernel/security
echo 1 > /sys/kernel/security/ima/active
```

Then, write an namespace-specific policy to `/sys/kernel/security/ima/policy`:

```
cat /dir/to/your/policy > /sys/kernel/security/ima/policy
```

In this demo, the policy file below is used:

```
# PROC_SUPER_MAGIC
dont_measure fsmagic=0x9fa0
dont_appraise fsmagic=0x9fa0
# SYSFS_MAGIC
dont_measure fsmagic=0x62656572
dont_appraise fsmagic=0x62656572
# DEBUGFS_MAGIC
dont_measure fsmagic=0x64626720
dont_appraise fsmagic=0x64626720
# TMPFS_MAGIC
dont_measure fsmagic=0x01021994
dont_appraise fsmagic=0x01021994
# RAMFS_MAGIC
dont_appraise fsmagic=0x858458f6
# DEVPTS_SUPER_MAGIC
dont_measure fsmagic=0x1cd1
dont_appraise fsmagic=0x1cd1
# BINFMTFS_MAGIC
dont_measure fsmagic=0x42494e4d
dont_appraise fsmagic=0x42494e4d
# SECURITYFS_MAGIC
dont_measure fsmagic=0x73636673
dont_appraise fsmagic=0x73636673
# SELINUX_MAGIC
dont_measure fsmagic=0xf97cff8c
dont_appraise fsmagic=0xf97cff8c
# CGROUP_SUPER_MAGIC
dont_measure fsmagic=0x27e0eb
dont_appraise fsmagic=0x27e0eb
# NSFS_MAGIC
dont_measure fsmagic=0x6e736673
dont_appraise fsmagic=0x6e736673

#measure func=FILE_CHECK
measure func=FILE_CHECK
measure func=MODULE_CHECK
measure func=FIRMWARE_CHECK
measure func=KEXEC_KERNEL_CHECK
measure func=KEXEC_INITRAMFS_CHECK
measure func=KEXEC_CMDLINE
measure func=KEY_CHECK keyrings=.builtin_trusted_keys|.ima
measure func=KEY_CHECK keyrings=.builtin_trusted_keys|.evm
dont_appraise fowner=0
```

To check if your IMA namespace is activated, run: `cat /sys/kernel/security/ima/active`. 

If it returns `1`, then the namespace is activated. Otherwise, it will return `0`.

Check the [IMA namespace patch log](https://lwn.net/Articles/922361/) for more information.

## 2. Execute a file and get the runtime PCR value

To presume a malicious attack:
1. Execute a simple Python file(`demo.python`), get the file hash from the IMA log(`/sys/kernel/security/ima/ascii_runtime_measurements`) and PCR 10 values. These values are the expected values.

   ```
   root@IMAns-demo:/home/ubuntu# python3 demo.python
   hello world!
   root@IMAns-demo:/home/ubuntu# tail -5 /sys/kernel/security/ima/ascii_runtime_measurements 
   10 e83c41f211a5d0a9452070d9571898ec6eb6c411 ima-ng sha1:5db8eb03071c8c231a8f51b3d2a98bd1eb589634 /home/ubuntu/demo.python
   10 a2bb10c7d82be3e7c5e8fcc1dade229de4da36c9 ima-ng sha256:00483d769f2d15f6d3c0f6f2d9c3c8dde3d377094d8411738f0f3b335008cf84 /usr/bil

   root@IMAns-demo:/home/ubuntu# tpm2_pcrread sha1:10
     sha1:
     10: 0x8708C588AC360439668B4E693B835A1CC8345CDB
   ```

   Here, the expected values are:\
     file hash: `5db8eb03071c8c231a8f51b3d2a98bd1eb589634` \
     PCR 10 value: `0x8708C588AC360439668B4E693B835A1CC8345CDB`
   
3. Modify the Python file, and execute it again.
   
   ```
   root@IMAns-demo:/home/ubuntu# echo 'print("someone unknown")' >> demo.python 
   root@IMAns-demo:/home/ubuntu# python3 demo.python
   hello world!
   someone unknown
   ```

4. Check the file hash from the IMA log and PCR value, then compare the new values with the expected values.

   ```
   root@IMAns-demo:/home/ubuntu# tail -5 /sys/kernel/security/ima/ascii_runtime_measurements 
   10 e83c41f211a5d0a9452070d9571898ec6eb6c411 ima-ng sha1:5db8eb03071c8c231a8f51b3d2a98bd1eb589634 /home/ubuntu/demo.python
   10 a2bb10c7d82be3e7c5e8fcc1dade229de4da36c9 ima-ng sha256:00483d769f2d15f6d3c0f6f2d9c3c8dde3d377094d8411738f0f3b335008cf84 /usr/binl
   10 80144f6ea869efb758e2c92f0050f657f7298bc7 ima-ng sha1:b1cd3b45f69dbefe72b65f57f15ee27c5de4bd72 /home/ubuntu/demo.python
   root@IMAns-demo:/home/ubuntu# tpm2_pcrread sha1:10
     sha1:
     10: 0x0A34C6C52D7AD0E6EA5256607BAFC2EF2B93A6F5
   ```

   Unexpected values: \
     file hash: `b1cd3b45f69dbefe72b65f57f15ee27c5de4bd72` \
     PCR 10 value: `0x0A34C6C52D7AD0E6EA5256607BAFC2EF2B93A6F5`








