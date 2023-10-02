# IMA namespace activation and PCR value check for a Docker container

This document describes the steps for activating [IMA namespace](https://github.com/stefanberger/linux-ima-namespaces) and shows how to check the differences between runtime PCR values when a file gets modified.

## Prerequisites for your system:

1. IMA-namespace enabled kernel. Kernel codes can be downloaded [here](https://github.com/stefanberger/linux-ima-namespaces).
2. Hardware TPM or [swtpm](https://github.com/stefanberger/swtpm) and its corresponding tools, `apt-get install tpm-tools` for TPM 1.0, or see [INSTALL](https://tpm2-tools.readthedocs.io/en/latest/INSTALL/) page for TPM 2.0. Don't forget to get ownership for your TPM.
3. `Docker` should be installed on your system.

In this repository, I use TPM 2.0 with `swtpm`. Therefore, all the TPM commands specified below are for TPM 2.0, hence there may be differences for TPM 1.0 commands.


## 0. Start swtpm using socket interface

To get more isolated view, in this demo, a container will have its own swtpm device, which is isolated from the host. To do so, start the swtpm on the localhost first:

```
mkdir -p /dir/to/your/dockerfile/myvtpm
swtpm socket --tpmstate dir=/dir/to/your/dockerfile/myvtpm --tpm2 --ctrl type=tcp,port=2322 \
   --server type=tcp,port=2321 --flags not-need-init -d
```

Then, proceed to the next steps.

## 1. Create a Docker container

- `Dockerfile`
  ```
  FROM ubuntu:22.04

  RUN apt-get -y update
  RUN apt-get -y install openssl vim tpm2-abrmd tpm2-tools python3 python3-pip tss2

  WORKDIR /
  ```

  Create a simple `Dockerfile` for the demo container.

- Create the container

  ```
  docker create --rm  --net host -e TPM2TOOLS_TCTI="swtpm:port=2321" \
      --privileged \
      -it --name imans_container imans_demo 
  ```

  **Note:** Check capabilities(`--cap-add`) and AppArmor profile if needed, and adjust them for your project. Or, simply use `--privileged` option.

Plus, if necessary, **copy your namespace-specific policy file to the container**, or create it inside the container before spawning the namespace.

Example policy file used in this demo:

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
measure func=FILE_CHECK mask=MAY_EXEC uid=0 fowner=0
measure func=FILE_CHECK mask=MAY_READ uid=0 fowner=0
measure func=MODULE_CHECK
measure func=FIRMWARE_CHECK
measure func=KEXEC_KERNEL_CHECK
measure func=KEXEC_INITRAMFS_CHECK
measure func=KEXEC_CMDLINE
measure func=KEY_CHECK keyrings=.builtin_trusted_keys|.ima
measure func=KEY_CHECK keyrings=.builtin_trusted_keys|.evm
appraise fowner=0

```
  

## 2. Start the container and TPM

Then, start the container with:
```
docker start -ai imans_container
```

Inside the container, to get usage of vTPM, run:
```
tpm2_startup -c
```

## 3. Spawn a new user namespace, and activate IMA namespace

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

To check if your IMA namespace is activated, run: `cat /sys/kernel/security/ima/active`. 

If it returns `1`, then the namespace is activated. Otherwise, it will return `0`.

Check the [IMA namespace patch log](https://lwn.net/Articles/922361/) for more information.

## 4. Execute a file and get the runtime PCR value

To presume a malicious attack:
1. Execute a simple Python file(`demo.python`), get the file hash from the IMA log(`/sys/kernel/security/ima/ascii_runtime_measurements`) and PCR 10 values. These values are the expected values.

   ```
   root@sev-guest-imans:/# echo 'print("hello world")' > demo.python
   root@sev-guest-imans:/# python3 demo.python 
   hello world
   root@sev-guest-imans:/# tpm2_pcrevent 10 demo.python 
   sha1: 8afe427bbfb4b47865ec49e7ad491872f210be06
   sha256: 4660ab1ff310887b8f4727933f68eeb74012a5fbc7107d500b146796f0d95b6b
   sha384: ad3dee94a2af19c9ba42de3e25f5334d66f408c21fce158b8a2301ab3d534e0f430aa3d1f055c05dc325374bc0f317dd
   sha512: 3404d8a30339a58713878a05d51168dad05ba93671009f0d62ac98185840f5b0d2703989f0fdf7ef3fd89c1011646069b53ea9d7db71f3c6eed3c71677f6d209
   root@sev-guest-imans:/# tail -5 /sys/kernel/security/ima/ascii_runtime_measurements 
   10 4917e89f1ed23888aafb6de997ae99c3d102a4bf ima-ng sha512:41ff68b12070a23168425b7fe3c4bbec5d0a9fe148ee951ce1d922ecda0bb016b53028dd12767e0d8c3df9a240f5ba1e70473c9f01e040062f4ee09572f67baf /etc/ssl/openssl.cnf
   10 11b23b6ad98842a845695c406414a720d6f8d3dc ima-ng sha512:ba3479d4a47a822c1dee7bcf35504545138c375809ca785ccd422159d565b877e682ddfa4ff951f7e738b667d79d64e8e1e77e266fda9887d3a59641571ddac8 /demo.python
   10 2d0ec7b1c8840d0659d6e144bcd233d32a530dcc ima-ng sha512:218670e40c6c506a52041475ee4bfd4fe1c324178a6d4b986ce198cc0156aabeeb7bd2230c4264abe14a471b7b9d9eded343910d1346705e8529e8be1fb7015b /usr/bin/ls
   10 252555935f4a0583197b04f10461252c5504570a ima-ng sha512:4a79bac0ba6eb215921694152c28c597d11030d6d4605280c144b434b6a8a1efffd96f105f436e823e958ce3ea8c6b169d60e7c3de44bab9559e4e01684e36fb /usr/bin/rm
   10 4fa19672250991263f98844ed570f77c7c36c803 ima-ng sha512:3404d8a30339a58713878a05d51168dad05ba93671009f0d62ac98185840f5b0d2703989f0fdf7ef3fd89c1011646069b53ea9d7db71f3c6eed3c71677f6d209 /demo.python
   root@sev-guest-imans:/# tpm2_pcrread sha512:10
     sha512:
       10: 0x0B5941D890EAE3D7C9889EEAB81E10CA213331943E8967BF761C2DDF0BF50EC2625167CE5833C35BA1011CBFD103FCB3A9C500975EDB29A7110B74D06C90A494
   ```

   Here, the expected values are:\
     file hash: `3404d8a30339a58713878a05d51168dad05ba93671009f0d62ac98185840f5b0d2703989f0fdf7ef3fd89c1011646069b53ea9d7db71f3c6eed3c71677f6d209` \
     PCR 10 value: `0x0B5941D890EAE3D7C9889EEAB81E10CA213331943E8967BF761C2DDF0BF50EC2625167CE5833C35BA1011CBFD103FCB3A9C500975EDB29A7110B74D06C90A494`
   
3. Modify the Python file, and execute it again.
   
   ```
   root@sev-guest-imans:/# echo 'print("someone unknown")' >> demo.python 
   root@sev-guest-imans:/# python3 demo.python 
   hello world
   someone unknown
   ```

4. Check the file hash from the IMA log and PCR value, then compare the new values with the expected values.

   ```
   root@sev-guest-imans:/# tpm2_pcrevent 10 demo.python 
   sha1: 79794c462cfdf42227b4c00869018005b872bbd2
   sha256: a993c332280a07f05b38866717e5a554a3f5cf288e2f320af25e55860b8ca34b
   sha384: 1d52a1b3e146c7e1bd5ef205a160dc1ee4a54005e3eb16bc013b49501cec2178dad7071880776c8db8a0eb4caf794de9
   sha512: 470a295a44c3f94106a767c27b519397bd4f6a1eda610d5401e8fa1e342b36ee1f8614c2862b172a8744e7aa79cf967a23966aa434042cf0d08f9d762b42af5e
   root@sev-guest-imans:/# tail -5 /sys/kernel/security/ima/ascii_runtime_measurements 
   10 11b23b6ad98842a845695c406414a720d6f8d3dc ima-ng sha512:ba3479d4a47a822c1dee7bcf35504545138c375809ca785ccd422159d565b877e682ddfa4ff951f7e738b667d79d64e8e1e77e266fda9887d3a59641571ddac8 /demo.python
   10 2d0ec7b1c8840d0659d6e144bcd233d32a530dcc ima-ng sha512:218670e40c6c506a52041475ee4bfd4fe1c324178a6d4b986ce198cc0156aabeeb7bd2230c4264abe14a471b7b9d9eded343910d1346705e8529e8be1fb7015b /usr/bin/ls
   10 252555935f4a0583197b04f10461252c5504570a ima-ng sha512:4a79bac0ba6eb215921694152c28c597d11030d6d4605280c144b434b6a8a1efffd96f105f436e823e958ce3ea8c6b169d60e7c3de44bab9559e4e01684e36fb /usr/bin/rm
   10 4fa19672250991263f98844ed570f77c7c36c803 ima-ng sha512:3404d8a30339a58713878a05d51168dad05ba93671009f0d62ac98185840f5b0d2703989f0fdf7ef3fd89c1011646069b53ea9d7db71f3c6eed3c71677f6d209 /demo.python
   10 18afb653b44a84f110016d12b9cb488992fac9c6 ima-ng sha512:470a295a44c3f94106a767c27b519397bd4f6a1eda610d5401e8fa1e342b36ee1f8614c2862b172a8744e7aa79cf967a23966aa434042cf0d08f9d762b42af5e /demo.python
   root@sev-guest-imans:/# tpm2_pcrread sha512:10
     sha512:
       10: 0x87BAFBD7A49ECB85494709DE3028621AA26C7B5D923E2D4C4C09002F5CEBB81117ED57926C774F951F5E68D63E8298E41DC62D15162D5CFE61EDFA861DF9F8BC
   ```

   Unexpected values: \
     file hash: `470a295a44c3f94106a767c27b519397bd4f6a1eda610d5401e8fa1e342b36ee1f8614c2862b172a8744e7aa79cf967a23966aa434042cf0d08f9d762b42af5e` \
     PCR 10 value: `0x87BAFBD7A49ECB85494709DE3028621AA26C7B5D923E2D4C4C09002F5CEBB81117ED57926C774F951F5E68D63E8298E41DC62D15162D5CFE61EDFA861DF9F8BC`

