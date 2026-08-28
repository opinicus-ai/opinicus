# Ultralytics PyPI releases shipped a cryptominer after CI workflow injection and token theft

- Date: 2024-12-04 to 2024-12-07 | Agent/tool: ultralytics PyPI package and its GitHub Actions release pipeline | Axis: supply

## What happened

Between December 4 and 7, 2024, an attacker abused the Ultralytics release pipeline to publish cryptominer-laced versions of the popular computer-vision library. The first round hit versions 8.3.41 and 8.3.42 through the project's own GitHub Actions workflow. A second round, versions 8.3.45 and 8.3.46, was published straight to PyPI with a stolen PyPI API token. Users who installed the bad versions got an XMRig miner that ran in the background. Google Colab users were banned for the resulting "abusive activity". The malicious versions stayed up for around half a day before removal. PyPI staff later confirmed the details from the project's own signing attestations.

## How it went wrong

The attacker opened draft pull requests and used a classic GitHub Actions script injection: a workflow step interpolated the untrusted branch name into a shell command, roughly `git pull origin ${{ github.head_ref }}`. A crafted branch name turned that step into attacker shell code on the release runner. The payload downloaded a script (a `curl ... file.sh | bash` shape) which modified the package build and fetched XMRig; the malicious code was bundled into the sdist that the workflow published. Two key package functions, `safe_download` and `safe_run`, were changed so that using the library downloaded and executed the miner. For the later versions the attacker reused an unrevoked PyPI token that was still sitting in the workflow's secrets and published directly, bypassing CI. On the victim machine, a plain `pip install ultralytics` ran the package's own build and setup code, and later importing it triggered download-and-exec.

## What the firewall should learn

This incident is about the install and build toolchain, and the agent's machine is where `pip install` runs. Signals: (1) exec of a build/setup interpreter (python running setup.py or a PEP 517 backend) under a pip/uv ancestry is arbitrary code from the package and deserves approval_required; (2) a file_open write of a file followed by exec of that same file in the same ancestry is download-then-run, worth approval_required (the builtin from-temp rule only observes, and only for /tmp); (3) network_connect from a process under a package-install ancestry to a host that is not the configured registry needs approval, because fetching a "model file" or miner payload looks like this; (4) the CI side lesson maps to the input observable: workflow text that interpolates `${{ github.head_ref }}` (or `${{ inputs.* }}`) into a run/pull step, or a `curl | bash` in a step, should be flagged when the agent writes such a file (decision: approval_required).

## Sources

- [HiddenLayer: Ultralytics Python Package Compromise Deploys Cryptominer](https://www.hiddenlayer.com/research/ultralytics-python-package-compromise-deploys-cryptominer)
- [PyPI Blog: Supply-chain attack analysis — Ultralytics](https://blog.pypi.org/posts/2024-12-11-ultralytics-attack-analysis/)
- [Wiz: Ultralytics AI Library Hacked via GitHub for Cryptomining](https://www.wiz.io/blog/ultralytics-ai-library-hacked-via-github-for-cryptomining)
- [Snyk: Ultralytics AI pwn request supply chain attack](https://snyk.io/blog/ultralytics-ai-pwn-request-supply-chain-attack/)
