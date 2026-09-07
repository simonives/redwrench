# justfile

fedora_host := env_var_or_default("REDWRENCH_FEDORA_HOST", "")

# Sync the working tree to the Fedora box and run the test suite there.
remote-test:
    #!/usr/bin/env bash
    set -euo pipefail
    if [ -z "{{fedora_host}}" ]; then
        echo "Set REDWRENCH_FEDORA_HOST to the Fedora box's address first." >&2
        exit 1
    fi
    rsync -az --exclude target --exclude .git ./ "{{fedora_host}}:~/redwrench/"
    ssh "{{fedora_host}}" "cd ~/redwrench && cargo test"

# Same as remote-test, but also runs the binary afterwards.
remote-run *ARGS:
    #!/usr/bin/env bash
    set -euo pipefail
    if [ -z "{{fedora_host}}" ]; then
        echo "Set REDWRENCH_FEDORA_HOST to the Fedora box's address first." >&2
        exit 1
    fi
    rsync -az --exclude target --exclude .git ./ "{{fedora_host}}:~/redwrench/"
    ssh "{{fedora_host}}" "cd ~/redwrench && cargo run -- {{ARGS}}"
