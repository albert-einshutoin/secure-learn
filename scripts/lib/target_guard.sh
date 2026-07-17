#!/bin/bash

# Attack labs deliberately use enumerated profiles instead of caller-provided
# CIDRs. A hardcoded identity/IP/port tuple keeps overrides from widening the
# authorized Docker target boundary.
secure_learn_validate_target() {
    local profile="${SECURE_LEARN_TARGET_PROFILE:-base}"
    local expected_target
    local expected_ip
    local expected_port=3000

    case "$profile" in
        base)
            expected_target=app
            expected_ip=172.23.0.20
            ;;
        exercise)
            expected_target=target-app
            expected_ip=172.32.0.100
            ;;
        *)
            echo "ERROR: Unknown Secure Learn target profile: $profile" >&2
            return 64
            ;;
    esac

    if [[ -n "${TARGET+x}" && "$TARGET" != "$expected_target" ]]; then
        echo "ERROR: TARGET is outside the '$profile' lab profile." >&2
        return 64
    fi
    if [[ -n "${TARGET_IP+x}" && "$TARGET_IP" != "$expected_ip" ]]; then
        echo "ERROR: TARGET_IP is outside the '$profile' lab profile." >&2
        return 64
    fi
    if [[ -n "${TARGET_PORT+x}" && "$TARGET_PORT" != "$expected_port" ]]; then
        echo "ERROR: TARGET_PORT is outside the '$profile' lab profile." >&2
        return 64
    fi

    TARGET="$expected_target"
    TARGET_IP="$expected_ip"
    TARGET_PORT="$expected_port"
    export TARGET TARGET_IP TARGET_PORT
}

# Validate text before any arithmetic expansion. Bash arithmetic recursively
# evaluates variable contents, so rejecting non-decimal data first prevents an
# environment value from becoming executable syntax.
secure_learn_validate_bounded_decimal() {
    local name="$1"
    local value="$2"
    local minimum="$3"
    local maximum="$4"
    local decimal

    if [[ ! "$value" =~ ^[0-9]+$ || ${#value} -gt 10 ]]; then
        echo "ERROR: $name must be a decimal integer from $minimum through $maximum." >&2
        return 64
    fi
    decimal=$((10#$value))
    if ((decimal < minimum || decimal > maximum)); then
        echo "ERROR: $name must be a decimal integer from $minimum through $maximum." >&2
        return 64
    fi
}

secure_learn_validate_loopback_base_url() {
    if [[ "$1" != "http://127.0.0.1:3000" ]]; then
        echo "ERROR: BASE_URL must be the loopback-only Secure Learn endpoint http://127.0.0.1:3000." >&2
        return 64
    fi
}
