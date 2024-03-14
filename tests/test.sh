#!/bin/bash

# This script tests some outputs agains a known psono server with known entries

this_dir="$(dirname "${BASH_SOURCE[0]}")"

# shellcheck source=/dev/null
source "${this_dir}/.secrets"

cd "${this_dir}/../src/psonoclient" || exit 1

format="${FORMAT:-plain}"

function psono::restricted() {
    psono \
        --endpoint "${SERVER_ENDPOINT}" \
        --api-key-id "${API_KEY_ID_0}" \
        --api-key-private-key "${API_KEY_PRIVATE_KEY_0}" \
        --api-key-secret-key "${API_KEY_SECRET_KEY_0}" \
        --insecure \
        --server-signature "${SERVER_SIGNATURE}" \
        --client-cert-key "${CLIENT_KEY}" \
        --client-cert-crt "${CLIENT_CERT}" \
        --format "${format}" \
        "$@"
}

function psono::unrestricted() {
    psono \
        --endpoint "${SERVER_ENDPOINT}" \
        --api-key-id "${API_KEY_ID_1}" \
        --api-key-private-key "${API_KEY_PRIVATE_KEY_1}" \
        --api-key-secret-key "${API_KEY_SECRET_KEY_1}" \
        --insecure \
        --server-signature "${SERVER_SIGNATURE}" \
        --client-cert-key "${CLIENT_KEY}" \
        --client-cert-crt "${CLIENT_CERT}" \
        --format "${format}" \
        "$@"
}

# shellcheck disable=SC2120
function psono::env() {
    psono::restricted get --secret '43f3f1e2-3db4-488b-842c-a66d1bda14f1' "$@"
}

# shellcheck disable=SC2120
function psono::note() {
    psono::restricted get --secret '92bc0d9c-0314-41a1-81c1-0a11d07c6edd' "$@"
}

# shellcheck disable=SC2120
function psono::website() {
    psono::restricted get --secret '314c54c2-39ee-48c3-8f22-36c356952616' "$@"
}

# shellcheck disable=SC2120
function psono::bookmark() {
    psono::restricted get --secret '6baa552a-d3e3-4e9a-aabf-5ece398b892d' "$@"
}

# shellcheck disable=SC2120
function psono::app() {
    psono::restricted get --secret 'f4d77180-3802-4875-b031-49c475d7dbd2' "$@"
}

function check::generic() {
    local entry_type="$1"
    local field="$2"
    local should="$3"

    local output=""
    output="$("psono::${entry_type}" "${field}")"

    echo -n "Check entry type '${entry_type}' with '${field}' and got '${output}'."
    [[ "${output}" == "$should" ]] && echo " OK" || echo " WRONG, should be '${should}'."
}

function check::title() {
    for entry_type in env note website bookmark app; do
        check::generic "$entry_type" --title "$entry_type title"
    done
}

function check::url() {
    for entry_type in website bookmark; do
        check::generic "$entry_type" --url "https://example.com"
    done
}

function check::username() {
    for entry_type in website app; do
        check::generic "$entry_type" --username "admin"
    done
}

function check::password() {
    for entry_type in website app; do
        check::generic "$entry_type" --password "1234"
    done
}

function check::notes() {
    for entry_type in env note website bookmark app; do
        check::generic "$entry_type" --notes "$entry_type notes"
    done
}

function check::all() {
    format="plain"
    for field in title url username password notes; do
        echo "# Run test for ${field}"
        "check::${field}"
        echo ""
    done
}

if [[ "$1" =~ ^(un)?restricted$ ]]; then
    access_type="$1"
    shift 1
    if [[ "$1" == "secret" ]]; then
        shift 1
        "psono::website" "$@"
    else
        "psono::${access_type}" "$@"
    fi
    exit $?
else
    check::all
fi
