#!/usr/bin/env bash
set -euo pipefail

: "${AEGIS_ECR_REGISTRY:?AEGIS_ECR_REGISTRY is required}"
: "${CONTROL_PLANE_DIGEST:?CONTROL_PLANE_DIGEST is required}"
: "${GITHUB_REPOSITORY:?GITHUB_REPOSITORY is required}"
: "${GITHUB_RUN_ATTEMPT:?GITHUB_RUN_ATTEMPT is required}"
: "${GITHUB_RUN_ID:?GITHUB_RUN_ID is required}"
: "${GH_TOKEN:?GH_TOKEN is required for GitHub attestation verification}"
: "${OPERATOR_UI_DIGEST:?OPERATOR_UI_DIGEST is required}"

readonly control_plane_source="ghcr.io/mrinmoyece/aegis-agent-platform"
readonly operator_ui_source="ghcr.io/mrinmoyece/aegis-operator-ui"
readonly otel_source="docker.io/otel/opentelemetry-collector-contrib"
readonly otel_digest="sha256:9c247564e65ca19f97d891cca19a1a8d291ce631b890885b44e3503c5fdb3895"

printf '%s\n' "${AEGIS_ECR_REGISTRY}" |
  grep --extended-regexp --quiet '^[0-9]{12}\.dkr\.ecr\.[a-z0-9-]+\.amazonaws\.com$'
for digest in "${CONTROL_PLANE_DIGEST}" "${OPERATOR_UI_DIGEST}"; do
  printf '%s\n' "${digest}" |
    grep --extended-regexp --quiet '^sha256:[0-9a-f]{64}$'
done

mirror_signed() {
  local source="$1"
  local digest="$2"
  local destination="$3"
  local tag="promotion-${GITHUB_RUN_ID}-${GITHUB_RUN_ATTEMPT}-${digest#sha256:}"
  local mirrored
  if mirrored="$(
    docker buildx imagetools inspect "${destination}:${tag}" \
      --format '{{json .Manifest.Digest}}' 2>/dev/null | tr -d '"'
  )"; then
    test "${mirrored}" = "${digest}"
  else
    oras copy --recursive "${source}@${digest}" "${destination}:${tag}"
  fi
  mirrored="$(
    docker buildx imagetools inspect "${destination}:${tag}" \
      --format '{{json .Manifest.Digest}}' | tr -d '"'
  )"
  test "${mirrored}" = "${digest}"
  cosign verify \
    --registry-referrers-mode oci-1-1 \
    --certificate-identity-regexp '^https://github.com/mrinmoyece/aegis-agent-platform/.github/workflows/supply-chain.yml@refs/heads/master$' \
    --certificate-oidc-issuer 'https://token.actions.githubusercontent.com' \
    "${destination}@${digest}" >/dev/null
  for predicate in \
    'https://slsa.dev/provenance/v1' \
    'https://spdx.dev/Document/v2.3'; do
    gh attestation verify "oci://${destination}@${digest}" \
      --bundle-from-oci \
      --repo "${GITHUB_REPOSITORY}" \
      --signer-workflow github.com/mrinmoyece/aegis-agent-platform/.github/workflows/supply-chain.yml \
      --source-ref refs/heads/master \
      --predicate-type "${predicate}" >/dev/null
  done
  docker buildx imagetools inspect "${destination}@${digest}" --raw |
    jq --raw-output '.manifests[].digest' |
    while IFS= read -r platform_digest; do
      gh attestation verify "oci://${destination}@${platform_digest}" \
        --bundle-from-oci \
        --repo "${GITHUB_REPOSITORY}" \
        --signer-workflow github.com/mrinmoyece/aegis-agent-platform/.github/workflows/supply-chain.yml \
        --source-ref refs/heads/master \
        --predicate-type 'https://spdx.dev/Document/v2.3' >/dev/null
    done
}

mirror_signed \
  "${control_plane_source}" \
  "${CONTROL_PLANE_DIGEST}" \
  "${AEGIS_ECR_REGISTRY}/aegis-agent-platform"
mirror_signed \
  "${operator_ui_source}" \
  "${OPERATOR_UI_DIGEST}" \
  "${AEGIS_ECR_REGISTRY}/aegis-operator-ui"

otel_destination="${AEGIS_ECR_REGISTRY}/aegis-otel-collector"
otel_tag="promotion-${GITHUB_RUN_ID}-${GITHUB_RUN_ATTEMPT}-${otel_digest#sha256:}"
if mirrored_otel="$(
  docker buildx imagetools inspect "${otel_destination}:${otel_tag}" \
    --format '{{json .Manifest.Digest}}' 2>/dev/null | tr -d '"'
)"; then
  test "${mirrored_otel}" = "${otel_digest}"
else
  docker buildx imagetools create \
    --tag "${otel_destination}:${otel_tag}" \
    "${otel_source}@${otel_digest}"
fi
mirrored_otel="$(
  docker buildx imagetools inspect "${otel_destination}:${otel_tag}" \
    --format '{{json .Manifest.Digest}}' | tr -d '"'
)"
test "${mirrored_otel}" = "${otel_digest}"
