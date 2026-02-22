#!/usr/bin/env bash
set -euo pipefail

# ---- required env ----
: "${GH_REPO:?}"
: "${S3_BUCKET:?}"
: "${AWS_REGION:?}"
: "${CLOUDFRONT_DISTRIBUTION_ID:?}"
: "${PKG_NAME:?}"
: "${SUITE:?}"
: "${COMPONENT:?}"
: "${APT_GPG_PRIVATE_KEY:?}"

S3_PREFIX="${S3_PREFIX:-}"
if [[ -n "${S3_PREFIX}" && "${S3_PREFIX}" != */ ]]; then
  S3_PREFIX="${S3_PREFIX}/"
fi

WORKDIR="$(pwd)"
mkdir -p repo/apt assets build

download_asset() {
  local tag="$1"
  local pattern="$2"
  local attempts=12

  for attempt in $(seq 1 "${attempts}"); do
    if gh release download "${tag}" -R "${GH_REPO}" -p "${pattern}" -D assets; then
      return 0
    fi
    echo "Asset ${pattern} not available yet (attempt ${attempt}/${attempts}); retrying..."
    sleep 5
  done

  echo "ERROR: Failed to download asset ${pattern} for ${tag} after ${attempts} attempts"
  return 1
}

echo "${APT_GPG_PRIVATE_KEY}" | gpg --batch --import >/dev/null 2>&1 || true

KEYID="$(gpg --list-secret-keys --with-colons | awk -F: '$1=="sec"{print $5; exit}')"
if [[ -z "${KEYID}" ]]; then
  echo "ERROR: No GPG secret key available after import."
  exit 1
fi

# Determine which tags to process
TAGS=""
if [[ "${BACKFILL_ALL:-false}" == "true" ]]; then
  echo "Backfill mode: collecting all release tags..."
  TAGS="$(gh release list -R "${GH_REPO}" --limit 200 --json tagName --jq '.[].tagName')"
else
  if [[ -n "${INPUT_TAG:-}" ]]; then
    TAGS="${INPUT_TAG}"
  elif [[ -n "${EVENT_TAG:-}" ]]; then
    TAGS="${EVENT_TAG}"
  elif [[ -n "${PUSH_TAG:-}" ]]; then
    TAGS="${PUSH_TAG}"
  else
    echo "No tag provided; using latest release tag..."
    TAGS="$(gh release view -R "${GH_REPO}" --json tagName --jq '.tagName')"
  fi
fi

echo "Tags to process:"
printf '%s\n' "${TAGS}"

# Pull existing repo from S3 so we keep older versions
echo "Sync existing repo from S3..."
aws s3 sync "s3://${S3_BUCKET}/${S3_PREFIX}apt/" repo/apt/ >/dev/null 2>&1 || true

# Build and add packages
while IFS= read -r TAG; do
  [[ -z "${TAG}" ]] && continue
  echo "=== Processing tag: ${TAG} ==="

  rm -rf assets build
  mkdir -p assets build

  deb_amd64="${PKG_NAME}_${TAG}_amd64.deb"
  deb_arm64="${PKG_NAME}_${TAG}_arm64.deb"

  download_asset "${TAG}" "${deb_amd64}"
  download_asset "${TAG}" "${deb_arm64}"

  if [[ ! -f "assets/${deb_amd64}" ]]; then
    echo "ERROR: Missing release asset: ${deb_amd64}"
    exit 1
  fi
  if [[ ! -f "assets/${deb_arm64}" ]]; then
    echo "ERROR: Missing release asset: ${deb_arm64}"
    exit 1
  fi

  mkdir -p "repo/apt/pool/${COMPONENT}/${PKG_NAME:0:1}/${PKG_NAME}/"
  cp -v assets/*.deb "repo/apt/pool/${COMPONENT}/${PKG_NAME:0:1}/${PKG_NAME}/"

done <<< "${TAGS}"

# Regenerate metadata
cd repo/apt

for arch in amd64 arm64; do
  mkdir -p "dists/${SUITE}/${COMPONENT}/binary-${arch}"
  dpkg-scanpackages -a "${arch}" pool > "dists/${SUITE}/${COMPONENT}/binary-${arch}/Packages"
  gzip -fk "dists/${SUITE}/${COMPONENT}/binary-${arch}/Packages"
done

# Release file with hashes
cat > apt-ftparchive.conf <<EOF
APT::FTPArchive::Release::Origin "fosrl";
APT::FTPArchive::Release::Label "newt";
APT::FTPArchive::Release::Suite "${SUITE}";
APT::FTPArchive::Release::Codename "${SUITE}";
APT::FTPArchive::Release::Architectures "amd64 arm64";
APT::FTPArchive::Release::Components "${COMPONENT}";
APT::FTPArchive::Release::Description "Newt APT repository";
EOF

apt-ftparchive -c apt-ftparchive.conf release "dists/${SUITE}" > "dists/${SUITE}/Release"

# Sign Release
cd "dists/${SUITE}"

gpg --batch --yes --pinentry-mode loopback \
  ${APT_GPG_PASSPHRASE:+--passphrase "${APT_GPG_PASSPHRASE}"} \
  --local-user "${KEYID}" \
  --clearsign -o InRelease Release

gpg --batch --yes --pinentry-mode loopback \
  ${APT_GPG_PASSPHRASE:+--passphrase "${APT_GPG_PASSPHRASE}"} \
  --local-user "${KEYID}" \
  -abs -o Release.gpg Release

# Export public key into apt repo root
cd ../../..
gpg --batch --yes --armor --export "${KEYID}" > "${WORKDIR}/repo/apt/public.key"

# Upload to S3
echo "Uploading to S3..."
# Verify the S3 bucket exists and is accessible before attempting sync to give a clearer error
echo "Checking S3 bucket '${S3_BUCKET}' and prefix '${S3_PREFIX}apt/' accessibility using prefix-scoped ListObjectsV2..."
# Use list-objects-v2 scoped to the repo prefix. This works with IAM policies that grant s3:ListBucket with a prefix condition.
if ! aws s3api list-objects-v2 --bucket "${S3_BUCKET}" --prefix "${S3_PREFIX}apt/" --max-items 1 >/dev/null 2>&1; then
  if [[ "${CREATE_BUCKET:-false}" == "true" ]]; then
    echo "S3 bucket '${S3_BUCKET}' not found or inaccessible. CREATE_BUCKET=true so attempting to create it in region ${AWS_REGION}..."
    if [[ "${AWS_REGION}" == "us-east-1" ]]; then
      if ! aws s3api create-bucket --bucket "${S3_BUCKET}" --region "${AWS_REGION}"; then
        echo "ERROR: Failed to create S3 bucket ${S3_BUCKET} in ${AWS_REGION}."
        exit 1
      fi
    else
      if ! aws s3api create-bucket --bucket "${S3_BUCKET}" --region "${AWS_REGION}" --create-bucket-configuration LocationConstraint="${AWS_REGION}"; then
        echo "ERROR: Failed to create S3 bucket ${S3_BUCKET} in ${AWS_REGION} (LocationConstraint=${AWS_REGION})."
        exit 1
      fi
    fi

    echo "Waiting for bucket to become accessible..."
    tries=0
    until aws s3api list-objects-v2 --bucket "${S3_BUCKET}" --prefix "${S3_PREFIX}apt/" --max-items 1 >/dev/null 2>&1; do
      tries=$((tries+1))
      if [[ ${tries} -ge 10 ]]; then
        echo "ERROR: Bucket ${S3_BUCKET} still not accessible after creation attempts."
        exit 1
      fi
      sleep 2
    done
    echo "Bucket ${S3_BUCKET} is now accessible."
  else
    echo "ERROR: S3 bucket '${S3_BUCKET}' does not exist or is not accessible with the configured AWS credentials/role for the prefix '${S3_PREFIX}apt/'."
    echo "Your IAM policy must allow 's3:ListBucket' on arn:aws:s3:::${S3_BUCKET} with a condition like s3:prefix=['${S3_PREFIX}apt/*'] or broader."
    echo "If you prefer not to change IAM, you can create the bucket manually (example):"
    echo "  aws s3api create-bucket --bucket ${S3_BUCKET} --region ${AWS_REGION}"
    exit 1
  fi
fi

aws s3 sync "${WORKDIR}/repo/apt" "s3://${S3_BUCKET}/${S3_PREFIX}apt/" --delete

# Invalidate metadata
echo "CloudFront invalidation..."
if ! aws cloudfront get-distribution --id "${CLOUDFRONT_DISTRIBUTION_ID}" >/dev/null 2>&1; then
  echo "WARNING: CloudFront distribution '${CLOUDFRONT_DISTRIBUTION_ID}' not found or not accessible; skipping invalidation."
else
  aws cloudfront create-invalidation \
    --distribution-id "${CLOUDFRONT_DISTRIBUTION_ID}" \
    --paths "/${S3_PREFIX}apt/dists/*" "/${S3_PREFIX}apt/public.key"
fi

echo "Done. Repo base: ${REPO_BASE_URL}"
