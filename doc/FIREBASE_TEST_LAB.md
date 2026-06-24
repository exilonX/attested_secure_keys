# Firebase Test Lab — CI setup

`.github/workflows/device-tests.yml` runs the example's `integration_test` suite
on **real Android devices** (the only way to exercise StrongBox / TEE / key
attestation — emulators report `software`/`none`). It authenticates to Google
Cloud with **Workload Identity Federation** (keyless) and a dedicated service
account, then calls `gcloud firebase test android run`.

This is the exact, working setup (the values below are for
`exilonX/attested_secure_keys` + GCP project `attested--keys`, project number
`95648027328` — substitute your own).

## 0. Cost

Test Lab has a **free daily quota: 30 min/day on physical devices** (Spark plan,
no card). Our run uses ~2–6 device-minutes, so it's effectively free. Programmatic
CI access generally needs **billing enabled (Blaze)** — there's no base fee, and
you stay inside the free quota, so set a **budget alert** (e.g. $1) and expect ~$0.
Physical-device overage is **$5/device-hour**.

## 1. Enable the APIs

```bash
gcloud config set project attested--keys
gcloud services enable \
  testing.googleapis.com \
  toolresults.googleapis.com \
  iamcredentials.googleapis.com \
  sts.googleapis.com
```

> `iamcredentials` + `sts` are required for WIF impersonation. Skipping them
> fails the test step (not the auth step) with `IAM Service Account Credentials
> API has not been used…` — confusing, because auth itself looks green.

## 2. Service account + roles

```bash
gcloud iam service-accounts create ftl-ci --display-name="Firebase Test Lab CI"
SA="ftl-ci@attested--keys.iam.gserviceaccount.com"
gcloud projects add-iam-policy-binding attested--keys --member="serviceAccount:$SA" --role="roles/cloudtestservice.testAdmin"
gcloud projects add-iam-policy-binding attested--keys --member="serviceAccount:$SA" --role="roles/serviceusage.serviceUsageConsumer"
```

## 3. Results bucket (you must own it)

Test Lab's **default** results bucket (`test-lab-<hash>`) is **Google-managed** —
a custom service account gets `storage.objects.create denied` on it, and you
can't grant access (you don't own it). So create your own and let the SA write:

```bash
gcloud storage buckets create gs://ftl-results-95648027328 --location=US --project=attested--keys
gcloud storage buckets add-iam-policy-binding gs://ftl-results-95648027328 \
  --member="serviceAccount:$SA" --role="roles/storage.objectAdmin"
```

The workflow passes this via the `GCP_RESULTS_BUCKET` repo variable
(`--results-bucket`).

## 4. Workload Identity Federation (keyless), scoped to this repo

```bash
PROJECT_NUMBER=$(gcloud projects describe attested--keys --format='value(projectNumber)')
gcloud iam workload-identity-pools create github --location=global || true
gcloud iam workload-identity-pools providers create-oidc github-provider \
  --location=global --workload-identity-pool=github \
  --issuer-uri="https://token.actions.githubusercontent.com" \
  --attribute-mapping="google.subject=assertion.sub,attribute.repository=assertion.repository" \
  --attribute-condition="assertion.repository=='exilonX/attested_secure_keys'"
gcloud iam service-accounts add-iam-policy-binding "$SA" \
  --role=roles/iam.workloadIdentityUser \
  --member="principalSet://iam.googleapis.com/projects/${PROJECT_NUMBER}/locations/global/workloadIdentityPools/github/attribute.repository/exilonX/attested_secure_keys"
```

## 5. GitHub repo Variables

**Settings → Secrets and variables → Actions → `Variables`** (not Secrets — the
workflow reads them as `${{ vars.* }}`):

| Variable | Value |
|---|---|
| `GCP_PROJECT_ID` | `attested--keys` |
| `GCP_SERVICE_ACCOUNT` | `ftl-ci@attested--keys.iam.gserviceaccount.com` |
| `GCP_WIF_PROVIDER` | `projects/95648027328/locations/global/workloadIdentityPools/github/providers/github-provider` |
| `GCP_RESULTS_BUCKET` | `ftl-results-95648027328` |

## 6. Run it

- **Actions → "Device tests (Firebase Test Lab)" → Run workflow** (on `main`), or
- label a PR `device-tests`, or
- wait for the nightly cron.

Results (logs, video, the JUnit XML) land in `gs://ftl-results-95648027328` and in
the Firebase console → Test Lab.

## Gotchas we hit (in order)

1. `./gradlew: No such file or directory` — the Gradle wrapper was gitignored;
   it's now committed (LF + executable, see `example/android/.gitattributes`).
2. Variables added under **Secrets** instead of **Variables** → `vars.*` empty.
3. `iamcredentials`/`sts` APIs not enabled → impersonation 403 at the test step.
4. `storage.objects.create denied` on the managed default bucket → use your own
   `--results-bucket`.
5. Billing not enabled → `billing account … is disabled` on bucket create / runs.
   Link an OPEN billing account (Blaze); stays ~$0 inside the free quota.
6. `--use-orchestrator` → "Test timed out": the Android Test Orchestrator is
   incompatible with Flutter's single-pass `integration_test`. Removed it.
7. Invalid device combo (`panther`/34 → "Incompatible device/OS combination") →
   use combos from `gcloud firebase test android models list`.
