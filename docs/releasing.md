# Release maintenance

This page is for maintainers, not installation. Users should follow
[Install and maintain](installation.md).

## Acceptance before 0.9.0

Keep the repository private until the operator explicitly accepts the release
candidate. Passing CI or a clean security review does not grant that approval.

1. Freeze the exact source commit and run the complete test gate, four-platform
   container builds, and a fresh adversarial review of that exact change.
2. Resolve actionable findings. Record the tested source SHA, commands and
   review scope; absence of findings is not a security guarantee.
3. Present the candidate for operator-controlled checks in
   [Compatibility](compatibility.md#operator-controlled-checks). Keep health,
   Network acceptance and physical shutdown evidence separate. Do not restart
   infrastructure or run power tests as part of an automated release check.
4. Obtain explicit GO for release and public visibility. If required repository
   policies cannot be enabled while private, stop for that separate decision;
   never weaken or bypass the release controller to make it pass.

Only after that approval, perform the policy setup below. A token stored as an
Actions secret is not evidence that its permissions or repository policies are
correct; the controller rechecks them.

## Maintainer release gate

Do not create the version tag or a GitHub Release by hand. Before dispatching
the release controller:

1. Make the repository and its GHCR package public.
2. Enable immutable GitHub Releases.
3. Protect `main`, then create one active tag ruleset named
   `N2U release tags`, targeting exactly `refs/tags/v*`, with only update and
   deletion restricted and an empty bypass list. Creation stays available so
   the workflow can use GitHub's atomic create-ref operation; once created, a
   version tag cannot be moved or removed. Emergency recovery requires an
   explicit, audited ruleset change rather than a standing bypass.
4. Require full commit-SHA pinning for Actions and keep the default
   `GITHUB_TOKEN` permission read-only.
5. Store a repository-scoped, read-only fine-grained token as
   `N2U_RELEASE_POLICY_TOKEN`. It needs Administration read and Contents read
   access so the controller can verify policy; it must have no write permission.
   GitHub does not expose private drafts to this read-only credential. Draft
   listing, inspection and mutation use the ephemeral `GITHUB_TOKEN` only in
   the reservation, binding and finalization jobs, which already need
   `contents: write`. Never widen the PAT to work around draft visibility.
6. Archive and remove every still-rerunnable historical tagged workflow that
   had package-write authority but predates this controller.
7. Confirm the reviewed source is the live `main` tip and that the requested
   version has no tag, draft, or published Release. Also confirm that no
   unexpected collaborator, installed GitHub App, writable deploy key,
   workflow, or package ACL has release authority.

Run **Publish container** manually from `main` and provide the exact SemVer tag,
such as `v0.9.0`. The controller first reserves the version with a protected
tag, creates its owned draft, publishes a uniquely named permanent OCI
retention anchor, binds its digest and attestation to the numeric reservation,
uploads an exact asset set, and only then publishes the immutable Release. It
never publishes a `:0.9.0` image alias.

The read-only preflight checks policy, source and tag absence, not private-draft
absence. The reservation job definitively checks draft absence with its writer
token immediately before tag creation. The image job checks policy and the
protected source tag before building, then verifies the image and attestation;
it has no repository-write permission or private-draft access. If the draft is
deleted or changed during the build, a run-specific image/attestation can remain,
but the binding job rejects the changed numeric draft before any Release update.

Never rerun all, failed, or individual jobs from a release run. Every release
job requires attempt one and matching upstream outputs. If anything fails after
reservation, inspect the monotonic external state and normally use a new
version; cleanup or manual continuation needs its own reviewed procedure. After
success, verify that the Git tag, source SHA, image digest, attestation,
retention anchor, release marker, bundle `.env`, assets, and checksums agree.

Keep `main` and all manual GitHub Release and GHCR writes frozen while the
controller is running. The controller requires the source to remain the live
`main` tip at every state transition. GitHub documents no conditional update
for the final draft-to-publish PATCH, so the controller cannot make that
boundary atomic against another authorized writer. It serializes its own
release runs, overwrites every expected mutable field during publication, and
validates the exact response and immutable readback; an independently
authorized concurrent writer remains part of the release trust boundary.

### Explicit recovery of an unpublished empty reservation

This is an operator-approved maintenance procedure, not a workflow retry or an
automatic cleanup path. Never apply it to a published Release or a reservation
with assets or an OCI publication. Preserve the failed run as an audit record.

1. Fix and review the cause first. Obtain explicit owner approval to recover
   the specific version, including draft/tag deletion. Freeze other writers.
2. Record the failed run and attempt, numeric draft ID, exact reservation body,
   source SHA, tag object and current tag ruleset. Re-read all of them immediately
   before mutation. Require an unpublished, empty draft, an exact lightweight
   source tag and no image under that run's OCI anchor.
3. Delete only that numeric draft. Temporarily exclude only its exact tag ref
   from the existing tag ruleset, delete only that tag, and restore the exact
   original ruleset immediately, including on failure. Do not disable protection
   globally, add a standing bypass or delete the failed run.
4. Read back the restored policy and absence of both draft and tag. If any
   result is ambiguous, stop and inspect; do not repeat a destructive call.
5. Once the corrected exact `main` has passed all gates, dispatch a new run with
   attempt one. Let it create the version afresh; never move or recreate the tag
   by hand, reuse the old draft or resume the old workflow's outputs.

## Pinned toolchains

The Buildx version and binary checksum and the BuildKit image digest in
`.github/actions/setup-pinned-buildx/action.yml` form one reviewed toolchain
unit. Update and verify all three together, then update the exact regression
constants in `internal/buildtest/buildx_test.go`; never substitute a moving tag
or a checksum downloaded at workflow runtime. The release SBOM generator is a
fourth content-addressed toolchain input enforced in the same test. Every
`push: true` build must remain explicitly cache-cold and must not import or
export a remote build cache; CI-only non-publishing builds may use their
separate cache.

The pinned attestation action reads the default Docker credential path rather
than `DOCKER_CONFIG`. A CI-only bridge validates and temporarily places only the
job's GHCR credential there, preserving the original credential-free config.
The bridge is checked before the image build. After attestation, on success or
failure, it restores the exact previous file (or removes only its newly created
file), scrubs the isolated publication credential, and verifies the pinned
Buildx plugin remains available. Cleanup failure blocks further verification or
publication. A killed/canceled hosted runner relies on ephemeral runner teardown.
No token grants, runtime dependencies or gateway behavior change.

The release attestation verifier is a separate pinned toolchain: its GitHub CLI
version/archive checksum and the Sigstore Public Good trusted-root source,
raw checksum, and compact-JSONL checksum must change together with their
regression constants. Never fall back to the runner's unpinned `gh`, fetch live
TUF metadata, or expose a GitHub token to the offline verification step.

## Deployment bundle contract

The release assets are named `nut-2-unifi-ups-gateway-vVERSION-compose.tar.gz`
and `nut-2-unifi-ups-gateway-vVERSION-compose.SHA256SUMS`. The archive contains
one versioned root with only `.env`, `compose.yaml`, `compose.auth.yaml` and
`RELEASE-METADATA.txt`. Both Linux and Synology use this same bundle.

Templates live in `deploy/compose`. Keep the project name and named state volume
stable. Review any template change together with its exact releaseguard hashes,
generated environment expectation, workflow paths, mutation tests and user
instructions. Do not replace verification with filename or substring checks.

The `edge` image is a development output from `main`, not a release candidate's
immutable identity. Retain the exact manifest digest and source SHA when asking
an operator to validate a private candidate. No tag, Release, visibility change,
production restart or deployment is implied by publishing an edge build.
