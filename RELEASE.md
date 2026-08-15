# Stable Release Playbook

This is the canonical, repeatable procedure for a public GlobalPlatform release.
It covers the upstream project, documentation, Windows signing and SDK artifacts,
the vcpkg registry and consumer, and the Homebrew tap. Read it before changing
release packaging, versioning, signing, or release documentation.

The Git tag names the GPShell release. The C library and PC/SC plugin use their
own ABI-derived versions; do not assume that all of their versions match the tag.

## Release Inputs And Approval Gates

Set the release tag once and use it consistently:

```sh
export TAG=3.0.0
```

Before proceeding, record the commit that will be released and confirm each
explicit gate with the release owner:

1. The release commit and its final version numbers are approved.
2. The stable tag may be pushed.
3. Each production SignPath request may be approved in the SignPath UI.
4. The GitHub release, vcpkg registry update, and Homebrew bottles may be made public.

Do not create a stable tag, submit or approve production signing, or publish a
release merely because a release candidate passed. Never put secrets, real card
keys, or production certificates in the repository or workflow logs.

## 1. Prepare The Release Commit

1. Start from the intended current upstream branch and inspect the worktree:

   ```sh
   git fetch origin
   git status --short
   git log --oneline --decorate -10
   ```

   Preserve unrelated local work. Release only deliberate, reviewed changes.

2. Update all relevant versions and release notes. At minimum, inspect these
   independent version sources:

   - `CMakeLists.txt`: `GPSHELL_VERSION`, which drives release artifact names.
   - `gpshell/CMakeLists.txt`: the GPShell ABI version (`CURRENT`, `REVISION`,
     and `AGE`).
   - `globalplatform/CMakeLists.txt`: the library ABI version.
   - `gppcscconnectionplugin/CMakeLists.txt`: the plugin ABI version.
   - `NEWS` and `gpshell/NEWS`: user-visible library and shell changes.

   Use the project ABI/versioning policy when changing library versions. Do not
   force a library package version to match a GPShell tag when their ABI versions
   differ.

3. Update documentation that describes user-visible changes:

   - Keep `gpshell/src/gpshell3.1.md` in sync with `gpshell3`; keep the legacy
     `gpshell/src/gpshell.1.md` in sync with `gpshell`.
   - Update the Jekyll site in `docs/`: features, supported workflows, download
     guidance, and funding/support links. GPShell3 is the preferred manual, but
     both manuals must be linked.
   - Keep the support text current when applicable:

     ```text
     Consulting for GlobalPlatform integration, smart-card deployment, and secure channel workflows is available at gpshell@ik.me.
     ```

   - Verify README links, API links, GitHub Sponsors, Patreon, and FLOSS Fund
     metadata when those public pages changed. A third-party directory re-crawl
     is not a reason to block an otherwise ready release.

4. Regenerate and review the public Doxygen API documentation. `docs/api/` is
   generated output that is deliberately committed for a release:

   ```sh
   cmake -S . -B out/build/release-docs \
     -DCMAKE_BUILD_TYPE=Release \
     -DTOOLS=OFF \
     -DGLOBALPLATFORM_BUILD_DOCS=ON
   cmake --build out/build/release-docs --target globalplatform-doc
   test -s out/build/release-docs/globalplatform/doc/html/index.html
   rsync -a --delete out/build/release-docs/globalplatform/doc/html/ docs/api/
   ```

   Review the API landing page and ensure no unintended generated churn is being
   committed.

5. Build and run the non-card test suite. A standard release check is:

   ```sh
   cmake --preset with-tests
   cmake --build out/build/with-tests
   ctest --test-dir out/build/with-tests -LE integration --output-on-failure
   ```

   Do not run card-backed integration tests or authentication examples unless
   the release owner has explicitly confirmed the reader, card, keys, and
   protocol. Failed mutual authentication can lock a card.

6. Review the diff, commit the release preparation, and push it for review:

   ```sh
   git diff --check
   git diff --cached --check
   git status --short
   ```

## 2. Test The Release Candidate

Use `.github/workflows/package-gpshell.yml` as the authoritative packaging
definition. Dispatch it manually from the release commit before tagging. A
branch/manual run uses `test-signing`; it must complete before the stable tag
is approved.

Verify every workflow job, including Linux, macOS, Windows static and dynamic
packages, and both Windows SDK architectures. Download and inspect the emitted
artifacts, especially:

- Windows static and dynamic MSI, MSIX, and ZIP artifacts where applicable.
- `globalplatform-sdk-<version>-windows-x86.zip` and `-x64.zip`.
- The shared SDK layout: headers, CMake package files, import library
  (`globalplatform.lib`), runtime DLLs, and a non-empty `doc/html/index.html`.

The dynamic Windows SDK deliberately contains `globalplatform.lib` for linking
and `globalplatform.dll` for runtime loading. It does not need `zlib.lib`:
consumers link GlobalPlatform, while its runtime dependencies are distributed
as DLLs. Do not add an unnecessary zlib import library to the SDK.

### SignPath Test Configuration

The regular GPShell Windows request signs the packaged executables and DLLs.
The SDK requests must use the artifact-configuration slug `SDK-only`, for both
x86 and x64 SDK jobs. `SDK-only` is version-agnostic and should select archive
members with wildcards rather than a versioned ZIP filename.

Keep XML include patterns aligned with the actual files packaged by CPack. The
OpenSSL runtime names may use wildcards such as `libcrypto-3*.dll` and
`libssl-3*.dll`; `zlib.dll` must match the current dependency filename. An
artifact configuration fails if any exact include cannot be found.

## 3. Create And Sign The Stable Core Release

After the explicit tag approval, create an annotated stable tag with no
prerelease suffix and push it:

```sh
git tag -a "$TAG" -m "Release $TAG"
git push origin "$TAG"
```

Do not use `tagGit.sh` for a release tag: it deletes tags before recreating
them. Correct an accidental tag only with an explicit, coordinated decision.

The tag push starts `package-gpshell.yml`. A tag without `-` selects
`release-signing`; tags such as `3.1.0-beta.1` and manual runs select
`test-signing`. Production requests require manual SignPath approval. Expect
three separately approvable production request groups:

1. Standard GPShell Windows packages.
2. Windows SDK x86, with artifact configuration `SDK-only`.
3. Windows SDK x64, with artifact configuration `SDK-only`.

For MSIX, the package publisher must match the production certificate subject.
The workflow sets the production publisher for stable tags; do not substitute a
test publisher in a production run.

Monitor the run and SignPath requests until completion:

```sh
gh run list --workflow package-gpshell.yml --limit 10
gh run view <run-id>
gh release view "$TAG"
```

Verify the published GitHub release is neither draft nor prerelease and that it
contains the expected Linux, macOS, Windows GPShell, x86/x64 SDK, and
`SHA256SUMS` assets. Download the assets and validate checksums before declaring
the core release complete:

```sh
gh release download "$TAG" -D out/release-verify
(cd out/release-verify && sha256sum -c SHA256SUMS --ignore-missing)
```

## 4. Publish The vcpkg Registry And Test A Consumer

Use the adjacent registry checkout at
`/home/widerstand/Projekte/globalplatform-vcpkg-registry` and the consumer at
`/home/widerstand/Projekte/globalplatform-consumer`. Confirm their remotes and
default branches before editing them. Before dispatching a registry or consumer
workflow, inspect its latest run and make sure its configured runner is still
available; renew, re-enable, or replace an expired/offline runner first.

1. In the registry, update `ports/globalplatform/portfile.cmake` so `REF`
   names the final upstream tag. Update `ports/globalplatform/vcpkg.json` using
   the library package version, not automatically the GPShell tag.
2. Follow vcpkg versioning rules: a new upstream source version gets a reset
   `port-version`; a port-only packaging fix increments `port-version`.
3. Run or review `.github/workflows/update-registry.yml`. It retrieves the
   archive, updates the SHA512 and runs `vcpkg x-add-version`; inspect the
   resulting `versions/baseline.json` and `versions/g-/globalplatform.json`.
   Commit and push the registry update.
4. In the consumer, update the custom-registry `baseline` in
   `vcpkg-configuration.json` to the committed registry baseline. Commit and
   push it, then trigger or monitor the consumer CI.
5. Require green consumer jobs on Linux, macOS, and Windows. They must build
   and run the CMake consumer test against the registry package without a real
   card. Record the registry and consumer commit IDs and run URLs.

The vcpkg port intentionally validates the ordinary package integration. It is
not a substitute for checking the shared Windows SDK ZIP.

## 5. Publish Homebrew Bottles

Use `/home/widerstand/Projekte/homebrew-globalplatform`. Its Formula source tag
must be the already-published core tag before the bottle workflow starts.

1. Update and review `Formula/globalplatform.rb`: the source `tag` must equal
   the upstream tag; do not change the formula version only to mimic unrelated
   library ABI numbers.
2. Run the tap's manual `release bottles` workflow from the intended branch.
   For the final release, set `package_version` and `release_tag` consistently
   and set `prerelease` to `false`. A temporary-branch prerelease run is useful
   for validating bottle generation before the final run.
   A Formula-only repair that reuses the same upstream source tag must use a
   Homebrew revision such as `3.0.0_1` for both values.
3. On Linux, Homebrew bottles must use the distribution PC/SC client and must
   not have a Homebrew `pcsc-lite` RPATH. Validate this with `ldd` and `readelf`;
   do not use card-facing commands in the bottle workflow.
4. The workflow creates bottle hashes, commits the Formula update, pushes the
   selected branch, tags `release_tag`, and creates the tap release. Review the
   generated commit, tag, release state, bottle URLs, and macOS/Linux tests.
5. Install or test the final formula on a supported platform when possible.
   Record the tap commit, workflow run, and release URL.

## 6. Verify Documentation And Close Out

After the release documentation commit has reached the branch used by GitHub
Pages, wait for a successful Pages build. Confirm all public pages load:

```sh
curl -fL https://kaoh.github.io/globalplatform/
curl -fL https://kaoh.github.io/globalplatform/api/index.html
```

Check that GPShell3 is presented as preferred, the legacy GPShell manual remains
available, the Features list matches the release notes and `gpshell3.1.md`, and
funding/support links point to the intended public destinations.

Create a short release record in the release discussion or project notes with:

- upstream commit, tag, workflow run, and GitHub release URL;
- three production SignPath approval/result references;
- vcpkg registry commit and consumer CI run;
- Homebrew commit, tag, and bottle release URL; and
- GitHub Pages build and API page verification.

Only close release-tracking issues and pull requests after the relevant artifact
or publication has been verified. Leave external-directory synchronization work
open if it depends on a third party.
