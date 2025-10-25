# Weekly Release Plan

This document defines a simple, predictable weekly release cadence for NULLA testnet. Each weekly release bundles fixes for bugs discovered in the previous week.

Repository facts:
- Language: Rust (primary)
- Build toolchain: cargo

## Goals
- Deliver fixes reliably every week.
- Keep scope small, predictable, and low-risk.
- Ensure quality through automation, review, and clear cut-off times.
- Keep users informed with consistent release notes.

## Cadence and Scope
- Cadence: Weekly, released every Friday at 16:00 UTC.
- Scope: Bug fixes triaged from the previous calendar week only.
  - Example: Release on Friday of Week W contains fixes for bugs reported/triaged during Week W-1.
- Exceptions:
  - Critical regressions may trigger an out-of-band hotfix (see “Hotfix Procedure”).

## Weekly Timeline (Default)
- Monday
  - Triage and prioritize bugs from the previous week (W-1).
  - Create or update the weekly milestone.
  - Assign issues, confirm acceptance criteria, and estimate effort.
- Tuesday–Thursday
  - Implement and review fixes.
- Thursday 18:00 UTC (Code Freeze)
  - All fixes intended for this week must be merged.
  - Cut a release candidate tag: vX.Y.Z-rc.1 on the release branch.
  
- Friday
  - If RC is stable, finalize the release:
    - Bump version to vX.Y.Z.
    - Tag and push.
    - Publish GitHub Release with notes.
    - Optional: publish crate/binaries if applicable.
  - If blockers are found, either:
    - Cut rc.2 and slip within the same day, or
    - Defer to next Friday release.

## Versioning and Branching
- Versioning: Semantic Versioning.
  - Weekly releases typically increment the patch version (e.g., 0.2.5 → 0.2.6).
  - If public API or user-facing breaking changes are introduced (rare for a bugfix cadence), increment MAJOR or MINOR accordingly.
- Branching:
  - main: always releasable.
  - release/*: optional short-lived branches when stabilizing a weekly release (e.g., release/0.2.6).
  - hotfix/*: used for urgent out-of-band fixes.


## Rollback Plan
- If a release causes critical issues:
  - Revert to the previous known-good tag while investigating.
  - Publish a short advisory and ETA for a fix or re-release.
  - Track a postmortem issue with root cause and preventive actions.



Questions or exceptions should be raised during Monday triage to minimize risk and maintain the weekly cadence.
