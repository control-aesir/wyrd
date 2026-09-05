#!/usr/bin/env python3
"""
AI Review Script for Wyrd Project (ngit/Nostr version)
Uses OpenRouter's free models to review PR changes via ngit commands.

Runs inside ngit-ci on a pull_request trigger. The coordinator sets
(see ngit-ci/src/runner/mod.rs: job_env + build_event_payload):
  - NGIT_CI_TRIGGER_EVENT  hex event id of the 1618/1619 that triggered the run
  - GITHUB_SHA             trigger commit
  - GITHUB_REF             refs/heads/<branch> (PR head) or refs/pull/ngit
  - NGIT_CI_REPOSITORY     30617 coordinate
and an act payload with pull_request.head.sha/ref but no number/base.

We resolve the exact PR via NGIT_CI_TRIGGER_EVENT instead of
`ngit pr list --status open` (which would pick the wrong concurrent PR)
and diff via merge-base against the target default branch.
"""

import json
import os
import subprocess
import sys
import urllib.error
import urllib.request
from pathlib import Path
from typing import Dict, List, Optional, Tuple


def run_command(cmd: List[str], check: bool = True) -> Tuple[bool, str]:
    """Run a command and return (success, output)."""
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, check=check)
        return (True, result.stdout.strip())
    except subprocess.CalledProcessError as e:
        return (False, (e.stderr.strip() if e.stderr else str(e)))


def get_trigger_context() -> Tuple[Optional[str], str, Optional[str]]:
    """
    Resolve the PR trigger.

    Returns (trigger_id_hex or None, head_sha, head_ref_short or None).
    - trigger_id from NGIT_CI_TRIGGER_EVENT (preferred, exact)
    - head_sha from GITHUB_SHA (always set by coordinator)
    - head_ref from GITHUB_REF -> short branch name
    """
    trigger_id = os.environ.get("NGIT_CI_TRIGGER_EVENT")
    # ngit-ci also sets NGIT_CI_TRIGGER_EVENT via job_env; act payload is deeper
    if trigger_id:
        trigger_id = trigger_id.strip()
        if len(trigger_id) < 40:  # sanity: hex
            trigger_id = None

    head_sha = os.environ.get("GITHUB_SHA", "").strip()
    github_ref = os.environ.get("GITHUB_REF", "").strip()
    head_ref: Optional[str] = None
    if github_ref.startswith("refs/heads/"):
        head_ref = github_ref.removeprefix("refs/heads/")
    elif github_ref.startswith("refs/pull/"):
        # fallback set by ngit-ci when no branch-name tag (1619 inherited)
        head_ref = None
    elif github_ref:
        head_ref = github_ref

    # Also try to hydrate branch via ngit pr view when trigger_id is known
    # (covers 1619 events with no branch-name tag; the view still knows head)
    if trigger_id and not head_ref:
        success, out = run_command(["ngit", "pr", "view", trigger_id, "--json"], check=False)
        if success and out:
            try:
                view = json.loads(out)
                # ngit pr view shape varies by version; try several keys
                candidate = (
                    view.get("head_branch")
                    or view.get("source_branch")
                    or view.get("branch")
                    or (view.get("head") or {}).get("ref")
                )
                if candidate:
                    head_ref = str(candidate).removeprefix("refs/heads/")
            except json.JSONDecodeError:
                pass

    return (trigger_id, head_sha, head_ref)


def find_fallback_pr_via_list(head_sha: str) -> Optional[str]:
    """
    Last-resort: find a PR whose head matches GITHUB_SHA.
    Only used when NGIT_CI_TRIGGER_EVENT is absent (local manual runs).
    """
    success, output = run_command(["ngit", "pr", "list", "--json"], check=False)
    if not success or not output:
        return None
    try:
        prs = json.loads(output)
    except json.JSONDecodeError:
        return None
    if not isinstance(prs, list):
        prs = [prs]
    for pr in prs:
        # ngit pr list entries may expose commit or head sha under various keys
        for key in ("commit", "head", "head_sha", "sha", "tip"):
            val = pr.get(key)
            if isinstance(val, str) and val.startswith(head_sha[:12]):
                # prefer event id
                return pr.get("id") or pr.get("event_id") or pr.get("nevent") or str(pr.get("number") or "")
        # also check nested view if needed
        pr_id = pr.get("id") or pr.get("event_id")
        if pr_id and head_sha:
            success, view_out = run_command(["ngit", "pr", "view", str(pr_id), "--json"], check=False)
            if success:
                try:
                    v = json.loads(view_out)
                    if head_sha[:12] in json.dumps(v):
                        return str(pr_id)
                except json.JSONDecodeError:
                    pass
    return None


def get_pr_diff(head_sha: str, head_ref: Optional[str]) -> Tuple[str, str]:
    """
    Get the diff for the PR as a merge-base diff (GitHub PR semantics).

    Strategy:
      1. Ensure origin/master is present (fetch shallow).
      2. Compute merge-base between HEAD (== GITHUB_SHA checkout) and origin/master.
      3. git diff merge-base...HEAD (two-dot via explicit merge-base equals three-dot).

    Returns (base_label, diff_text).
    """
    # Ensure we have a remote
    run_command(["git", "remote", "get-url", "origin"], check=False)

    # Try to ensure origin/master exists; tolerate already-fetched
    # In CI checkout is at detached HEAD == head_sha, with origin pointing at clone URL.
    for fetch_cmd in [
        ["git", "fetch", "origin", "master", "--depth", "256"],
        ["git", "fetch", "origin", "refs/heads/master:refs/remotes/origin/master", "--depth", "256"],
    ]:
        success, _ = run_command(fetch_cmd, check=False)
        if success:
            break

    # Determine base oid via merge-base, fallback to origin/master directly
    base_rev = "origin/master"
    success, out = run_command(["git", "rev-parse", "--verify", "origin/master"], check=False)
    if not success:
        # try master without origin prefix (local)
        success2, _ = run_command(["git", "rev-parse", "--verify", "master"], check=False)
        if success2:
            base_rev = "master"

    # Prefer merge-base for accurate PR diff; fallback to direct diff against base
    merge_base: Optional[str] = None
    success, out = run_command(["git", "merge-base", base_rev, "HEAD"], check=False)
    if success and out:
        merge_base = out.strip()
    else:
        # deepening fallback: fetch more history
        run_command(["git", "fetch", "origin", "--depth", "512"], check=False)
        success, out = run_command(["git", "merge-base", base_rev, "HEAD"], check=False)
        if success and out:
            merge_base = out.strip()

    diff_range = f"{merge_base}...HEAD" if merge_base else f"{base_rev}...HEAD"
    success, diff = run_command(["git", "diff", diff_range], check=False)
    if success and diff:
        return (diff_range, diff)

    # Last fallbacks for shallow/orphan PRs
    for fallback_range in ["origin/master...HEAD", "master...HEAD", "origin/master", "HEAD~1...HEAD"]:
        success, diff = run_command(["git", "diff", fallback_range], check=False)
        if success and diff:
            return (fallback_range, diff)

    # Absolute last: show head commit alone
    success, diff = run_command(["git", "show", "--format=", "HEAD"], check=False)
    if success and diff:
        return ("HEAD", diff)

    return (diff_range, "Unable to retrieve PR diff")


def call_openrouter_api(prompt: str, api_key: str) -> Optional[str]:
    """Call OpenRouter API with a free model."""
    url = "https://openrouter.ai/api/v1/chat/completions"
    model = "openrouter/free"
    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json",
        "HTTP-Referer": "https://gitworkshop.dev/npub1k0y4eceal2zryes3azm6nsgt0r0jsa2v8zcsdf9uqxttn0jlfe9q04c9h8/grasp.t5.st/wyrd",
        "X-Title": "Wyrd AI Review",
    }
    data = {
        "model": model,
        "messages": [
            {
                "role": "system",
                "content": """You are an expert code reviewer for the Wyrd project, a decentralized, append-only, content-addressed drive system.
Review the provided code changes with focus on:
1. Correctness and adherence to project invariants
2. Security considerations (cryptographic safety, data validation)
3. Performance implications
4. Clarity and maintainability
5. Alignment with the project's architectural principles

Provide specific, actionable feedback. If changes are good, say so. If there are issues, explain them clearly.
Focus on the most important issues first. Be concise but thorough.""",
            },
            {"role": "user", "content": prompt},
        ],
        "temperature": 0.2,
        "max_tokens": 2000,
    }
    req = urllib.request.Request(url, data=json.dumps(data).encode("utf-8"), headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=30) as response:
            result = json.loads(response.read().decode("utf-8"))
            return result["choices"][0]["message"]["content"]
    except urllib.error.HTTPError as e:
        try:
            body = e.read().decode("utf-8")
        except Exception:
            body = "No error details"
        print(f"OpenRouter API error {e.code}: {body}", file=sys.stderr)
        return None
    except Exception as e:
        print(f"Error calling OpenRouter API: {str(e)}", file=sys.stderr)
        return None


def post_pr_comment(pr_id: str, comment: str) -> bool:
    """Post a comment on the PR using ngit (id = event id hex or nevent)."""
    # ngit pr comment <ID> --body <BODY>  (see `ngit pr comment --help`)
    success, output = run_command(["ngit", "pr", "comment", pr_id, "--body", comment], check=False)
    if not success:
        print(f"ngit pr comment failed: {output}", file=sys.stderr)
    return success


def main():
    print("Starting AI code review (ngit version)...")

    api_key = os.environ.get("OPENROUTER_API_KEY")
    if not api_key:
        print("Error: OPENROUTER_API_KEY environment variable not set", file=sys.stderr)
        sys.exit(1)

    trigger_id, head_sha, head_ref = get_trigger_context()

    # Fallback for local runs without coordinator env
    if not trigger_id and head_sha:
        trigger_id = find_fallback_pr_via_list(head_sha)

    if not head_sha:
        print("Error: GITHUB_SHA not set — are you running inside ngit-ci?", file=sys.stderr)
        print("Hint: locally set GITHUB_SHA=$(git rev-parse HEAD) and NGIT_CI_TRIGGER_EVENT=<pr-event-id>", file=sys.stderr)
        sys.exit(1)

    if trigger_id:
        print(f"Trigger PR event: {trigger_id}  head={head_ref or '(no branch)'}  sha={head_sha[:12]}")
    else:
        print(f"No NGIT_CI_TRIGGER_EVENT — running in fallback mode  head={head_ref or '(no branch)'}  sha={head_sha[:12]}")

    # Get PR diff via merge-base semantics
    diff_range, diff = get_pr_diff(head_sha, head_ref)
    if not diff or diff == "Unable to retrieve PR diff":
        print(f"Warning: Could not retrieve PR diff for range {diff_range}. Review may be limited.", file=sys.stderr)
        diff = "[Diff unavailable]"
    else:
        print(f"Retrieved PR diff via {diff_range} ({len(diff)} chars)")

    # Load project context relative to checkout (not hardcoded /home/thomas/...)
    # Workflow cwd is the repo checkout after `actions/checkout`.
    context = "Wyrd: Decentralized, append-only, content-addressed drive system"
    for candidate in [
        Path("docs/architecture.md"),
        Path(".ngit/docs/architecture.md"),
        Path("/home/thomas/workspace/control/wyrd/docs/architecture.md"),
    ]:
        try:
            if candidate.exists():
                text = candidate.read_text()
                context = (text[:800] + "...") if len(text) > 800 else text
                break
        except Exception:
            pass

    label = f"{trigger_id[:12] if trigger_id else head_sha[:12]}"
    prompt = f"""
PROJECT CONTEXT:
{context}

PR {label} CHANGES (base: origin/master, range: {diff_range}, head: {head_ref or head_sha}):
{diff}

Please review these changes for the Wyrd project. Focus on:
1. Correctness and adherence to project invariants (see architecture.md)
2. Security considerations (cryptographic safety, data validation)
3. Performance implications
4. Clarity and maintainability
5. Alignment with the project's architectural principles

Provide specific, actionable feedback in GitHub-flavored markdown format.
"""

    print("Calling OpenRouter API for review...")
    review = call_openrouter_api(prompt, api_key)
    if not review:
        print("Error: Failed to get review from OpenRouter", file=sys.stderr)
        sys.exit(1)

    print("\n=== AI REVIEW ===")
    print(review)
    print("=== END REVIEW ===\n")

    # Post comment if we have a PR identity and an NSEC (coordinator injects NGIT_NSEC via secrets)
    # Don't gate on GITHUB_ACTIONS — ngit-ci/act may not set it; gate on presence of nsec instead.
    nsec_available = bool(os.environ.get("NGIT_NSEC") or os.environ.get("NSEC") or os.environ.get("NGIT_CI_SECRET_NGIT_NSEC"))
    if trigger_id and nsec_available:
        print(f"Posting review as PR comment via ngit pr comment {trigger_id[:12]}...")
        comment = f"""## AI Code Review

{review}

---
*This review was generated by AI using OpenRouter's free models. Please review carefully and use your judgment.*"""
        if post_pr_comment(trigger_id, comment):
            print("Successfully posted review as PR comment via ngit")
        else:
            print("Warning: Failed to post PR comment via ngit (check NGIT_NSEC and relay connectivity)", file=sys.stderr)
    elif trigger_id:
        print("Skipping PR comment: NGIT_NSEC/NSEC not set (secret only available on maintainer-authored PRs)", file=sys.stderr)
        print("To enable comments, provision NGIT_NSEC as a per-repo secret for this coordinate.", file=sys.stderr)
    else:
        print("Skipping PR comment: no trigger PR id resolved", file=sys.stderr)

    print("AI review completed")


if __name__ == "__main__":
    main()
