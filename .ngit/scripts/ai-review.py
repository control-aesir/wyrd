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
    - trigger_id from NGIT_CI_TRIGGER_EVENT (preferred, exact), plus fallbacks:
      GITHUB_EVENT_PATH (act payload), env file, git notes
    - head_sha from GITHUB_SHA (always set by coordinator)
    - head_ref from GITHUB_REF -> short branch name
    """
    trigger_id = os.environ.get("NGIT_CI_TRIGGER_EVENT", "").strip()
    if trigger_id and len(trigger_id) < 40:
        trigger_id = ""
    if not trigger_id:
        # try alternative name ngit-ci may inject (secret-style prefix scrubbing)
        trigger_id = os.environ.get("NGIT_CI_SECRET_NGIT_CI_TRIGGER_EVENT", "").strip() or trigger_id
    if not trigger_id:
        # try reading from GitHub event file (act writes it) — coordinator also embeds
        # NGIT_CI_* in job_env but act may not forward host env into the job container;
        # workflow-level env forwarding (see ai-review.yml) should fix it, but keep fallback.
        for path in [os.environ.get("GITHUB_EVENT_PATH", ""), "/github/workflow/event.json"]:
            if path and Path(path).exists():
                try:
                    data = json.loads(Path(path).read_text())
                    # coordinator's build_event_payload for pull_request does not embed trigger id,
                    # but keep parsing in case future protocol does
                    for key in ("ngit_trigger_event", "NGIT_CI_TRIGGER_EVENT", "trigger_event_id"):
                        if data.get(key):
                            cand = str(data[key]).strip()
                            if len(cand) >= 40:
                                trigger_id = cand
                                break
                    if trigger_id:
                        break
                except Exception:
                    pass
    if trigger_id and len(trigger_id) < 40:
        trigger_id = None
    if not trigger_id:
        trigger_id = None

    head_sha = os.environ.get("GITHUB_SHA", "").strip()
    if not head_sha:
        # fallback: current HEAD
        success, out = run_command(["git", "rev-parse", "HEAD"], check=False)
        if success and out:
            head_sha = out.strip()
    github_ref = os.environ.get("GITHUB_REF", "").strip()
    head_ref: Optional[str] = None
    if github_ref.startswith("refs/heads/"):
        head_ref = github_ref.removeprefix("refs/heads/")
    elif github_ref.startswith("refs/pull/"):
        head_ref = None
    elif github_ref:
        head_ref = github_ref

    if trigger_id and not head_ref:
        success, out = run_command(["ngit", "pr", "view", trigger_id, "--json"], check=False)
        if success and out:
            try:
                view = json.loads(out)
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

    ngit pr list --json does not expose commit SHAs, so we use the git
    branch relationship: if HEAD is on a branch, find the PR whose branch
    matches that branch (strips commit hash suffix from PR branch names).
    """
    # Step 1: Get all git branches that contain the commit
    success, output = run_command([
        "git", "branch", "--contains", head_sha,
        "--format", "%(refname:short)", "--all"
    ], check=False)
    if not success or not output:
        return None
    git_branches = [b.strip() for b in output.strip().split('\n') if b.strip()]
    if not git_branches:
        return None
    
    # Step 2: List all PRs
    success, pr_list_output = run_command(["ngit", "pr", "list", "--json"], check=False)
    if not success or not pr_list_output:
        return None
    try:
        prs = json.loads(pr_list_output)
    except json.JSONDecodeError:
        return None
    if not isinstance(prs, list):
        prs = [prs]

    # Step 3: Extract base branch name from PR branch field (e.g., "pr/epoch-escrow(e4259b79)" -> "pr/epoch-escrow")
    def extract_base_branch(pr_branch: str) -> str:
        if '(' in pr_branch:
            return pr_branch.split('(')[0].strip()
        return pr_branch

    # Step 4: Match PR branches with git branches
    for pr in prs:
        pr_branch = pr.get("branch", "")
        base_branch = extract_base_branch(pr_branch)
        
        if base_branch in git_branches:
            pr_id = pr.get("id") or pr.get("event_id")
            if pr_id:
                return str(pr_id)

    return None


def get_pr_diff(head_sha: str, head_ref: Optional[str]) -> Tuple[str, str]:
    """
    Get the diff for the PR as a merge-base diff (GitHub PR semantics).

    The ngit-ci runner checks out the PR head detached at GITHUB_SHA with
    depth=1. `git merge-base origin/master HEAD` therefore fails until we
    deepen. We try progressively: fetch master, deepen, unshallow, then fall
    back to HEAD~1 / show for orphan single-commit PRs.

    Returns (base_label, diff_text).
    """
    def try_diff(range_spec: str) -> Optional[str]:
        success, out = run_command(["git", "diff", range_spec], check=False)
        if success and out.strip():
            return out
        # also consider empty diff as valid (no changes) only if command succeeded and range exists
        if success:
            # check if range resolves
            success2, _ = run_command(["git", "rev-parse", "--verify", range_spec.split("...")[0].split("..")[0]], check=False)
            if success2:
                return out
        return None

    # Diagnostics for CI debug
    success, remotes = run_command(["git", "remote", "-v"], check=False)
    if success:
        print(f"git remotes: {remotes[:500]}", file=sys.stderr)

    # Ensure origin/master is present — try several fetch strategies
    # (origin may be nostr://, so some fetches fail; be permissive)
    base_rev = "origin/master"
    has_origin_master = False
    for fetch_cmd in [
        ["git", "fetch", "origin", "master:refs/remotes/origin/master", "--depth", "512"],
        ["git", "fetch", "origin", "refs/heads/master:refs/remotes/origin/master", "--depth", "512"],
        ["git", "fetch", "origin", "--depth", "512"],
        ["git", "fetch", "--depth", "512"],
    ]:
        success, _ = run_command(fetch_cmd, check=False)
        success2, _ = run_command(["git", "rev-parse", "--verify", "origin/master"], check=False)
        if success2:
            has_origin_master = True
            base_rev = "origin/master"
            break

    if not has_origin_master:
        success, _ = run_command(["git", "rev-parse", "--verify", "master"], check=False)
        if success:
            base_rev = "master"
        else:
            # last resort: try to discover default branch from origin HEAD
            success, out = run_command(["git", "remote", "set-head", "origin", "-a"], check=False)
            success, out = run_command(["git", "rev-parse", "--verify", "origin/HEAD"], check=False)
            if success:
                base_rev = "origin/HEAD"

    # Try to deepen history so merge-base can be found (256 is ngit-ci's PR_DIFF_HISTORY_DEPTH)
    # If repo is shallow, unshallow or deepen.
    is_shallow = Path(".git/shallow").exists()
    if is_shallow:
        run_command(["git", "fetch", "--unshallow"], check=False)
        run_command(["git", "fetch", "origin", "--depth", "512"], check=False)

    # Also ensure HEAD's history is deep enough
    run_command(["git", "fetch", "origin", head_sha, "--depth", "512"], check=False)

    merge_base: Optional[str] = None
    for base in [base_rev, "origin/master", "master", "origin/HEAD"]:
        success, out = run_command(["git", "merge-base", base, "HEAD"], check=False)
        if success and out.strip():
            merge_base = out.strip()
            base_rev = base
            print(f"merge-base {base}..HEAD = {merge_base[:12]}", file=sys.stderr)
            break
        else:
            print(f"no merge-base for {base}..HEAD: {out[:200] if out else 'empty'}", file=sys.stderr)

    if merge_base:
        diff = try_diff(f"{merge_base}..HEAD")
        if diff is not None:
            return (f"{merge_base[:12]}..HEAD", diff)

    # Fallbacks: direct three-dot, diff against base, HEAD parent
    for rng in [f"{base_rev}...HEAD", f"{base_rev}..HEAD", "HEAD~1..HEAD", "HEAD^..HEAD"]:
        diff = try_diff(rng)
        if diff is not None and diff.strip():
            return (rng, diff)

    # Single-commit PR or orphan: show the HEAD patch itself
    for cmd in [["git", "show", "--patch", "--format=", "HEAD"], ["git", "show", "HEAD"], ["git", "log", "-p", "-1", "HEAD"]]:
        success, out = run_command(cmd, check=False)
        if success and out.strip():
            return ("HEAD patch", out)

    # Last: name-only fallback
    success, out = run_command(["git", "diff", "--name-only", "HEAD~1", "HEAD"], check=False)
    if success and out.strip():
        return ("name-only", out)

    return (base_rev, "Unable to retrieve PR diff")


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
    # In act the checkout is in GITHUB_WORKSPACE; steps may run outside it
    ws = os.environ.get("GITHUB_WORKSPACE")
    if ws and Path(ws).exists():
        try:
            os.chdir(ws)
            print(f"Working directory: {ws}", file=sys.stderr)
        except Exception as e:
            print(f"chdir to GITHUB_WORKSPACE failed: {e}", file=sys.stderr)
    print("Starting AI code review (ngit version)...")
    print(f"pwd={Path.cwd()} GITHUB_WORKSPACE={ws}", file=sys.stderr)

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
