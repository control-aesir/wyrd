#!/usr/bin/env python3
"""
AI Review Script for Wyrd Project (ngit/Nostr version)
Uses OpenRouter's free models to review PR changes via ngit commands
"""

import json
import os
import subprocess
import sys
import urllib.error
import urllib.request
from typing import Dict, List, Optional, Tuple


def run_command(cmd: List[str], check: bool = True) -> Tuple[bool, str]:
    """Run a command and return (success, output)"""
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, check=check)
        return (True, result.stdout.strip())
    except subprocess.CalledProcessError as e:
        return (False, e.stderr.strip() if e.stderr else str(e))


def get_pr_number_from_env() -> Optional[int]:
    """Get PR number from GitHub Actions environment if available"""
    pr_num = os.environ.get("GITHUB_EVENT_PULL_REQUEST_NUMBER")
    if pr_num and pr_num.isdigit():
        return int(pr_num)
    return None


def find_open_pr() -> Optional[Tuple[int, str, str]]:
    """Find the most recent open PR using ngit.

    Returns (pr_number, base_branch, head_branch) or None.
    """
    success, output = run_command(["ngit", "pr", "list", "--json", "--status", "open"], check=False)
    if not success or not output:
        return None

    try:
        prs = json.loads(output)
    except json.JSONDecodeError:
        return None

    if not isinstance(prs, list) or not prs:
        return None

    # Take the first (most recent) open PR
    pr = prs[0]
    pr_number = pr.get("number") or pr.get("id")

    if pr_number is None:
        return None

    # Try to get base and head branches from the PR view
    success, view_output = run_command(["ngit", "pr", "view", str(pr_number), "--json"], check=False)
    if not success:
        return None

    try:
        view = json.loads(view_output)
    except json.JSONDecodeError:
        return None

    # Extract base and head branch from PR metadata
    # ngit PRs with pr/ prefix have specific branch tracking
    base_branch = view.get("base_branch") or view.get("target") or "master"
    head_branch = view.get("head_branch") or view.get("source_branch") or ""

    # If we can't extract branches from ngit view, derive from PR number
    # ngit pr/ branches: the branch name itself contains the info
    if not head_branch:
        # Try to get from the PR's events/comments or use git
        head_branch = f"pr/{pr_number}"

    return (pr_number, str(base_branch), head_branch)


def get_pr_diff(pr_number: int, base_branch: str, head_branch: str) -> str:
    """Get the diff for a PR using ngit/git"""
    # Try ngit first - try to get diff between base and head
    success, output = run_command(
        ["git", "diff", f"{base_branch}...{head_branch}"], check=False
    )
    if success and output:
        return output

    # Fallback: git diff against master
    success, output = run_command(["git", "diff", "origin/master"], check=False)
    if success and output:
        return output

    # Try git diff with pr/ prefix
    success, output = run_command(
        ["git", "diff", f"master...pr/{pr_number}"], check=False
    )
    if success and output:
        return output

    return "Unable to retrieve PR diff"


def call_openrouter_api(prompt: str, api_key: str) -> Optional[str]:
    """Call OpenRouter API with a free model"""
    url = "https://openrouter.ai/api/v1/chat/completions"

    # Using a free model from OpenRouter - gemini-flash-1.5 is commonly available as free
    model = "google/gemini-flash-1.5"

    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json",
        "HTTP-Referer": "https://gitworkshop.dev/npub1k0y4eceal2zryes3azm6nsgt0r0jsa2v8zcsdf9uqxttn0jlfe9q04c9h8/grasp.t5.st/wyrd",
        "X-Title": "Wyrd AI Review"
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
Focus on the most important issues first. Be concise but thorough."""
            },
            {
                "role": "user",
                "content": prompt
            }
        ],
        "temperature": 0.2,
        "max_tokens": 2000
    }

    req = urllib.request.Request(url, data=json.dumps(data).encode('utf-8'), headers=headers)

    try:
        with urllib.request.urlopen(req, timeout=30) as response:
            result = json.loads(response.read().decode('utf-8'))
            return result['choices'][0]['message']['content']
    except urllib.error.HTTPError as e:
        error_body = e.read().decode('utf-8') if e.read() else "No error details"
        print(f"OpenRouter API error {e.code}: {error_body}", file=sys.stderr)
        return None
    except Exception as e:
        print(f"Error calling OpenRouter API: {str(e)}", file=sys.stderr)
        return None


def post_pr_comment(pr_id: str, comment: str) -> bool:
    """Post a comment on the PR using ngit"""
    success, output = run_command(
        ["ngit", "pr", "comment", pr_id, "--body", comment], check=False
    )
    return success


def main():
    """Main function"""
    print("Starting AI code review (ngit version)...")

    # Get OpenRouter API key from environment
    api_key = os.environ.get("OPENROUTER_API_KEY")
    if not api_key:
        print("Error: OPENROUTER_API_KEY environment variable not set", file=sys.stderr)
        sys.exit(1)

    # Try to get PR number from GitHub Actions env first
    pr_number = get_pr_number_from_env()

    # If not in GitHub env, find the open PR using ngit
    if pr_number is None:
        result = find_open_pr()
        if result is None:
            print("Error: Could not determine PR number. Set OPENROUTER_API_KEY and either:")
            print("  1. Set GITHUB_EVENT_PULL_REQUEST_NUMBER env var, or")
            print("  2. Run with ngit open PRs available")
            sys.exit(1)
        pr_number, base_branch, head_branch = result
        print(f"Found open PR #{pr_number} (base={base_branch}, head={head_branch})")
    else:
        # Get branch info using ngit
        success, view_output = run_command(["ngit", "pr", "view", str(pr_number), "--json"], check=False)
        if success:
            try:
                view = json.loads(view_output)
                base_branch = view.get("base_branch", "master")
                head_branch = view.get("head_branch", f"pr/{pr_number}")
            except json.JSONDecodeError:
                base_branch = "master"
                head_branch = f"pr/{pr_number}"
        else:
            base_branch = "master"
            head_branch = f"pr/{pr_number}"

    # Get PR diff
    diff = get_pr_diff(pr_number, base_branch, head_branch)
    if not diff or diff == "Unable to retrieve PR diff":
        print("Warning: Could not retrieve PR diff. Review may be limited.", file=sys.stderr)
        diff = "[Diff unavailable]"
    else:
        print(f"Retrieved PR diff ({len(diff)} chars)")

    # Load project context
    try:
        with open("/home/thomas/workspace/control/wyrd/docs/architecture.md", "r") as f:
            architecture_content = f.read()
        context = architecture_content[:500] + "..." if len(architecture_content) > 500 else architecture_content
    except Exception:
        context = "Wyrd: Decentralized, append-only, content-addressed drive system"

    # Construct prompt for AI
    prompt = f"""
PROJECT CONTEXT:
{context}

PR #{pr_number} CHANGES (base: {base_branch}, head: {head_branch}):
{diff}

Please review these changes for the Wyrd project. Focus on:
1. Correctness and adherence to project invariants (see architecture.md)
2. Security considerations (cryptographic safety, data validation)
3. Performance implications
4. Clarity and maintainability
5. Alignment with the project's architectural principles

Provide specific, actionable feedback in GitHub-flavored markdown format.
"""

    # Call OpenRouter API
    print("Calling OpenRouter API for review...")
    review = call_openrouter_api(prompt, api_key)

    if not review:
        print("Error: Failed to get review from OpenRouter", file=sys.stderr)
        sys.exit(1)

    # Output review
    print("\n=== AI REVIEW ===")
    print(review)
    print("=== END REVIEW ===\n")

    # Post comment using ngit if we have a PR ID
    ngit_pr_id = str(pr_number)

    if os.environ.get("GITHUB_ACTIONS") == "true":
        print("Posting review as PR comment via ngit...")
        comment = f"""## AI Code Review

{review}

---
*This review was generated by AI using OpenRouter's free models. Please review carefully and use your judgment.*"""

        if post_pr_comment(ngit_pr_id, comment):
            print("Successfully posted review as PR comment via ngit")
        else:
            print("Warning: Failed to post PR comment via ngit", file=sys.stderr)

    print("AI review completed")


if __name__ == "__main__":
    main()