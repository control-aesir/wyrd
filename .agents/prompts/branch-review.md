# Full branch code review compared to master, posts to PR

Current branch:!`git branch --show-current`
PR info:!`ngit pr list --json --offline`
Recent commits (master..HEAD):!`git log master..HEAD --oneline`
Diff stats:!`git diff master..HEAD --stat`

### Code quality checks:
!`cargo check 2>&1`
!`cargo test 2>&1`
!`cargo clippy 2>&1`

## **Your task:** 
1. Analyze the above information and produce a comprehensive code review covering:
   - Overall assessment
   - Potential bugs/edge cases
   - Code quality (style, readability, maintainability)
   - Test coverage observations
   - Clippy warnings/suggestions
   - Performance considerations
   - Specific improvements with file:line references

2. **After writing the review**, post it as a PR comment:
   - Extract the PR `id` (nevent1...) from the PR info JSON where `branch` contains the current branch name
   - Run: `ngit pr comment <PR_ID> --body "$(cat <<'EOF'\n<your-review-text>\nEOF\n)" --json`
   
   Use the bash tool to execute this. The review should be well-formatted markdown.

Be constructive and specific. Reference actual files and line numbers. Do not impersonate the user and make clear where the review comes from.
