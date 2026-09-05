# ngit templates

Reusable templates for the contribution workflow.

## Available templates

| File         | Use when                                                                                             |
| ------------ | ---------------------------------------------------------------------------------------------------- |
| `feature.md` | A planned, multi-step change with design/spec impact — the default shape for anything that will become a PR. |

## Usage

```bash
ngit issue create \
  --subject "<type>(<scope>): <summary>" \
  --label enhancement \
  --body "$(cat .ngit/templates/feature.md)"
```

Then replace every `{{...}}` placeholder before running — `ngit` will publish
the body as-is to the relay. The `<!-- ... -->` header docstring records when
to use the template and is hidden by most renderers.

## Conventions

- Templates contain **only `{{...}}` placeholders** for repo-specific content;
  the surrounding scaffolding stays the same across uses.
- Reference issues from PRs as `nostr:nevent1...` URIs (never raw hex IDs) per
  the ngit skill rules.
- Keep templates in sync with the contribution workflow in `AGENTS.md`: any
  change to the required issue shape should be reflected here in the same PR.
