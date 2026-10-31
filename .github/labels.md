# Issue labels

Valet uses the same label set as xcwds/xcwds and xcwds/xcwds.github.io, so one routine can rank
work across all three. Agents can't define labels, but adding a label that a repo doesn't have
creates it with a grey color and no description; the owner then sets the color and description from
the tables below. Never invent labels outside this file.

Every open issue gets one type label, and one priority label unless it is `tracking`. Add `needs
decision` when it applies. Renovate's "Dependency Dashboard" issue gets no labels.

## Type

| Label           | Use for                                                            |
| --------------- | ------------------------------------------------------------------ |
| `bug`           | Something that exists and behaves wrongly                          |
| `enhancement`   | A new feature, tool, recipe or improvement                         |
| `documentation` | Docs, READMEs, comments and contributor notes only                 |
| `security`      | Credential exposure, policy bypass, audit gaps, data leaks          |
| `accessibility` | A barrier for people using assistive tech, keyboards or large text |
| `tooling`       | CI, build, release workflows, dependencies and test infrastructure |

An issue can carry more than one type (`bug` + `security`) when both are true.

## Priority

| Label                | Meaning                                                                       |
| -------------------- | ----------------------------------------------------------------------------- |
| `priority: critical` | A credential leak, a policy bypass, data loss, or Valet broken for all         |
| `priority: high`     | Broken behavior people hit, or it blocks other planned work                   |
| `priority: medium`   | Correctness edge cases and meaningful improvements                            |
| `priority: low`      | Nits, docs, polish and nice-to-haves                                          |

The "Issue to PR" routine works the highest priority first and breaks ties toward the smaller,
older issue.

## Status

| Label            | Meaning                                                                             |
| ---------------- | ----------------------------------------------------------------------------------- |
| `needs decision` | The owner must choose something first (open questions, proposals, RFC choices)      |
| `tracking`       | An epic, plan or umbrella issue; the work happens in its sub-issues, so no priority |

Automated issue work skips `needs decision` and `tracking` issues. Remove `needs decision` once the
issue records the owner's answer.

## Set by people

`human requested`, `refinement requested`, `answered in comments`, `branding`, `good first issue`,
`help wanted`, `question`, `duplicate`, `invalid` and `wontfix` are applied by people. Agents never
add them and never remove them, except `refinement requested` and `answered in comments` as below.
Read `human requested` as a sign the owner cares about the issue.

## Refinement

`refinement requested` asks for an issue to be turned into something ready to build. The labeling
routine refines at most 2 per run, oldest first. Refining means:

- Rewrite the body into a scoped spec in the style of the repo's planned issues: the goal, what the
  user gets, how it fits the existing code (name the files, packages or plugins), privacy and
  storage notes, acceptance criteria and tests, and what's out of scope. Follow the repo's CLAUDE.md
  and the RFC. Keep the owner's own words in a final "Original request" section.
- Split an issue too big for one PR into sub-issues (each refined the same way) and make it
  `tracking`.
- Review the result for completeness and correctness before saving, and fix what that finds.
- Questions only the owner can answer go in an "Open questions" section with a recommended answer for
  each, and the issue gets `needs decision`.
- Then remove `refinement requested`, set the type and priority, and leave one comment summarising
  what changed. The owner adds the label again to ask for another pass.

## Answered in comments

`answered in comments` means the owner answered an issue's open questions in a comment. The labeling
routine handles it alongside refinement (the 2-per-run limit covers both): move the answers into
the body's "Decisions" section (quoting the owner's choice, dated), drop answered questions from
"Open questions", remove `needs decision` when none are left, then remove `answered in comments`.
If the body already records the answers, only remove the label.
