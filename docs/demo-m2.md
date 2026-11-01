# M2 demo: an implementer agent with zero GitHub credentials

The milestone's claim, shown live: an agent in a container with **no GitHub credential** clones a
repository, fixes a bug, pushes its own branch and opens a pull request, all through Valet, and
anything outside its job is refused by Valet and, failing that, by GitHub.

The same scenarios run in CI against a fake GitHub (`e2e/implementer_test.go`) and the deployment
(`deploy/smoke.sh`); this is the run against the real thing.

## Setup

- **Sandbox repository:** [xcwds/valet-sandbox](https://github.com/xcwds/valet-sandbox), with
  `.github/CODEOWNERS`, a buggy `src/greet.sh`, its task list in `src/TODO.md`, and Valet's
  devcontainer in `.devcontainer/`.
- **Rulesets** applied and checked with your own `gh` login ([github-rulesets.md](github-rulesets.md)):

  ```sh
  deploy/github/apply.sh xcwds/valet-sandbox
  deploy/github/check.sh xcwds/valet-sandbox --app-id <app id>
  ```

- **The GitHub App** ([github-app.md](github-app.md)), installed on the sandbox only. Its key is in
  Valet's secret store, never a file Valet reads:

  ```sh
  docker compose -f deploy/compose.yaml exec -T valet valet secrets set github/app-key < app.private-key.pem
  ```

- **Valet** running with `deploy/compose.yaml` ([deploy.md](deploy.md)), and `deploy/connectors.yaml`
  set to the App:

  ```yaml
  github:
    app_id: "<app id>"
    installation_id: <installation id>
    private_key_secret: github/app-key
  ```

## Run

1. **Start a job** from a checkout of the sandbox:

   ```sh
   path/to/valet/deploy/devcontainer/new-job.sh implementer xcwds/valet-sandbox --ttl 2h
   ```

2. **Reopen in Container** (within ten minutes). `valet-setup` enrolls the container and routes
   git, HTTPS and MCP through Valet.

3. **No credentials in the container.** From the host, run the check inside it:

   ```sh
   docker exec -i -u vscode <container> bash -s < path/to/valet/e2e/live/no-creds.sh
   ```

   It checks the environment (every process's), git config with origins, credential files, and
   files under `$HOME`, `/workspaces`, `/tmp`, `/etc`, `/run`, `/opt`, `/usr/local` for GitHub's
   token formats, and must end with `No GitHub credential found.` Valet's own session token is
   expected and only reported.

4. **The task.** In the container, ask Claude Code:

   > Fix the bug described in src/TODO.md. Commit, push to your agent branch, and open a pull
   > request against main.

   Expected: it pushes `agent/<job-id>/…` and opens the pull request with `github_pr_create`.
   Nothing on GitHub was done with anything but the job's installation token, narrowed to
   `xcwds/valet-sandbox` with `contents: write, pull_requests: write, checks: read`.

5. **Refusals.** In the container's terminal:

   ```sh
   git push origin HEAD:main                         # refused: implementer/push-elsewhere
   git push origin HEAD:refs/heads/agent/job-other/x  # refused: another job's branch
   git clone https://github.com/xcwds/valet          # refused: outside the job (403)
   curl -sS https://github.com                       # refused by Charon (403); no route otherwise
   ```

   Each is denied by Valet before GitHub sees it, audited, and alerted.

6. **The second wall** (optional). Show GitHub refusing what a policy bug would let through: start
   valetd with a policy file whose implementer role allows `git.push` to `main`, push again, and
   GitHub's ruleset refuses it (`GH013: Repository rule violations`). Restore the default policy
   afterwards.

7. **On the host:** the trail and its integrity.

   ```sh
   valet audit tail --job <job-id> -n 100
   valet audit verify
   ```

8. **Revoke** the job and show its token refused on MCP, git and egress:

   ```sh
   valet job revoke <job-id> --reason "demo over"
   ```

Then the pull request waits for your review: the App can't approve or merge it.

## Recorded run

_To be filled in from the live run: the commands above with their output, the pull request's
link, and the `no-creds` result._
