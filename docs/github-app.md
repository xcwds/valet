# Setting up the GitHub App

Valet acts on GitHub as one GitHub App (RFC decision 9). For each job it mints an installation
token narrowed to exactly the job's repositories and to its role's permissions, so even a token
that escaped Valet couldn't approve, merge or touch other repositories beyond what the role allows.

## 1. Create the App

In your account or organization: **Settings → Developer settings → GitHub Apps → New GitHub App**.

- **Webhook:** off. Valet doesn't receive events.
- **Repository permissions:** the union of what the roles need. With the default roles:

  | Permission    | Level        | Used by                       |
  | ------------- | ------------ | ----------------------------- |
  | Contents      | Read & write | implementer (read: reviewer)  |
  | Pull requests | Read & write | reviewer, implementer         |
  | Issues        | Read & write | triage                        |
  | Metadata      | Read         | everyone (GitHub requires it) |
  | Checks        | Read         | reviewer, implementer         |

  Grant nothing else. Never grant Administration: Valet refuses to request it, and the App doesn't
  need it.
- **Where can this App be installed:** only on this account.

Note the **App ID**, then **Generate a private key** and download the `.pem` file.

## 2. Install it

**Install App** → choose **Only select repositories** and pick the repositories agents may work
in. Note the **installation ID** from the URL of the installation's settings page
(`…/settings/installations/<id>`).

Every repository in a job must belong to the account the App is installed on; Valet refuses others,
so a job for `someone-else/site` can never become a token for your `site`.

## 3. Give Valet the key

The key goes into Valet's encrypted secret store, never into a config file:

```sh
valet secrets set github/app-key < my-app.private-key.pem
shred -u my-app.private-key.pem   # or keep it somewhere safe offline
```

## 4. Configure the connector

In the connectors file (`connectors:` in `valet.yaml`):

```yaml
github:
  app_id: "123456"
  installation_id: 7890123
  private_key_secret: github/app-key
  # api_url: https://github.example.com/api/v3   # GitHub Enterprise Server
  # git_url: https://github.example.com          # and where it serves git (default https://github.com)
  # permissions:        # per role; omitted means the defaults below
  #   reviewer:    { contents: read,  pull_requests: write, checks: read, metadata: read }
  #   implementer: { contents: write, pull_requests: write, checks: read, metadata: read }
  #   triage:      { issues: write, metadata: read }
```

A role not listed under `permissions` gets no GitHub token at all. Levels are `read` or `write`.

## 5. Protect your branches

Valet's policy is the first wall; GitHub's rulesets are the second (RFC decision 4). Apply and
check them with [github-rulesets.md](github-rulesets.md), and keep the App off every bypass list.

## How tokens behave

- Minted on a job's first GitHub action, cached for the job, refreshed five minutes before GitHub's
  one-hour expiry, never used past the job's end.
- Revoked on GitHub (`DELETE /installation/token`) as soon as the job is revoked.
- If GitHub ever returns more permissions or repositories than asked for, the token is revoked and
  refused.
- Failed mints back off per job (1 s doubling to 5 min), and a rate-limit answer from GitHub pauses
  every mint until GitHub says to retry, so an agent can't burn the App's quota through Valet.
