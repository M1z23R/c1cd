# C1CD - CI/CD Webhook Listener

A simple webhook listener that triggers local commands when receiving webhooks from GitLab or GitHub.

## Setup

### GitLab Personal Access Token

1. Go to [GitLab Personal Access Tokens](https://gitlab.com/-/profile/personal_access_tokens)
2. Create a new token with these scopes:
   - `api` - Full access to the API
   - `read_api` - Read access to the API
   - `read_repository` - Read access to repositories

### GitHub Personal Access Token

1. Go to [GitHub Personal Access Tokens](https://github.com/settings/tokens)
2. Click "Generate new token" → "Generate new token (classic)"
3. Select these permissions:

**Repository permissions (required):**
- `repo` - Full control of private repositories
  - OR just `public_repo` if you only need access to public repositories
- `admin:repo_hook` - Full control of repository hooks
  - This includes `write:repo_hook` and `read:repo_hook`

**User permissions (required):**
- `user:email` - Access to user email addresses (for authentication)

**Optional permissions:**
- `read:org` - Read org and team membership (if working with organization repos)

### Alternative Minimal GitHub Setup

If you want minimal permissions, you can use:
- `public_repo` - Access to public repositories
- `admin:repo_hook` - Manage repository webhooks  
- `user:email` - Access user email

## Usage

### Add Authentication Token

```bash
# Interactive mode - will prompt for provider and token
./c1cd --pat
# or
./c1cd --login
# or  
./c1cd --auth
```

### Create Webhook Job

```bash
# Interactive mode - will prompt for provider selection and token
./c1cd
```

### Run Service

```bash
./c1cd --service
```

## Environment Variables

- `C1CD_PORT` - Port for webhook listener (default: 9091)

## Webhook Endpoints

- GitLab: `http://your-server:9091/gitlab/webhook`
- GitHub: `http://your-server:9091/github/webhook`

## Config File

Configuration is stored in `~/.config/c1cd/config.json`

### Structure

```json
{
  "tokens": {
    "gitlab": [
      {
        "token": "glpat-xxxxxxxxxxxxxxxxxxxx", 
        "username": "your-username",
        "user_id": 12345
      }
    ],
    "github": [
      {
        "token": "ghp_xxxxxxxxxxxxxxxxxxxx",
        "username": "your-username", 
        "user_id": 67890
      }
    ]
  },
  "jobs": [
    {
      "provider": "github",
      "project_id": 123456789,
      "project_name": "owner/repo-name",
      "workspace": "/path/to/local/repo",
      "event": "on_push",
      "branches": ["main", "develop"],
      "commands": ["npm test", "npm run build"],
      "webhook_url": "http://your-server:9091/github/webhook",
      "enable_ssl_verification": true,
      "secret": "webhook-secret-token"
    }
  ]
}
```

## Supported Events

### GitLab
- `on_push` - Push events
- `on_merge_request` - Merge request events  
- `on_tag` - Tag push events
- `on_issue` - Issue events
- `on_note` - Note/comment events
- `on_job` - Job events
- `on_pipeline` - Pipeline events
- `on_wiki_page` - Wiki page events
- `on_release` - Release events
- `on_confidential_issue` - Confidential issue events
- `on_confidential_note` - Confidential note events

### GitHub
- `on_push` - Push events
- `on_pull_request` - Pull request events
- `on_release` - Release events  
- `on_issue` - Issue events
- `on_tag` - Tag/release creation events

## Security Notes

- Webhook secrets are automatically generated and used for validation
- Keep your personal access tokens secure
- Use HTTPS in production environments
- Review webhook payload permissions carefully