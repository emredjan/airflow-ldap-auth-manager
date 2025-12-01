> [!NOTE]
> The code in this repository is written with the help of AI (specifically, ChatGPT 5), including this README (lazy, I know). Although I tried my best to streamline and validate most of it, there may still be some intricacies that need to be sorted out.

# Airflow LDAP Auth Manager

A drop-in **Auth Manager** for **Apache Airflow 3.x** that authenticates users against **LDAP/Active Directory** and maps LDAP groups to Airflow roles (**admin / editor / viewer**). It supports redundant LDAP servers, secure transport (LDAPS or StartTLS), and secret indirection for bind credentials via Airflow’s **Secrets Backend** (Variables).

## Features

- **LDAP/AD authentication** using [`ldap3`](https://ldap3.readthedocs.io/)
- **Group → role mapping** (admin > editor > viewer)
- **Redundancy & failover** via `ldap3.ServerPool` (ROUND_ROBIN by default)
- **TLS: LDAPS or StartTLS** (with certificate verification)
- **Secrets-friendly config:** `bind_dn_secret` and `bind_password_secret` read from Airflow Variables (resolved through your configured secrets backend)
- **Clean Airflow 3 API:** uses the Airflow SDK (`airflow.sdk.*`)
- **Simple login UI** with configurable instance name and login tip
- **Helpful logging:** logs which LDAP server the connection bound to

## To-do

- [x] Extend the user & group search base config items to allow multiple entries (or LDAP `OR` syntax)
- [x] Package this and upload to pypi

## Requirements

- **Python:** 3.12+
- **Airflow:** 3.1+ (Auth Manager interface & SDK)
- **Libraries:** `ldap3`, `fastapi`, `jinja2` (`fastapi` & `jinja2` is likely installed already as Airflow dependencies)
- **Optional (recommended):** a Secrets Backend (Vault, AWS Secrets Manager, GCP SM, Azure KV) configured for Airflow Variables

## Installation

Install from PyPi into the environment where Airflow is installed:

```shell
pip install airflow-ldap-auth-manager
```


Or install after cloning the project:

```shell
git clone <repo url>
cd airflow-ldap-auth-manager
pip install .
```

## Configure Airflow

Changes needed in `airflow.cfg`:

### Enable the Auth Manager

```ini
[core]
# Fully qualified path to the auth manager class in this repo
auth_manager = airflow_ldap_auth_manager.LDAPAuthManager
```


### Make sure JWT settings are configured correctly

```ini
[api_auth]
jwt_secret = # Needs to be set
jwt_algorithm = # Either leave empty, or make sure consistent across all machines
jwt_audience = # Either leave empty, or make sure consistent across all machines
jwt_issuer = # Either leave empty, or make sure consistent across all machines
```

### LDAP settings

Add a section for the LDAP auth manager (adjust to your environment):

```ini
[ldap_auth_manager]
server_uri = ldaps://ldap1.example.com:636,ldaps://ldap2.example.com:636
bind_dn =
bind_password =
bind_dn_secret = secret/path/to/airflow/variable/for/bind_dn
bind_password_secret = path/to/airflow/variable/for/bind_password
user_search_base = OU=Users,DC=company_name
user_search_filter = (|(uid={username})(sAMAccountName={username})(mail={username}))
group_search_base = OU=Groups,DC=company_name
group_member_attr = member
admin_groups = airflow-admins
editor_groups = airflow-editors
viewer_groups = airflow-viewers,airflow-auditors
username_attr = uid
email_attr = mail
start_tls = false
verify_ssl = true
post_login_redirect = /
logout_redirect = /
debug_logging = false
```

Environment variable overrides are supported in the standard Airflow fashion, e.g.:`

`AIRFLOW__LDAP_AUTH_MANAGER__BIND_DN_SECRET=api_server/ldap_auth_manager/bind_dn`


### Branding & login hint (optional)

```ini
[api]
# Human-friendly name for titles/headers on the login page
instance_name = Company Airflow

[ldap_auth_manager]
# Optional helper text shown under "Sign in"
login_tip = Using your Company credentials
```

Restart the api-server after changes.

## Configuration reference

``` ini
[ldap_auth_manager]
# LDAP authentication/authorization settings for LDAPAuthManager.
# This section supports multiple redundant servers, secure transport (LDAPS or StartTLS),
# and secret indirection for bind credentials via Airflow’s Secrets Backend.

# Comma-separated list of LDAP server URIs.
# - Supports ldap:// and ldaps:// schemes.
# - When multiple URIs are provided, the manager builds an ldap3 ServerPool with ROUND_ROBIN
#   strategy for load distribution and failover.
# - For ldaps://, TLS is implicit from connect; for ldap:// + start_tls=true, StartTLS is
#   negotiated before bind.
# - Mixing ldaps:// with start_tls=true is not meaningful; prefer one approach.
#
# Variable: AIRFLOW__LDAP_AUTH_MANAGER__SERVER_URI
#
server_uri = ldaps://ldap1.example.com:636,ldaps://ldap2.example.com:636

# Name of the Airflow Variable that contains the LDAP bind DN (service account).
# The Variable is resolved through the configured Secrets Backend (e.g. Vault, AWS SM, etc.).
# If set, any plaintext `bind_dn` value is ignored. Leave empty to attempt anonymous bind.
# Remember: This needs to be set in the "Airflow/Variables" section in your secret manager,
# NOT "Airflow/Config"!
#
# Variable: AIRFLOW__LDAP_AUTH_MANAGER__BIND_DN_SECRET
#
bind_dn_secret = secret/path/to/airflow/variable/for/bind_dn
bind_dn =

# Name of the Airflow Variable that contains the LDAP bind password (service account).
# The Variable is resolved through the configured Secrets Backend.
# If set, any plaintext `bind_password` value is ignored.
# Remember: This needs to be set in the "Airflow/Variables" section in your secret manager,
# NOT "Airflow/Config"!
#
# Variable: AIRFLOW__LDAP_AUTH_MANAGER__BIND_PASSWORD_SECRET
#
bind_password_secret = path/to/airflow/variable/for/bind_password
bind_password =

# Base DN under which user entries are searched.
# Example (Active Directory): OU=Users,OU=Country,DC=example,DC=com
# Supports multiple base DNs, separated by newlines, semicolons, or as a JSON array.
#
# Variable: AIRFLOW__LDAP_AUTH_MANAGER__USER_SEARCH_BASE
#
user_search_base = OU=Users,DC=company_name

# LDAP filter template to locate the authenticating user.
# The literal "{username}" placeholder is replaced with the submitted login identifier.
# Must be a valid RFC 4515 filter. The username value is safely escaped before substitution.
# Example: (|(uid={username})(sAMAccountName={username})(mail={username}))
#
# Variable: AIRFLOW__LDAP_AUTH_MANAGER__USER_SEARCH_FILTER
#
user_search_filter = (|(uid={username})(sAMAccountName={username})(mail={username}))

# Base DN under which group entries are searched for authorization.
#
# Variable: AIRFLOW__LDAP_AUTH_MANAGER__GROUP_SEARCH_BASE
#
group_search_base = OU=Groups,DC=company_name

# The group attribute that lists membership (DNs of user entries).
# Common values:
#   - Active Directory: member
#   - RFC2307/posix groups: memberUid (then matching is by username instead of DN)
#
# Variable: AIRFLOW__LDAP_AUTH_MANAGER__GROUP_MEMBER_ATTR
#
group_member_attr = member

# Comma-separated list of groups that grant the Airflow "admin" role.
# Values can be group CNs or full DNs under group_search_base (matching is case-insensitive).
#
# Variable: AIRFLOW__LDAP_AUTH_MANAGER__ADMIN_GROUPS
#
admin_groups = airflow-admins


# Comma-separated list of groups that grant the Airflow "editor" role.
# Leave empty to disable this mapping.
#
# Variable: AIRFLOW__LDAP_AUTH_MANAGER__EDITOR_GROUPS
#
editor_groups = airflow-editors

# Comma-separated list of groups that grant the Airflow "viewer" role.
# Users are mapped to the highest role matched (admin > editor > viewer).
#
# Variable: AIRFLOW__LDAP_AUTH_MANAGER__VIEWER_GROUPS
#
viewer_groups = airflow-viewers,airflow-auditors

# Attribute on the user entry to use as the Airflow username.
# Typical values: uid, sAMAccountName, userPrincipalName
#
# Variable: AIRFLOW__LDAP_AUTH_MANAGER__USERNAME_ATTR
#
username_attr = uid

# Attribute on the user entry that contains the email address.
# Typical values: mail, userPrincipalName
#
# Variable: AIRFLOW__LDAP_AUTH_MANAGER__EMAIL_ATTR
#
email_attr = mail

# Whether to perform StartTLS on ldap:// connections before bind.
# - true  : Use StartTLS (only applies to ldap:// URIs).
# - false : Do not use StartTLS. For ldaps:// URIs, TLS is already implicit.
#
# Variable: AIRFLOW__LDAP_AUTH_MANAGER__START_TLS
#
start_tls = false

# Whether to verify the server certificate for TLS (ldaps or StartTLS).
# Set to true in production with a valid trust store. Set to false only for testing.
#
# Variable: AIRFLOW__LDAP_AUTH_MANAGER__VERIFY_SSL
#
verify_ssl = true

# Path (relative to the Airflow web root) to redirect a user after successful login.
# Example: "/" or "/home"
#
# Variable: AIRFLOW__LDAP_AUTH_MANAGER__POST_LOGIN_REDIRECT
#
post_login_redirect = /

# Path (relative to the Airflow web root) to redirect a user after logout.
# Example: "/" or "/login"
#
# Variable: AIRFLOW__LDAP_AUTH_MANAGER__LOGOUT_REDIRECT
#
logout_redirect = /

# Enable debug logging for LDAP operations.
# This can be useful to troubleshoot LDAP issues, but beware that it may log
# sensitive information such as usernames and group names.
#
# Variable: AIRFLOW__LDAP_AUTH_MANAGER__DEBUG_LOGGING
#
debug_logging = false

# Optional login hint shown under "Sign in". Leave empty to hide.
#
# Variable: AIRFLOW__LDAP_AUTH_MANAGER__LOGIN_TIP
#
login_tip = Using your Company credentials
```


## UI & templates

- Login template: `ldap_login.html`
- Static assets are served under `/auth/static/` (e.g. `/auth/static/style.css`, `/auth/static/airflow.svg`)
- Form posts to `/auth/token`

If you see 404 Not Found for `/auth/static/...`, ensure the StaticFiles mount path in your FastAPI router matches the URLs used in the template.

## Logging & diagnostics

If `debug_logging = true` in config:

After successful bind, the manager logs which LDAP server was selected from the pool, e.g.:

```log
LDAP bound to ldaps://ldap2.example.com:636 (pool_strategy=ROUND_ROBIN, start_tls=False)
```
Optionally, it can log the authenticated identity via the LDAP `whoami` extended operation.

## Security notes

- **Choose one TLS mode:** either `ldaps://...` or `ldap://` with `start_tls=true`. Mixing them is discouraged.
- Keep `verify_ssl = true` in production and ensure your trust store contains the issuing CA(s).
- Bind credentials should preferrably be supplied via `*_secret` indirection (Variables → Secrets Backend), not plaintext.

## Troubleshooting

- **Can’t bind / invalid credentials:** test with `ldapsearch` using the same DN/password and base/filter.
- **User not found:** verify `user_search_base` and `user_search_filter` (remember `{username}` substitution).
- **Group mapping not applied:** confirm `group_search_base`, `group_member_attr`, and that your groups are in the configured bases.
- **TLS errors:** verify certificates and CA chain; ensure the hostname matches the server certificate CN/SAN.
- **Static assets 404:** check the FastAPI `StaticFiles` mount matches `/auth/static`.

## Contributing

Issues and PRs are welcome. Please include:

- A clear description of the problem or feature
- Repro steps or tests when possible
- Your Airflow, Python, and LDAP server versions
