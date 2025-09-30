"""
LDAPAuthManager for Apache Airflow 3.1+

Key notes:
* Implements all abstract methods from BaseAuthManager, including
  `filter_authorized_menu_items`, `is_authorized_asset[_alias]`, `is_authorized_backfill`,
  `is_authorized_pool`, `is_authorized_variable`, and `is_authorized_custom_view`.
* LDAP authentication via ldap3.
* JWT cookie handoff per Airflow 3 spec (`_token`, not httponly, secure if https).
* Group→role mapping for admin/editor/viewer.
"""

import logging
import ssl
from collections.abc import Iterable
from dataclasses import dataclass, field
from enum import IntEnum
from pathlib import Path
from typing import Optional, override

from fastapi import APIRouter, FastAPI, Body, Form, Request
from fastapi.responses import HTMLResponse, RedirectResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from jinja2 import Environment, FileSystemLoader
from ldap3 import (
    ALL,
    ALL_ATTRIBUTES,
    AUTO_BIND_NO_TLS,
    AUTO_BIND_TLS_BEFORE_BIND,
    ROUND_ROBIN,
    SUBTREE,
    Connection,
    Server,
    ServerPool,
    Tls,
)

from airflow.api_fastapi.auth.managers.base_auth_manager import COOKIE_NAME_JWT_TOKEN, BaseAuthManager, ResourceMethod
from airflow.api_fastapi.auth.managers.models import resource_details as rd
from airflow.api_fastapi.auth.managers.models.base_user import BaseUser
from airflow.configuration import conf
from airflow.sdk import Variable

log = logging.getLogger("airflow.auth.ldap")


def _get_sensitive(section: str, key: str) -> str | None:
    # 1) Secret indirection via Variables/secret backend
    secret_name = conf.get(section, f"{key}_secret", fallback=None)
    if secret_name:
        val = Variable.get(secret_name, default=None)
        if val:
            return val
    # 2) Plaintext fallback from airflow.cfg
    return conf.get(section, key, fallback=None)


# -----------------------------
# User model
# -----------------------------
@dataclass
class LdapUser(BaseUser):
    user_id: str
    username: str | None = None
    email: str | None = None
    groups: list[str] = field(default_factory=list)


class Role(IntEnum):
    NONE = 0
    VIEWER = 1
    EDITOR = 2
    ADMIN = 3


# -----------------------------
# Helper: LDAP access
# -----------------------------
class LdapClient:
    def __init__(self):
        uris = [uri.strip() for uri in conf.get("ldap_auth_manager", "server_uri").split(",")]

        self._bind_dn = _get_sensitive("ldap_auth_manager", "bind_dn")
        self._bind_pw = _get_sensitive("ldap_auth_manager", "bind_password")
        self._user_base = conf.get("ldap_auth_manager", "user_search_base")
        self._user_filter_tpl = conf.get(
            "ldap_auth_manager",
            "user_search_filter",
            fallback="(|(uid={username})(sAMAccountName={username})(mail={username}))",
        )
        self._group_base = conf.get("ldap_auth_manager", "group_search_base", fallback=None)
        self._group_member_attr = conf.get("ldap_auth_manager", "group_member_attr", fallback="member")
        self._username_attr = conf.get("ldap_auth_manager", "username_attr", fallback="uid")
        self._email_attr = conf.get("ldap_auth_manager", "email_attr", fallback="mail")
        self._start_tls = conf.getboolean("ldap_auth_manager", "start_tls", fallback=False)
        self._verify_ssl = conf.getboolean("ldap_auth_manager", "verify_ssl", fallback=True)
        self._debug_logging = conf.getboolean("ldap_auth_manager", "debug_logging", fallback=False)

        servers = []
        for uri in uris:
            tls = None
            if uri.lower().startswith("ldaps://") or self._start_tls:
                ctx = ssl.create_default_context()
                if not self._verify_ssl:
                    ctx.check_hostname = False
                    ctx.verify_mode = ssl.CERT_NONE
                tls = Tls(validate=ssl.CERT_REQUIRED if self._verify_ssl else ssl.CERT_NONE, version=ssl.PROTOCOL_TLS)
            servers.append(Server(uri, use_ssl=uri.lower().startswith("ldaps://"), get_info=ALL, tls=tls))

        self._servers = ServerPool(servers, pool_strategy=ROUND_ROBIN)

    def _service_conn(self) -> Connection:

        auto_bind = AUTO_BIND_TLS_BEFORE_BIND if self._start_tls else AUTO_BIND_NO_TLS

        if self._start_tls and any(s.ssl for s in self._servers.servers):
            raise ValueError("start_tls=true requires ldap:// (plain) servers, not ldaps://")

        conn = Connection(
            self._servers,  # this is a ServerPool
            user=self._bind_dn or None,
            password=self._bind_pw or None,
            auto_bind=auto_bind,
        )

        if self._debug_logging:
            # after successful auto_bind
            srv = conn.server  # the chosen ldap3.Server from the pool

            use_ssl = getattr(srv, "ssl", None)
            if use_ssl is None:
                use_ssl = getattr(srv, "use_ssl", False)

            scheme = "ldaps" if use_ssl else "ldap"
            port = srv.port or (636 if use_ssl else 389)
            pool_strategy = getattr(self._servers, "strategy", None) or getattr(self._servers, "pool_strategy", "n/a")

            log.info(
                f"LDAP bound to {scheme}://{srv.host}:{port} "
                f"(pool_strategy={pool_strategy}, start_tls={self._start_tls})"
            )

            # optional: show the authenticated identity
            try:
                who = conn.extend.standard.who_am_i()
                log.info(f"LDAP whoami: {who}")
            except Exception as e:
                log.warning(f"LDAP whoami not available: {e!r}")

        return conn

    def authenticate(self, username: str, password: str) -> Optional[dict]:
        with self._service_conn() as svc:
            flt = self._user_filter_tpl.format(username=username)
            if not svc.search(
                search_base=self._user_base,
                search_filter=flt,
                search_scope=SUBTREE,
                attributes=ALL_ATTRIBUTES,
            ):
                return None
            entry = svc.entries[0]
            user_dn = entry.entry_dn
            attrs = entry.entry_attributes_as_dict

        try:
            with Connection(self._servers, user=user_dn, password=password, auto_bind=True):
                pass
        except Exception:
            return None

        groups: list[str] = []
        if self._group_base:
            with self._service_conn() as svc2:
                member_attr = self._group_member_attr
                member_filters = [f"({member_attr}={user_dn})", f"({member_attr}={username})"]
                flt = f"(|{''.join(member_filters)})"
                svc2.search(
                    search_base=self._group_base,
                    search_filter=flt,
                    search_scope=SUBTREE,
                    attributes=["cn"],
                )
                for e in svc2.entries:
                    groups.append(str(e.cn))

        norm_username = (
            attrs.get(self._username_attr, [username])[0]
            if isinstance(attrs.get(self._username_attr), list)
            else attrs.get(self._username_attr, username)
        )
        email = attrs.get(self._email_attr)
        email = email[0] if isinstance(email, list) else email

        return {"dn": user_dn, "attrs": attrs, "username": norm_username, "email": email, "groups": groups}


# -----------------------------
# AuthZ policy helpers
# -----------------------------
class Policy:
    """
    Small helper that translates LDAP groups to a single effective Role and
    exposes convenience predicates.
    """

    def __init__(self):
        # Store as lowercase once; compare on lowercase later.
        self.admin_groups = {g.lower() for g in _csv_to_set(conf.get("ldap_auth_manager", "admin_groups", fallback=""))}
        self.editor_groups = {
            g.lower() for g in _csv_to_set(conf.get("ldap_auth_manager", "editor_groups", fallback=""))
        }
        self.viewer_groups = {
            g.lower() for g in _csv_to_set(conf.get("ldap_auth_manager", "viewer_groups", fallback=""))
        }
        # Default if user matches no configured groups
        self._default_role = Role.NONE  # <— deny by default

    def role_for(self, groups: Iterable[str]) -> Role:
        gs = {g.lower() for g in (groups or [])}
        if self.admin_groups and (gs & self.admin_groups):
            return Role.ADMIN
        if self.editor_groups and (gs & self.editor_groups):
            return Role.EDITOR
        if self.viewer_groups and (gs & self.viewer_groups):
            return Role.VIEWER
        # If no mapping found, default to least privilege
        return self._default_role

    def at_least(self, groups: Iterable[str], min_role: Role) -> bool:
        return self.role_for(groups) >= min_role

    # kept for readability if you want to use them elsewhere
    def is_admin(self, groups: Iterable[str]) -> bool:
        return self.at_least(groups, Role.ADMIN)

    def is_editor(self, groups: Iterable[str]) -> bool:
        return self.at_least(groups, Role.EDITOR)

    def is_viewer(self, groups: Iterable[str]) -> bool:
        return self.at_least(groups, Role.VIEWER)


def _csv_to_set(val: str) -> set[str]:
    return {x.strip() for x in val.split(",") if x.strip()}


# -----------------------------
# LDAP Auth Manager
# -----------------------------
class LdapAuthManager(BaseAuthManager[LdapUser]):
    def __init__(self, context=None):
        super().__init__(context=context)
        self._ldap = LdapClient()
        self._policy = Policy()
        self._debug_logging = conf.getboolean("ldap_auth_manager", "debug_logging", fallback=False)

    # --- Authentication surface ---
    @override
    def get_url_login(self, **kwargs) -> str:
        next_url = kwargs.get("next", "/")
        return f"/auth/login?next={next_url}"

    def get_url_logout(self) -> Optional[str]:
        return conf.get("ldap_auth_manager", "logout_redirect", fallback="/")

    @override
    def serialize_user(self, user: LdapUser) -> dict:
        return {
            "user_id": user.user_id,
            "username": user.username,
            "email": user.email,
            "groups": user.groups,
        }

    @override
    def deserialize_user(self, data: dict) -> LdapUser:
        return LdapUser(
            user_id=str(data.get("user_id")),
            username=data.get("username"),
            email=data.get("email"),
            groups=list(data.get("groups") or []),
        )

    @override
    async def get_user_from_token(self, token: str) -> LdapUser | None:
        import jwt
        from jwt import ExpiredSignatureError, InvalidAudienceError, InvalidSignatureError, InvalidTokenError

        secret = conf.get("api_auth", "jwt_secret")
        if not secret:
            return None

        alg = conf.get("api_auth", "jwt_algorithm", fallback="HS512") or "HS512"
        audience = conf.get("api_auth", "jwt_audience", fallback="urn:airflow.apache.org:api")
        aud = (audience.split(",")[0]).strip() if audience and "," in audience else audience
        issuer = conf.get("api_auth", "jwt_issuer", fallback=None)

        try:
            claims = jwt.decode(
                token,
                secret,
                algorithms=[alg],
                audience=aud if aud else None,
                issuer=issuer if issuer else None,
                options={"require": ["sub", "exp", "iat"], "verify_aud": bool(aud)},
            )
        except (ExpiredSignatureError, InvalidAudienceError, InvalidSignatureError, InvalidTokenError):
            return None

        data = claims.get("user") or {}
        user = self.deserialize_user(data)

        # Enforce whitelist again at request time
        if self._policy.role_for(user.groups) is Role.NONE:
            return None

        return user

    # --- Menu filtering ---
    def filter_authorized_menu_items(self, menu_items, *, user: LdapUser):
        # Everyone can see the whole menu; the endpoints themselves enforce write restrictions.
        return list(menu_items or [])

    # --- Authorization surface ---
    def _norm_method(self, method) -> str:
        name = getattr(method, "name", None)
        if name:
            return str(name).upper()
        value = getattr(method, "value", None)
        if value is not None:
            return str(value).upper()
        return str(method).upper()

    def _is_authorized(
        self,
        *,
        method: ResourceMethod | str,
        user: LdapUser,
        access_entity: "rd.DagAccessEntity | None" = None,
        write_scope: str | None = None,
    ) -> bool:
        """
        Central authorization rule-set.

        Rules:
        - GET -> Viewer+
        - Non-GET:
            - If write_scope == "dag_run" (or DagAccessEntity.DAG_RUN), Editor+
            - Else Admin only
        """
        role = self._policy.role_for(user.groups)
        if role == Role.NONE:
            return False  # deny outright

        m = self._norm_method(method)

        # Always allow reads
        if m == "GET":
            return self._policy.at_least(user.groups, Role.VIEWER)

        # Non-GET (write-ish)
        # Detect dag-run scoped writes either via explicit marker or DagAccessEntity
        dag_run_scoped = False
        if write_scope == "dag_run":
            dag_run_scoped = True
        elif access_entity is not None:
            try:
                # Handle both enum and str cases
                ae_name = getattr(access_entity, "name", str(access_entity)).upper()
                dag_run_scoped = ae_name in {"DAG_RUN", "DAGRUN", "RUN"}
            except Exception:
                pass

        if dag_run_scoped:
            return self._policy.at_least(user.groups, Role.EDITOR)

        # Everything else requires full admin
        return self._policy.at_least(user.groups, Role.ADMIN)

    @override
    def is_authorized_configuration(
        self, *, method: ResourceMethod, user: LdapUser, details: rd.ConfigurationDetails | None = None
    ) -> bool:
        # Configuration changes are admin-only; reads are fine for all.
        return self._is_authorized(method=method, user=user)

    @override
    def is_authorized_connection(
        self, *, method: ResourceMethod, user: LdapUser, details: rd.ConnectionDetails | None = None
    ) -> bool:
        return self._is_authorized(method=method, user=user)

    @override
    def batch_is_authorized_connection(
        self, *, method: ResourceMethod, user: LdapUser, details: rd.ConnectionDetails | None = None
    ) -> bool:
        return self._is_authorized(method=method, user=user)

    @override
    def batch_is_authorized_variable(
        self, *, method: ResourceMethod, user: LdapUser, details: rd.VariableDetails | None = None
    ) -> bool:
        return self._is_authorized(method=method, user=user)

    @override
    def is_authorized_variable(
        self, *, method: ResourceMethod, user: LdapUser, details: rd.VariableDetails | None = None
    ) -> bool:
        return self._is_authorized(method=method, user=user)

    @override
    def batch_is_authorized_pool(
        self, *, method: ResourceMethod, user: LdapUser, details: rd.PoolDetails | None = None
    ) -> bool:
        return self._is_authorized(method=method, user=user)

    @override
    def is_authorized_pool(
        self, *, method: ResourceMethod, user: LdapUser, details: rd.PoolDetails | None = None
    ) -> bool:
        return self._is_authorized(method=method, user=user)

    @override
    def is_authorized_asset(
        self, *, method: ResourceMethod, user: LdapUser, details: rd.AssetDetails | None = None
    ) -> bool:
        return self._is_authorized(method=method, user=user)

    @override
    def is_authorized_asset_alias(
        self, *, method: ResourceMethod, user: LdapUser, details: rd.AssetAliasDetails | None = None
    ) -> bool:
        return self._is_authorized(method=method, user=user)

    @override
    def is_authorized_backfill(
        self, *, method: ResourceMethod, user: LdapUser, details: rd.BackfillDetails | None = None
    ) -> bool:
        # Backfills are disruptive -> admin-only for writes; reads for all
        return self._is_authorized(method=method, user=user, write_scope=None)

    @override
    def is_authorized_dag(
        self,
        *,
        method: ResourceMethod,
        user: LdapUser,
        access_entity: rd.DagAccessEntity | None = None,
        details: rd.DagDetails | None = None,
    ) -> bool:
        # Let editor write only when the operation targets DAG RUNs
        return self._is_authorized(method=method, user=user, access_entity=access_entity, write_scope=None)

    @override
    def batch_is_authorized_dag(
        self,
        *,
        method: ResourceMethod,
        user: LdapUser,
        access_entity: rd.DagAccessEntity | None = None,
        details: rd.DagDetails | None = None,
    ) -> bool:
        # Let editor write only when the operation targets DAG RUNs
        return self._is_authorized(method=method, user=user, access_entity=access_entity, write_scope=None)

    @override
    def is_authorized_view(self, *, access_view: rd.AccessView, user: LdapUser) -> bool:
        # Views are read-only by design
        return self._policy.at_least(user.groups, Role.VIEWER)

    @override
    def is_authorized_custom_view(self, *, method: ResourceMethod | str, resource_name: str, user: LdapUser) -> bool:
        return self._is_authorized(method=method, user=user)

    # -----------------------------
    # FastAPI extension for login/token/logout
    # -----------------------------
    def get_fastapi_app(self) -> Optional[FastAPI]:
        router = APIRouter()

        base_dir = Path(__file__).parent
        template_dir = base_dir / "templates"
        static_dir = base_dir / "static"
        jinja_env = Environment(loader=FileSystemLoader(template_dir), autoescape=True)

        instance_name = conf.get("api", "instance_name", fallback="Airflow")
        login_tip = conf.get("ldap_auth_manager", "login_tip", fallback="")

        jinja_env.globals.update(instance_name=instance_name, login_tip=login_tip)

        def render(name: str, **ctx) -> HTMLResponse:
            tpl = jinja_env.get_template(name)
            return HTMLResponse(tpl.render(**ctx))

        def _sanitize_next(raw_next: Optional[str], request: Request) -> str:
            """Return a safe, same-origin path for redirect.
            - unwrap nested next parameters once (e.g. "/?next=/graph")
            - drop absolute URLs to other hosts
            - default to '/'
            """
            target = (raw_next or "/").strip()
            try:
                from urllib.parse import parse_qs, urlparse

                # unwrap one level of nested 'next'
                qn = parse_qs(urlparse(target).query).get("next", [])
                if qn:
                    target = qn[0]

                # allow only same-origin relative paths
                if target.startswith("/") and not target.startswith("//"):
                    return target

                # if absolute, ensure same host
                u = urlparse(target)
                req = urlparse(str(request.base_url))
                if u.scheme and u.netloc and u.netloc == req.netloc:
                    return u.path or "/"
            except Exception:
                pass
            return "/"

        @router.get("/login", response_class=HTMLResponse)
        def login_form(next: str = "/", error: str | None = None):
            return render("ldap_login.html", next=next, error=error)

        @router.post("/token")
        async def create_token(request: Request):
            # --- parse input: JSON or form ---
            username = password = next_param = None
            ct = (request.headers.get("content-type") or "").lower()

            if ct.startswith("application/x-www-form-urlencoded") or ct.startswith("multipart/form-data"):
                form = await request.form()
                username = form.get("username")
                password = form.get("password")
                next_param = form.get("next")
            else:
                # Try JSON regardless of Content-Type (some clients lie)
                try:
                    payload = await request.json()
                except Exception:
                    payload = None
                if isinstance(payload, dict):
                    username = payload.get("username")
                    password = payload.get("password")
                    next_param = payload.get("next")

            if not username or not password:
                return JSONResponse({"detail": "username and password are required"}, status_code=422)

            # --- authenticate via LDAP as you already do ---
            info = self._ldap.authenticate(username=username, password=password)  # type: ignore[assignment]
            if not info:
                if "application/json" in (request.headers.get("accept") or ""):
                    return JSONResponse({"detail": "Invalid credentials"}, status_code=401)
                target = f"/auth/login?next={(next_param or '/')}&&error=Invalid%20credentials"
                return RedirectResponse(url=target, status_code=303)

            user = LdapUser(
                user_id=info["dn"],
                username=info.get("username"),
                email=info.get("email"),
                groups=info.get("groups", []),
            )

            # role check...
            role = self._policy.role_for(user.groups)
            if role is Role.NONE:
                msg = "You are not a member of any Airflow access group"
                if "application/json" in (request.headers.get("accept") or ""):
                    return JSONResponse({"detail": msg}, status_code=403)
                target = f"/auth/login?next={(next_param or '/')}&&error=" + msg.replace(" ", "%20")
                return RedirectResponse(url=target, status_code=303)

            # --- mint JWT (same as your current code) ---
            from datetime import datetime, timedelta, timezone
            import jwt

            secret = conf.get("api_auth", "jwt_secret")
            if not secret:
                return JSONResponse({"detail": "api_auth.jwt_secret is not set"}, status_code=500)

            alg = conf.get("api_auth", "jwt_algorithm", fallback="HS512") or "HS512"
            audience = conf.get("api_auth", "jwt_audience", fallback="urn:airflow.apache.org:api")
            aud = (audience.split(",")[0]).strip() if audience and "," in audience else audience
            issuer = conf.get("api_auth", "jwt_issuer", fallback=None)
            kid = conf.get("api_auth", "jwt_kid", fallback=None)
            exp_secs = conf.getint("api_auth", "jwt_expiration_time", fallback=36000)

            now = datetime.now(timezone.utc)
            claims = {
                "sub": user.user_id,
                "iat": int(now.timestamp()),
                "nbf": int(now.timestamp()) - 5,
                "exp": int((now + timedelta(seconds=exp_secs)).timestamp()),
                "aud": aud,
                "user": self.serialize_user(user),
            }
            if issuer:
                claims["iss"] = issuer
            headers = {"kid": kid} if kid else None
            token = jwt.encode(claims, secret, algorithm=alg, headers=headers)

            # --- respond JSON for API callers, cookie+303 for browsers ---
            wants_json = "application/json" in (request.headers.get("accept") or "")
            if wants_json:
                return JSONResponse({
                    "access_token": token,
                    "token_type": "Bearer",
                    "expires_in": exp_secs,
                })

            target = _sanitize_next(next_param, request) # type: ignore[arg-type]
            resp = RedirectResponse(url=target or "/", status_code=303)
            secure = (request.base_url.scheme == "https") or bool(conf.get("api", "ssl_cert", fallback=""))
            resp.set_cookie(COOKIE_NAME_JWT_TOKEN, token, secure=secure, httponly=False, samesite="lax", path="/")
            return resp

        @router.get("/logout")
        def logout(next: str = "/"):
            resp = RedirectResponse(url=conf.get("ldap_auth_manager", "logout_redirect", fallback=next))
            resp.delete_cookie(COOKIE_NAME_JWT_TOKEN, path="/")
            return resp

        app = FastAPI()
        app.mount("/static", StaticFiles(directory=str(static_dir)), name="auth-static")
        app.include_router(router)
        return app
