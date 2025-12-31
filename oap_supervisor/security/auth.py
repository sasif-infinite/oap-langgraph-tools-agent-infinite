import os
import time
from functools import lru_cache
from typing import Optional, Any

import httpx
from jose import jwk, jwt
from jose.utils import base64url_decode
from langgraph_sdk import Auth
from langgraph_sdk.auth.types import StudioUser

KEYCLOAK_ISSUER = os.environ.get("KEYCLOAK_ISSUER", "")
KEYCLOAK_AUDIENCE = os.environ.get("KEYCLOAK_AUDIENCE")
JWKS_PATH = "/protocol/openid-connect/certs"

# The "Auth" object is a container that LangGraph will use to mark our authentication function
auth = Auth()


@lru_cache(maxsize=1)
def fetch_jwks() -> dict:
    if not KEYCLOAK_ISSUER:
        raise Auth.exceptions.HTTPException(
            status_code=500, detail="Keycloak issuer not configured"
        )
    issuer = KEYCLOAK_ISSUER.rstrip("/")
    url = f"{issuer}{JWKS_PATH}"
    response = httpx.get(url, timeout=5.0)
    response.raise_for_status()
    return response.json()


def verify_keycloak_token(raw_token: str) -> dict[str, Any]:
    if not raw_token:
        raise Auth.exceptions.HTTPException(
            status_code=401, detail="Missing bearer token"
        )

    try:
        unverified_header = jwt.get_unverified_header(raw_token)
    except Exception as exc:
        raise Auth.exceptions.HTTPException(
            status_code=401, detail="Invalid token header"
        ) from exc

    jwks = fetch_jwks()
    signing_key = next(
        (key for key in jwks.get("keys", []) if key.get("kid") == unverified_header.get("kid")),
        None,
    )

    if not signing_key:
        fetch_jwks.cache_clear()
        raise Auth.exceptions.HTTPException(
            status_code=401, detail="Signing key not found for token"
        )

    message, encoded_signature = raw_token.rsplit(".", 1)
    decoded_signature = base64url_decode(encoded_signature.encode("utf-8"))
    public_key = jwk.construct(signing_key)

    if not public_key.verify(message.encode("utf-8"), decoded_signature):
        raise Auth.exceptions.HTTPException(
            status_code=401, detail="Invalid token signature"
        )

    claims = jwt.get_unverified_claims(raw_token)

    now = time.time()
    if claims.get("exp") and now > claims["exp"]:
        raise Auth.exceptions.HTTPException(
            status_code=401, detail="Token has expired"
        )

    if claims.get("iss") != KEYCLOAK_ISSUER:
        raise Auth.exceptions.HTTPException(
            status_code=401, detail="Token issuer mismatch"
        )

    aud_claim = claims.get("aud")
    if KEYCLOAK_AUDIENCE:
        if isinstance(aud_claim, str) and aud_claim != KEYCLOAK_AUDIENCE:
            raise Auth.exceptions.HTTPException(
                status_code=401, detail="Token audience mismatch"
            )
        if isinstance(aud_claim, list) and KEYCLOAK_AUDIENCE not in aud_claim:
            raise Auth.exceptions.HTTPException(
                status_code=401, detail="Token audience mismatch"
            )

    return claims


# The `authenticate` decorator tells LangGraph to call this function as middleware
# for every request. This will determine whether the request is allowed or not
@auth.authenticate
async def get_current_user(authorization: str | None) -> Auth.types.MinimalUserDict:
    """Check if the user's JWT token is valid using Keycloak."""

    # Ensure we have authorization header
    if not authorization:
        raise Auth.exceptions.HTTPException(
            status_code=401, detail="Authorization header missing"
        )

    token = authorization.replace("Bearer ", "")
    claims = verify_keycloak_token(token)

    return {
        "identity": claims.get("sub", ""),
    }


@auth.on.threads.create
@auth.on.threads.create_run
async def on_thread_create(
    ctx: Auth.types.AuthContext,
    value: Auth.types.on.threads.create.value,
):
    """Add owner when creating threads.

    This handler runs when creating new threads and does two things:
    1. Sets metadata on the thread being created to track ownership
    2. Returns a filter that ensures only the creator can access it
    """

    if isinstance(ctx.user, StudioUser):
        return

    # Add owner metadata to the thread being created
    # This metadata is stored with the thread and persists
    metadata = value.setdefault("metadata", {})
    metadata["owner"] = ctx.user.identity


@auth.on.threads.read
@auth.on.threads.delete
@auth.on.threads.update
@auth.on.threads.search
async def on_thread_read(
    ctx: Auth.types.AuthContext,
    value: Auth.types.on.threads.read.value,
):
    """Only let users read their own threads.

    This handler runs on read operations. We don't need to set
    metadata since the thread already exists - we just need to
    return a filter to ensure users can only see their own threads.
    """
    if isinstance(ctx.user, StudioUser):
        return

    return {"owner": ctx.user.identity}


@auth.on.assistants.create
async def on_assistants_create(
    ctx: Auth.types.AuthContext,
    value: Auth.types.on.assistants.create.value,
):
    if isinstance(ctx.user, StudioUser):
        return

    # Add owner metadata to the assistant being created
    # This metadata is stored with the assistant and persists
    metadata = value.setdefault("metadata", {})
    metadata["owner"] = ctx.user.identity


@auth.on.assistants.read
@auth.on.assistants.delete
@auth.on.assistants.update
@auth.on.assistants.search
async def on_assistants_read(
    ctx: Auth.types.AuthContext,
    value: Auth.types.on.assistants.read.value,
):
    """Only let users read their own assistants.

    This handler runs on read operations. We don't need to set
    metadata since the assistant already exists - we just need to
    return a filter to ensure users can only see their own assistants.
    """

    if isinstance(ctx.user, StudioUser):
        return

    return {"owner": ctx.user.identity}


@auth.on.store()
async def authorize_store(ctx: Auth.types.AuthContext, value: dict):
    if isinstance(ctx.user, StudioUser):
        return

    # The "namespace" field for each store item is a tuple you can think of as the directory of an item.
    namespace: tuple = value["namespace"]
    assert namespace[0] == ctx.user.identity, "Not authorized"
