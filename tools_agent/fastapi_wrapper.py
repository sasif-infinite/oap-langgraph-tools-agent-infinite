"""FastAPI wrapper for LangGraph Tools Agent with JWT authentication."""

import os
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
import httpx
from starlette.requests import Request
from starlette.responses import Response, StreamingResponse

from tools_agent.middleware import JWTAuthMiddleware

# Create FastAPI app
app = FastAPI(
    title="LangGraph Tools Agent",
    description="LangGraph Tools Agent with JWT Authentication",
    version="0.1.0",
)

# Get LangGraph service URL from environment
LANGGRAPH_SERVICE_URL = os.getenv("LANGGRAPH_SERVICE_URL", "http://localhost:8123")

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Configure this based on your needs
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Add JWT authentication middleware
app.add_middleware(JWTAuthMiddleware, excluded_paths=["/health"])


@app.get("/health")
async def health_check():
    """Health check endpoint."""
    return {"status": "ok"}


@app.api_route("/{path:path}", methods=["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"])
async def proxy_to_langgraph(request: Request, path: str):
    """
    Proxy all requests to the LangGraph service after JWT validation.
    
    Args:
        request: Incoming request
        path: Path to forward to LangGraph service
        
    Returns:
        Response from LangGraph service
    """
    # Build target URL
    target_url = f"{LANGGRAPH_SERVICE_URL}/{path}"
    
    # Copy query parameters
    if request.url.query:
        target_url = f"{target_url}?{request.url.query}"
    
    # Prepare headers
    headers = dict(request.headers)
    # Remove host header as it should be set by httpx
    headers.pop("host", None)
    
    # Get request body
    body = await request.body()
    
    # Forward the request to LangGraph service
    async with httpx.AsyncClient() as client:
        try:
            response = await client.request(
                method=request.method,
                url=target_url,
                headers=headers,
                content=body,
                timeout=300.0,  # 5 minutes timeout
            )
            
            # Check if response is streaming
            if response.headers.get("content-type", "").startswith("text/event-stream"):
                # For streaming responses
                async def generate():
                    async for chunk in response.aiter_bytes():
                        yield chunk
                
                return StreamingResponse(
                    generate(),
                    status_code=response.status_code,
                    headers=dict(response.headers),
                    media_type=response.headers.get("content-type"),
                )
            else:
                # For regular responses
                return Response(
                    content=response.content,
                    status_code=response.status_code,
                    headers=dict(response.headers),
                    media_type=response.headers.get("content-type"),
                )
                
        except httpx.HTTPError as e:
            return Response(
                content=f"Error proxying request to LangGraph service: {str(e)}",
                status_code=502,
            )


if __name__ == "__main__":
    import uvicorn
    
    port = int(os.getenv("PORT", "8000"))
    uvicorn.run(app, host="0.0.0.0", port=port)
