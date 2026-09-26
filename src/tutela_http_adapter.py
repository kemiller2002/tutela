"""Constrained HTTP adapter for authorized Tutela adversarial campaigns."""
from __future__ import annotations
from dataclasses import dataclass
import hashlib, http.client
from urllib.parse import urlsplit

SENSITIVE_HEADERS={"authorization","cookie","set-cookie","proxy-authorization"}
ALLOWED_METHODS={"GET","POST","PUT","PATCH","DELETE","HEAD","OPTIONS"}

class HttpPolicyError(RuntimeError): pass

@dataclass(frozen=True)
class HttpPolicy:
    allowed_origins: tuple[str,...]
    timeout_seconds: float=3.0
    max_request_bytes: int=65536
    max_response_bytes: int=131072

def origin(url: str)->str:
    p=urlsplit(url)
    if p.scheme not in {"http","https"} or not p.hostname:
        raise HttpPolicyError("only explicit http/https targets are supported")
    port=p.port or (443 if p.scheme=="https" else 80)
    return f"{p.scheme}://{p.hostname}:{port}"

def _safe_headers(headers):
    return {k:("[REDACTED]" if k.lower() in SENSITIVE_HEADERS else v)
            for k,v in headers.items()}

def make_http_adapter(policy: HttpPolicy):
    allowed=set(policy.allowed_origins)
    def execute(scenario: dict, attempt: int)->dict:
        req=scenario.get("http")
        if not isinstance(req,dict): raise HttpPolicyError("scenario has no declarative http request")
        url=req.get("url",""); target_origin=origin(url)
        if target_origin not in allowed: raise HttpPolicyError("target origin is not explicitly authorized")
        method=req.get("method","GET").upper()
        if method not in ALLOWED_METHODS: raise HttpPolicyError("HTTP method is not allowed")
        body=req.get("body","").encode()
        if len(body)>policy.max_request_bytes: raise HttpPolicyError("request exceeds byte budget")
        p=urlsplit(url); path=p.path or "/"
        if p.query: path+="?"+p.query
        conn_cls=http.client.HTTPSConnection if p.scheme=="https" else http.client.HTTPConnection
        conn=conn_cls(p.hostname,p.port,timeout=policy.timeout_seconds)
        headers=dict(req.get("headers",{}))
        try:
            conn.request(method,path,body=body or None,headers=headers)
            response=conn.getresponse()
            data=response.read(policy.max_response_bytes+1)
            truncated=len(data)>policy.max_response_bytes
            data=data[:policy.max_response_bytes]
            status=response.status
            response_headers=_safe_headers(dict(response.getheaders()))
        finally:
            conn.close()
        expectation=scenario.get("expect",{})
        allowed_status=set(expectation.get("status",[]))
        outcome="RESISTED" if allowed_status and status in allowed_status else "INDETERMINATE"
        if expectation.get("violationStatus") and status in set(expectation["violationStatus"]):
            outcome="VIOLATED"
        return {"attempt":attempt,"outcome":outcome,"status":status,
                "responseBytes":len(data),"responseTruncated":truncated,
                "responseSha256":hashlib.sha256(data).hexdigest(),
                "headers":response_headers}
    return execute
