"""Bounded MVP API. Never deploy this demo unchanged with real customer data."""
import os
from contextlib import asynccontextmanager
from datetime import datetime, timezone, timedelta, date
from typing import Literal
from fastapi import FastAPI, Depends, HTTPException, Request
from pydantic import BaseModel, Field
from sqlalchemy import select, func
from sqlalchemy.orm import Session
from .db import Base, AuditEvent, audit, engine_for_env, uid
from .security import current_actor
from .model import *

@asynccontextmanager
async def lifespan(app: FastAPI):
    engine = engine_for_env()
    app.state.engine = engine
    if os.getenv('H4_AUTO_CREATE_TABLES') == '1':
        Base.metadata.create_all(engine)
    try:
        yield
    finally:
        engine.dispose()

def session_dep(request: Request):
    with Session(request.app.state.engine) as session:
        yield session

def require_tenant(session: Session, model, entity_id: str, tenant_id: str):
    item = session.scalar(select(model).where(model.id == entity_id, model.tenant_id == tenant_id))
    if item is None:
        raise HTTPException(404, 'Not found')
    return item

app = FastAPI(title='H4 AgentShield', version='0.1.0', lifespan=lifespan,
              description='Tenant-scoped technical MVP; not production-ready.')

@app.middleware('http')
async def add_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['Cache-Control'] = 'no-store'
    response.headers['X-Frame-Options'] = 'DENY'
    return response

@app.get('/healthz', include_in_schema=False)
def healthz():
    return {'ok': True}

@app.get('/v1/audit')
def audit_list(auth=Depends(current_actor), session: Session=Depends(session_dep)):
    rows = session.scalars(select(AuditEvent).where(AuditEvent.tenant_id == auth['tenant_id'])
                           .order_by(AuditEvent.created_at.desc()).limit(100)).all()
    return {'events': [{'kind': r.kind, 'resource_id': r.resource_id,
                        'actor_id': r.actor_id, 'at': r.created_at.isoformat()} for r in rows]}

class AgentCreate(BaseModel):
    name: str = Field(min_length=2,max_length=80)

class PolicyCreate(BaseModel):
    agent_id: str
    tool: str = Field(min_length=1,max_length=120)
    action: str = Field(min_length=1,max_length=100)
    resource: str = Field(min_length=1,max_length=160)
    effect: Literal['allow','deny']
    requires_review: bool=False

class EvaluateRequest(BaseModel):
    agent_id: str
    tool: str
    action: str
    resource: str

@app.post('/v1/agents', status_code=201)
def create_agent(payload: AgentCreate, auth=Depends(current_actor), session: Session=Depends(session_dep)):
    agent=Agent(tenant_id=auth['tenant_id'],name=payload.name)
    session.add(agent); session.flush(); audit(session,auth,'agent.created',agent.id);session.commit()
    return {'id':agent.id,'name':agent.name}

@app.post('/v1/policies',status_code=201)
def create_policy(payload: PolicyCreate, auth=Depends(current_actor), session: Session=Depends(session_dep)):
    require_tenant(session,Agent,payload.agent_id,auth['tenant_id'])
    policy=Policy(tenant_id=auth['tenant_id'],**payload.model_dump())
    session.add(policy);session.flush();audit(session,auth,'policy.created',policy.id);session.commit()
    return {'id':policy.id,'effect':policy.effect}

@app.post('/v1/evaluate')
def evaluate(payload: EvaluateRequest, auth=Depends(current_actor), session: Session=Depends(session_dep)):
    require_tenant(session,Agent,payload.agent_id,auth['tenant_id'])
    matches=session.scalars(select(Policy).where(Policy.tenant_id==auth['tenant_id'],
        Policy.agent_id==payload.agent_id,Policy.tool==payload.tool,
        Policy.action==payload.action,Policy.resource==payload.resource)).all()
    # Explicit denies always win; otherwise review has precedence over allow.
    denied=next((p for p in matches if p.effect=='deny'),None)
    reviewed=next((p for p in matches if p.effect=='allow' and p.requires_review),None)
    allowed=next((p for p in matches if p.effect=='allow'),None)
    winner=denied or reviewed or allowed
    result='deny' if denied or not winner else 'review' if reviewed else 'allow'
    decision=Decision(tenant_id=auth['tenant_id'],agent_id=payload.agent_id,
        result=result,matched_policy=winner.id if winner else '')
    session.add(decision);session.flush();audit(session,auth,'policy.evaluated',decision.id);session.commit()
    return {'decision':result,'decision_id':decision.id,'reason':'explicit-deny' if denied else 'no-matching-policy' if not winner else 'matched-policy',
            'note':'Policy evaluation only: this API does not execute tools.'}
