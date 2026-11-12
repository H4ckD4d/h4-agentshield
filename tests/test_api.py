import hashlib, json, os
import pytest
from fastapi.testclient import TestClient
from . import TEST_APP

KEY_A='tenantA_sample_key_0123456789ABCDEFG'
KEY_B='tenantB_sample_key_0123456789ABCDEFG'
KEY_REVIEWER='tenantA_reviewer_key_0123456789ABC'
KEY_SECOND='tenantA_second_reviewer_0123456789'

@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.setenv('H4_DATABASE_URL',f'sqlite:///{tmp_path / "db.sqlite"}')
    monkeypatch.setenv('H4_AUTO_CREATE_TABLES','1')
    monkeypatch.setenv('H4_TENANTS',json.dumps([
        {'tenant_id':'t-a','actor_id':'owner','key':KEY_A},
        {'tenant_id':'t-a','actor_id':'reviewer','key':KEY_REVIEWER},
        {'tenant_id':'t-a','actor_id':'second','key':KEY_SECOND},
        {'tenant_id':'t-b','actor_id':'ownerB','key':KEY_B},
    ]))
    with TestClient(TEST_APP) as c:
        yield c

def headers(key=KEY_A):
    return {'X-API-Key':key}

def test_security(client):
    assert client.get('/healthz').status_code==200
    assert client.get('/v1/audit').status_code==401
    assert client.get('/v1/audit', headers=headers('invalid')).status_code==401
    assert client.get('/v1/audit', headers=headers()).status_code==200
    assert client.get('/v1/audit', headers=headers()).headers['Cache-Control']=='no-store'

def test_policy_deny_by_default_and_tenant_isolation(client):
    agent=client.post('/v1/agents',json={'name':'Demo assistant'},headers=headers()).json()['id']
    payload={'agent_id':agent,'tool':'calendar','action':'read','resource':'team'}
    assert client.post('/v1/evaluate',json=payload,headers=headers()).json()['decision']=='deny'
    assert client.post('/v1/evaluate',json=payload,headers=headers(KEY_B)).status_code==404
    client.post('/v1/policies',json={**payload,'effect':'allow'},headers=headers())
    assert client.post('/v1/evaluate',json=payload,headers=headers()).json()['decision']=='allow'

def test_explicit_deny_beats_allow(client):
    agent=client.post('/v1/agents',json={'name':'Demo agent'},headers=headers()).json()['id']
    payload={'agent_id':agent,'tool':'files','action':'write','resource':'sandbox'}
    assert client.post('/v1/policies',json={**payload,'effect':'allow','requires_review':True},headers=headers()).status_code==201
    assert client.post('/v1/evaluate',json=payload,headers=headers()).json()['decision']=='review'
    client.post('/v1/policies',json={**payload,'effect':'deny'},headers=headers())
    assert client.post('/v1/evaluate',json=payload,headers=headers()).json()['decision']=='deny'

def test_audit_visibility_is_tenant_scoped(client):
    from sqlalchemy.orm import Session
    from . import TEST_APP
    from agentshield.db import AuditEvent

    with Session(TEST_APP.state.engine) as session:
        session.add(AuditEvent(tenant_id='t-a',actor_id='owner',kind='synthetic',resource_id='a'))
        session.add(AuditEvent(tenant_id='t-b',actor_id='ownerB',kind='synthetic',resource_id='b'))
        session.commit()
    a=client.get('/v1/audit',headers=headers(KEY_A)).json()['events']
    b=client.get('/v1/audit',headers=headers(KEY_B)).json()['events']
    assert [x['resource_id'] for x in a]==['a']
    assert [x['resource_id'] for x in b]==['b']

def test_missing_auth_config_fails_closed(client, monkeypatch):
    monkeypatch.delenv('H4_TENANTS')
    response=client.get('/v1/audit',headers=headers(KEY_A))
    assert response.status_code==503
