from sqlalchemy.orm import Mapped, mapped_column
from sqlalchemy import String, Boolean
from .db import Base, uid

class Agent(Base):
    __tablename__='agents'
    id: Mapped[str]=mapped_column(String(36),primary_key=True,default=uid)
    tenant_id: Mapped[str]=mapped_column(String(100),index=True)
    name: Mapped[str]=mapped_column(String(80))

class Policy(Base):
    __tablename__='policies'
    id: Mapped[str]=mapped_column(String(36),primary_key=True,default=uid)
    tenant_id: Mapped[str]=mapped_column(String(100),index=True)
    agent_id: Mapped[str]=mapped_column(String(36),index=True)
    tool: Mapped[str]=mapped_column(String(120))
    action: Mapped[str]=mapped_column(String(100))
    resource: Mapped[str]=mapped_column(String(160))
    effect: Mapped[str]=mapped_column(String(10))
    requires_review: Mapped[bool]=mapped_column(Boolean,default=False)

class Decision(Base):
    __tablename__='decisions'
    id: Mapped[str]=mapped_column(String(36),primary_key=True,default=uid)
    tenant_id: Mapped[str]=mapped_column(String(100),index=True)
    agent_id: Mapped[str]=mapped_column(String(36))
    result: Mapped[str]=mapped_column(String(20))
    matched_policy: Mapped[str]=mapped_column(String(36),default='')
