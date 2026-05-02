from datetime import datetime
from typing import Optional

from sqlalchemy import Column, JSON
from sqlmodel import Field, SQLModel


class User(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    username: str = Field(unique=True, index=True)
    hashed_password: str
    technitium_token_encrypted: Optional[str] = None
    created_at: datetime = Field(default_factory=datetime.utcnow)


class UserSession(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    user_id: int = Field(foreign_key="user.id", index=True)
    login_time: datetime = Field(default_factory=datetime.utcnow)
    logout_time: Optional[datetime] = None


class GlobalSettings(SQLModel, table=True):
    id: int = Field(default=1, primary_key=True)
    zone: str = Field(default="home.lan")
    technitium_url: str = Field(default="http://localhost:5380")


class Collection(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    name: str = Field(index=True)
    description: Optional[str] = None
    subdomain: Optional[str] = None
    sync_status: str = Field(default="pending")
    last_error: Optional[str] = None
    created_at: datetime = Field(default_factory=datetime.utcnow)
    updated_at: datetime = Field(default_factory=datetime.utcnow)


class CollectionSubnet(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    collection_id: int = Field(foreign_key="collection.id", index=True)
    cidr: str


class Host(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    collection_id: int = Field(foreign_key="collection.id", index=True)
    hostname: str
    ip_address: str
    mac_address: str
    sync_status: str = Field(default="pending")
    last_error: Optional[str] = None
    created_at: datetime = Field(default_factory=datetime.utcnow)
    updated_at: datetime = Field(default_factory=datetime.utcnow)


class BlockListSubscription(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    name: str
    url: str
    enabled: bool = True
    created_at: datetime = Field(default_factory=datetime.utcnow)


class RuleSet(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    name: str
    created_at: datetime = Field(default_factory=datetime.utcnow)


class CustomRule(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    ruleset_id: int = Field(foreign_key="ruleset.id", index=True)
    domain: str
    action: str  # "block" or "allow"


class CollectionBlockList(SQLModel, table=True):
    collection_id: int = Field(foreign_key="collection.id", primary_key=True)
    blocklist_id: int = Field(foreign_key="blocklistsubscription.id", primary_key=True)


class CollectionRuleSet(SQLModel, table=True):
    collection_id: int = Field(foreign_key="collection.id", primary_key=True)
    ruleset_id: int = Field(foreign_key="ruleset.id", primary_key=True)


class DiscoveredHost(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    fqdn: str = Field(unique=True, index=True)
    hostname: str
    ip_address: str
    mac_address: Optional[str] = None
    suggested_collection_id: Optional[int] = Field(default=None, foreign_key="collection.id")
    dismissed: bool = Field(default=False)
    created_at: datetime = Field(default_factory=datetime.utcnow)
    updated_at: datetime = Field(default_factory=datetime.utcnow)


class ChangeLog(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    session_id: int = Field(foreign_key="usersession.id", index=True)
    entity_type: str   # "host", "collection", "ruleset", "customrule", "blocklistsubscription"
    entity_id: int
    operation: str     # "create", "update", "delete"
    before_state: Optional[dict] = Field(default=None, sa_column=Column(JSON))
    after_state: Optional[dict] = Field(default=None, sa_column=Column(JSON))
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    undone: bool = Field(default=False)
