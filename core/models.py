from sqlalchemy import Column, Integer, String, DateTime, Text, Boolean, create_engine, ForeignKey
from sqlalchemy.orm import declarative_base, relationship
from sqlalchemy.sql import func

Base = declarative_base()

class IoC(Base):
    __tablename__ = "iocs"
    id = Column(Integer, primary_key=True)
    type = Column(String(32), index=True)   # ip, domain, hash, url, email
    value = Column(String(512), index=True)
    source = Column(String(128))            # feed name
    first_seen = Column(DateTime, default=func.now())
    last_seen = Column(DateTime, default=func.now(), onupdate=func.now())
    meta = Column(Text)                     # raw JSON or notes
    enriched = Column(Boolean, default=False)

class Enrichment(Base):
    __tablename__ = "enrichments"
    id = Column(Integer, primary_key=True)
    ioc_id = Column(Integer, ForeignKey("iocs.id"))
    provider = Column(String(64))
    result = Column(Text)
    created_at = Column(DateTime, default=func.now())
    ioc = relationship("IoC", back_populates="enrichments")

IoC.enrichments = relationship("Enrichment", order_by=Enrichment.id, back_populates="ioc")
