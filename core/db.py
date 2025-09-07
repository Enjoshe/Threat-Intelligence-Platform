import json
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from .models import Base, IoC, Enrichment

class DB:
    def __init__(self, db_url="sqlite:///threatintel.db"):
        self.engine = create_engine(db_url, connect_args={"check_same_thread": False})
        Base.metadata.create_all(self.engine)
        self.Session = sessionmaker(bind=self.engine)

    def upsert_ioc(self, ioc_type, value, source, meta=None):
        s = self.Session()
        existing = s.query(IoC).filter(IoC.type==ioc_type, IoC.value==value).first()
        if existing:
            existing.source = source
            if meta:
                try:
                    # merge metadata JSON
                    cur_meta = json.loads(existing.meta or "{}")
                    new_meta = {**cur_meta, **(meta if isinstance(meta, dict) else {})}
                    existing.meta = json.dumps(new_meta)
                except Exception:
                    existing.meta = (existing.meta or "") + "\n" + str(meta)
            s.add(existing)
            s.commit()
            s.close()
            return existing
        i = IoC(type=ioc_type, value=value, source=source, meta=json.dumps(meta) if meta else None)
        s.add(i)
        s.commit()
        s.refresh(i)
        s.close()
        return i

    def list_iocs(self, limit=100):
        s = self.Session()
        res = s.query(IoC).order_by(IoC.last_seen.desc()).limit(limit).all()
        s.close()
        return res

    def get_ioc(self, ioc_id):
        s = self.Session()
        r = s.query(IoC).get(ioc_id)
        s.close()
        return r

    def add_enrichment(self, ioc_id, provider, result):
        s = self.Session()
        e = Enrichment(ioc_id=ioc_id, provider=provider, result=json.dumps(result))
        s.add(e)
        s.commit()
        s.refresh(e)
        s.close()
        return e
