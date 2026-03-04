from pymongo import MongoClient
import os
from bson.objectid import ObjectId
import logging

logger = logging.getLogger(__name__)

# MongoDB URI from env var or default to localhost
MONGO_URI = os.environ.get("MONGO_URI", "mongodb://localhost:27017/")
DB_NAME = os.environ.get("DB_NAME", "phishing_detector")

_client = None

def get_db():
    global _client
    if _client is None:
        try:
            _client = MongoClient(MONGO_URI, serverSelectionTimeoutMS=2000)
            # attempt a quick server selection
            _client.admin.command('ping')
            return _client[DB_NAME]
        except Exception:
            # fallback to an in-memory DB for offline testing
            class InMemoryCollection:
                def __init__(self):
                    self._data = []

                def insert_one(self, doc):
                    # emulate ObjectId as string index
                    doc_copy = dict(doc)
                    doc_copy['_id'] = str(len(self._data) + 1)
                    self._data.append(doc_copy)
                    class Res: pass
                    r = Res()
                    r.inserted_id = doc_copy['_id']
                    return r

                def find_one(self, q):
                    for d in self._data:
                        ok = True
                        for k, v in q.items():
                            if d.get(k) != v:
                                ok = False
                                break
                        if ok:
                            return d
                    return None

                def count_documents(self, q):
                    if not q:
                        return len(self._data)
                    cnt = 0
                    for d in self._data:
                        match = True
                        for k, v in q.items():
                            if d.get(k) != v:
                                match = False
                                break
                        if match:
                            cnt += 1
                    return cnt

                def find(self):
                    # return a simple cursor-like object
                    class Cursor:
                        def __init__(self, data):
                            self._data = list(data)

                        def sort(self, key, direction):
                            reverse = direction < 0
                            self._data.sort(key=lambda x: x.get(key, None), reverse=reverse)
                            return self

                        def limit(self, n):
                            self._data = self._data[:n]
                            return self

                        def __iter__(self):
                            return iter(self._data)

                    return Cursor(self._data)

                def aggregate(self, pipeline):
                    # minimal aggregate support for group count by a field
                    # support groups like { $group: { _id: "$risk_score", count: {$sum:1}}}
                    # naive implementation
                    results = {}
                    for d in self._data:
                        key = d.get('risk_score')
                        results[key] = results.get(key, 0) + 1
                    return [{"_id": k, "count": v} for k, v in results.items()]

            class InMemoryDB:
                def __init__(self):
                    self.users = InMemoryCollection()
                    self.scans = InMemoryCollection()

            _client = InMemoryDB()
            return _client
    # if _client is the in-memory DB, return it directly
    if hasattr(_client, 'users') and hasattr(_client, 'scans'):
        return _client
    return _client[DB_NAME]


def log_scan(record: dict):
    db = get_db()
    collection = db.scans
    try:
        collection.insert_one(record)
    except Exception as e:
        logger.exception(f"Failed to insert scan record: {e}")


def create_user(user: dict) -> str:
    db = get_db()
    users = db.users
    res = users.insert_one(user)
    return str(res.inserted_id)


def find_user_by_email(email: str):
    db = get_db()
    users = db.users
    return users.find_one({"email": email})


def get_user_by_id(uid: str):
    db = get_db()
    users = db.users
    # try ObjectId lookup (real Mongo) then fallback to string id (in-memory)
    try:
        res = users.find_one({"_id": ObjectId(uid)})
        if res:
            return res
    except Exception:
        pass
    try:
        res = users.find_one({"_id": uid})
        if res:
            return res
    except Exception:
        pass
    return None
