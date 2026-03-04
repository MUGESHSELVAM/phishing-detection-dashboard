from dataclasses import dataclass, asdict
from typing import Optional


@dataclass
class User:
    email: str
    password_hash: str
    created_at: Optional[str] = None

    def to_dict(self):
        return asdict(self)
