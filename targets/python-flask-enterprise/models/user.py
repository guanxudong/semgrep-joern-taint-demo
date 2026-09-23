"""User model."""
from dataclasses import dataclass, field, fields


@dataclass
class User:
    id: int = 0
    username: str = ""
    email: str = ""
    password_hash: str = ""
    role: str = "customer"
    display_name: str = ""
    bio: str = ""
    is_active: bool = True

    @classmethod
    def from_dict(cls, data):
        known = {f.name for f in fields(cls)}
        return cls(**{k: v for k, v in (data or {}).items() if k in known})

    def update_from(self, data):
        for key, value in (data or {}).items():
            if hasattr(self, key):
                setattr(self, key, value)
        return self

    def to_dict(self, redact=True):
        out = {
            "id": self.id,
            "username": self.username,
            "email": self.email,
            "role": self.role,
            "display_name": self.display_name,
            "bio": self.bio,
            "is_active": self.is_active,
        }
        if not redact:
            out["password_hash"] = self.password_hash
        return out
