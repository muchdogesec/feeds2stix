from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Generic, Iterator, TypeVar

@dataclass(slots=True)
class BaseEntry:
    created: datetime
    modified: datetime


TEntry = TypeVar("TEntry", bound=BaseEntry)


class Group(Generic[TEntry]):
    start_date = datetime.min.replace(tzinfo=UTC)
    end_date = datetime.max.replace(tzinfo=UTC)

    def __init__(self) -> None:
        self.entries: list[TEntry] = []
        self.created = None
        self.modified = None
        self.count = 0

    def append(self, entry: TEntry) -> None:
        self.count += 1
        self.created = min(self.created or entry.created, entry.created)
        self.modified = max(self.modified or entry.modified, entry.modified)

        if (self.start_date and entry.modified < self.start_date) or (
            self.end_date and entry.modified > self.end_date
        ):
            return

        self.entries.append(entry)

    def __bool__(self) -> bool:
        return bool(self.entries)

    def __len__(self) -> int:
        return len(self.entries)
    
    def __iter__(self):
        return iter(self.entries)
    
    def __getitem__(self, key):
        return self.entries[key]
