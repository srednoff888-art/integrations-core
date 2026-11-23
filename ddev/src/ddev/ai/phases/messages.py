# (C) Datadog, Inc. 2026-present
# All rights reserved
# Licensed under a 3-clause BSD style license (see LICENSE)

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from ddev.event_bus.orchestrator import BaseMessage

if TYPE_CHECKING:
    from ddev.ai.runtime.errors import CredentialRefreshError


@dataclass
class PhaseTrigger(BaseMessage):
    phase_id: str | None  # None = initial pipeline start; str = the phase that just finished


@dataclass
class PhaseFailedMessage(BaseMessage):
    phase_id: str
    error: str
    refresh_error: CredentialRefreshError | None = field(default=None, repr=False)
