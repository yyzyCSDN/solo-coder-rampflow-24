from __future__ import annotations
from dataclasses import dataclass
from datetime import date,time,timedelta
from typing import Iterable
from .timeutil import Window,utc,zone_info,wall_window,merge_windows
from .models import Decision

@dataclass(frozen=True)
class Recurrence:
    weekdays:frozenset[int]
    local_start:time
    local_end:time
    zone:str
    exception_dates:frozenset[date]=frozenset()
    inclusion_dates:frozenset[date]=frozenset()

@dataclass(frozen=True)
class Notam:
    notam_id:str
    scope:str
    subject:str
    effective:Window
    priority:int
    action:str
    recurrence:Recurrence|None=None
    conditions:frozenset[str]=frozenset()

@dataclass(frozen=True)
class NotamEffect:
    notam_id:str
    window:Window
    action:str
    priority:int

class NotamRegistry:
    def __init__(self,notams:Iterable[Notam]=()):
        self.notams={n.notam_id:n for n in notams}
        self.revision=0

    def upsert(self,notam:Notam)->int:
        self.notams[notam.notam_id]=notam;self.revision+=1;return self.revision

    def cancel(self,notam_id:str)->bool:
        if notam_id not in self.notams:return False
        del self.notams[notam_id];self.revision+=1;return True

    def _occurrences(self, n: Notam, horizon: Window) -> list[Window]:
        base = n.effective.intersection(horizon)
        if base is None:
            return []
        if n.recurrence is None:
            return [base]
        r = n.recurrence
        z = zone_info(r.zone)
        # An overnight band attributed to a local date can end after midnight of
        # the next day (and DST transitions shift the end by another hour), so
        # scan two days on either side of the local horizon.
        local_start = base.start.astimezone(z).date() - timedelta(days=2)
        local_end = base.end.astimezone(z).date() + timedelta(days=2)
        cur = local_start
        out = []
        while cur <= local_end:
            active = (cur.weekday() in r.weekdays and cur not in r.exception_dates) or cur in r.inclusion_dates
            if active:
                occurrence = wall_window(cur, r.local_start, r.local_end, r.zone).intersection(n.effective)
                if occurrence:
                    occurrence = occurrence.intersection(horizon)
                    if occurrence:
                        out.append(occurrence)
            cur += timedelta(days=1)
        # Adjacent nightly bands touch at midnight (and DST fall-back bands
        # overlap). Merge them so the post-midnight continuation is not split
        # off and the ban cannot leak through the seam.
        return merge_windows(out)

    def effects(self,scope:str,subject:str,horizon:Window,conditions:Iterable[str]=())->tuple[NotamEffect,...]:
        context=set(conditions);out=[]
        for n in self.notams.values():
            if n.scope!=scope or n.subject not in {subject,"*"}:continue
            if n.conditions and not n.conditions.issubset(context):continue
            for w in self._occurrences(n,horizon):
                out.append(NotamEffect(n.notam_id,w,n.action,n.priority))
        out.sort(key=lambda e:(e.window.start,-e.priority,e.notam_id))
        return tuple(out)

    def decision(self,scope:str,subject:str,window:Window,conditions:Iterable[str]=())->Decision:
        effects=self.effects(scope,subject,window,conditions)
        active=[e for e in effects if e.window.overlaps(window)]
        if not active:return Decision(True,"clear","no applicable NOTAM",{"revision":self.revision})
        by_time=sorted(active,key=lambda e:(-e.priority,e.notam_id))
        top=by_time[0]
        if top.action in {"closed","prohibited","unavailable"}:
            return Decision(False,"notam-closure",f"{subject} restricted by {top.notam_id}",{"notam":top.notam_id,"priority":top.priority,"revision":self.revision})
        return Decision(True,"conditional",f"{subject} affected by {top.notam_id}",{"action":top.action,"notam":top.notam_id,"revision":self.revision})
