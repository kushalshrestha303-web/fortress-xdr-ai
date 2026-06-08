from fastapi import APIRouter, HTTPException

from app.models.events import PlaybookApprovalRequest, PlaybookRunRequest
from app.services.playbook_engine import HIGH_RISK_INCIDENT_PLAYBOOK, decide_playbook_run, run_high_risk_playbook

router = APIRouter(tags=["playbooks"])


@router.get("/playbooks")
async def list_playbooks() -> dict[str, object]:
    return {"playbooks": [HIGH_RISK_INCIDENT_PLAYBOOK]}


@router.post("/playbooks/high-risk-incident-response/run")
async def run_playbook(request: PlaybookRunRequest) -> dict[str, object]:
    return await run_high_risk_playbook(request)


@router.post("/playbooks/runs/{run_id}/decision")
async def decide_playbook(run_id: str, request: PlaybookApprovalRequest) -> dict[str, object]:
    result = await decide_playbook_run(run_id, request)
    if result is None:
        raise HTTPException(status_code=404, detail="Playbook run not found")
    return result
