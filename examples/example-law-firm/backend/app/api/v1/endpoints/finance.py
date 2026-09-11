"""Minimal example law-firm application API slice for golden scan tests."""
from fastapi import APIRouter, Depends

router = APIRouter()


@router.post("/case-fee-receipts/{event_id}/purge")
async def post_case_fee_receipt_purge(event_id: str, user=Depends(require_roles)):  # noqa: F821
    pass


@router.post("/expenses/{expense_id}/purge")
async def post_expense_purge(expense_id: str, user=Depends(require_roles)):  # noqa: F821
    pass
