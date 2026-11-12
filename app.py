"""Simple local dashboard for prompt inspection and secure document retrieval."""

from __future__ import annotations

from pathlib import Path
from uuid import uuid4

import streamlit as st

from security_middleware.action_gateway import ActionGateway
from security_middleware.audit_log import AuditLog, initialize_audit_database
from security_middleware.content_assessor import OllamaContentAssessor
from security_middleware.ml_detector import MLDetector
from security_middleware.content_protection import (
    ContentDecision,
    ContentEnvelope,
    ContentInspector,
    DataSensitivity,
    OriginTrust,
)
from security_middleware.controlled_tools import (
    DOCUMENT_FILES,
    ControlledTools,
    initialize_demo_databases,
)
from security_middleware.review_queue import (
    ReviewDecision,
    ReviewQueue,
    initialize_review_database,
)
from security_middleware.secure_retrieval import SecureDocumentRetrieval


PROJECT_ROOT = Path(__file__).resolve().parent
RUNTIME_ROOT = PROJECT_ROOT / "runtime_data"


@st.cache_resource
def classifier(artifact_stamp: tuple[int, int] | None) -> MLDetector:
    return MLDetector(PROJECT_ROOT / 'models' / 'prompt_classifier.joblib')


def current_classifier() -> MLDetector:
    path = PROJECT_ROOT / 'models' / 'prompt_classifier.joblib'
    try:
        stat = path.stat()
        stamp = (stat.st_mtime_ns, stat.st_size)
    except FileNotFoundError:
        stamp = None
    return classifier(stamp)


@st.cache_resource
def services() -> tuple[ContentInspector, SecureDocumentRetrieval, ReviewQueue, AuditLog]:
    """Initialize the local services used by the dashboard."""
    records_path = RUNTIME_ROOT / "project_records.db"
    outbox_path = RUNTIME_ROOT / "outbox.db"
    review_path = RUNTIME_ROOT / "reviews.db"
    audit_path = RUNTIME_ROOT / "security_events.db"
    initialize_demo_databases(records_path, outbox_path)
    initialize_review_database(review_path)
    initialize_audit_database(audit_path)
    queue = ReviewQueue(review_path)
    inspector = ContentInspector(
        assessor=OllamaContentAssessor(), require_assessment_for_untrusted=True
    )
    retrieval = SecureDocumentRetrieval(
        ActionGateway(
            ControlledTools(PROJECT_ROOT / "sample_data" / "documents", records_path, outbox_path)
        ),
        inspector,
        queue,
    )
    return inspector, retrieval, queue, AuditLog(audit_path)


def show_inspection(result) -> None:
    """Render an inspection result without hiding its decision evidence."""
    if result.decision is ContentDecision.PASS:
        st.success("PASS")
    elif result.decision is ContentDecision.SANITIZE:
        st.warning("SANITIZE")
    else:
        st.error("HOLD FOR REVIEW")
    st.write(result.reason)
    st.caption(f'Inspection duration: {result.duration_ms:.1f} ms')
    if result.detector_outputs:
        st.dataframe([output.model_dump() for output in result.detector_outputs], hide_index=True)
    if result.model_assessment:
        st.caption(
            f"Local model assessment: {result.model_assessment.risk} — "
            f"{result.model_assessment.reason}"
        )
    if result.findings:
        st.dataframe([finding.model_dump() for finding in result.findings], hide_index=True)
    if result.sanitized_content:
        st.text_area("Content available after inspection", result.sanitized_content, height=180)


st.set_page_config(page_title="Security Middleware", layout="wide")
st.title("AI Agent Security Middleware")
st.caption("Local prompt inspection, secure document retrieval, and review workflow.")

inspector, retrieval, review_queue, audit_log = services()
analysis_tab, retrieval_tab, review_tab, audit_tab = st.tabs(
    ["Analyze text", "Secure retrieval", "Review queue", "Security events"]
)

with analysis_tab:
    st.subheader("Prompt and content inspection")
    mode = st.selectbox('Detection configuration', ['Rules + Qwen', 'Rules only', 'Rules + ML', 'Rules + ML + Qwen'])
    user_text = st.text_area("Text to inspect", height=220, max_chars=20_000)
    if st.button("Analyze text", type="primary"):
        envelope = ContentEnvelope(
            source_id="dashboard-input",
            content_id=str(uuid4()),
            origin_trust=OriginTrust.UNTRUSTED,
            data_sensitivity=DataSensitivity.PUBLIC,
            content=user_text,
        )
        selected_inspector = ContentInspector(
            assessor=OllamaContentAssessor() if 'Qwen' in mode else None,
            require_assessment_for_untrusted='Qwen' in mode,
            detector=current_classifier() if 'ML' in mode else None,
        )
        with st.spinner('Inspecting content…'):
            result = selected_inspector.inspect(envelope)
        audit_log.record(
            "content_inspection",
            result.reason,
            {
                "source_id": envelope.source_id,
                "content_id": envelope.content_id,
                "finding_count": len(result.findings),
                "model_risk": result.model_assessment.risk if result.model_assessment else None,
                "configuration": mode,
                "duration_ms": result.duration_ms,
            },
            decision=result.decision.value,
        )
        if result.decision is ContentDecision.HOLD_FOR_REVIEW:
            item = review_queue.create(envelope, result)
            st.info(f"Stored as review item #{item.review_id}.")
        st.session_state['last_inspection'] = (mode, user_text, result)
    previous = st.session_state.get('last_inspection')
    if previous and previous[:2] == (mode, user_text):
        show_inspection(previous[2])

with retrieval_tab:
    st.subheader("Gateway-protected document retrieval")
    document_id = st.selectbox("Approved document", sorted(DOCUMENT_FILES))
    if st.button("Retrieve document"):
        task_id = f"ui-retrieval-{uuid4()}"
        result = retrieval.retrieve(task_id, document_id)
        audit_log.record(
            "secure_document_retrieval",
            result.inspection.reason if result.inspection else result.action.reason,
            {"document_id": document_id, "review_id": result.review_id},
            task_id=task_id,
            decision=result.inspection.decision.value if result.inspection else result.action.decision.value,
        )
        st.caption(
            f"Gateway: {result.action.decision.value} / "
            f"{result.action.execution_outcome.value}"
        )
        if result.inspection:
            show_inspection(result.inspection)
        else:
            st.error(result.action.reason)
        if result.review_id:
            st.info(f"Stored as review item #{result.review_id}.")

with review_tab:
    st.subheader("Pending human review")
    pending_items = review_queue.pending()
    if not pending_items:
        st.info("No content is waiting for review.")
    for item in pending_items:
        with st.expander(f"Review #{item.review_id}: {item.content_id}"):
            st.write(item.reason)
            st.text_area("Held content", item.content, key=f"content-{item.review_id}", height=130)
            excerpt = st.text_area("Approved excerpt", key=f"excerpt-{item.review_id}")
            first, second = st.columns(2)
            if first.button("Approve excerpt", key=f"approve-{item.review_id}"):
                try:
                    review_queue.decide(item.review_id, ReviewDecision.APPROVED, excerpt)
                    audit_log.record("review_decision", "Reviewer approved a specific excerpt.", {"review_id": item.review_id}, decision="APPROVED")
                    st.rerun()
                except ValueError as error:
                    st.error(str(error))
            if second.button("Reject content", key=f"reject-{item.review_id}"):
                review_queue.decide(item.review_id, ReviewDecision.REJECTED)
                audit_log.record("review_decision", "Reviewer rejected held content.", {"review_id": item.review_id}, decision="REJECTED")
                st.rerun()

with audit_tab:
    st.subheader("Recent security events")
    events = audit_log.recent()
    if events:
        st.dataframe([event.model_dump() for event in events], hide_index=True, width="stretch")
    else:
        st.info("No events have been recorded yet.")
