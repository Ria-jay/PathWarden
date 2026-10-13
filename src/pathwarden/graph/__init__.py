"""Typed, permission-aware security graph."""

from __future__ import annotations

from pathwarden.graph.build import build_graph
from pathwarden.graph.export import graph_to_dict, graph_to_dot, graph_to_json, graph_to_mermaid
from pathwarden.graph.model import EdgeType, NodeType, SecurityGraph
from pathwarden.graph.permissions import (
    ApprovalAssessment,
    ApprovalAssessmentStatus,
    PermissionResult,
    PermissionStep,
    assess_approval,
    check_destinations,
    evaluate_access,
    fold_statuses,
)

__all__ = [
    "ApprovalAssessment",
    "ApprovalAssessmentStatus",
    "EdgeType",
    "NodeType",
    "PermissionResult",
    "PermissionStep",
    "SecurityGraph",
    "assess_approval",
    "build_graph",
    "check_destinations",
    "evaluate_access",
    "fold_statuses",
    "graph_to_dict",
    "graph_to_dot",
    "graph_to_json",
    "graph_to_mermaid",
]
