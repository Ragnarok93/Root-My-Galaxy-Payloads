#!/usr/bin/env python3
"""Offline source-level HXL1 waiter ownership model: NO exploit, device or QEMU actions.

This model tests implications of explicit *assumptions* in Samsung's original
futex and RT-mutex source. It does not establish that a joint runtime
interleaving or any UAF dereference can occur on the factory firmware.
"""
from __future__ import annotations
from dataclasses import dataclass, replace
from enum import Enum

class ProxyResult(str, Enum):
    NONE="no_proxy_result"
    LATE_ERROR_ROLLBACK="late_error_rollback"
    OWNER_MISSING_UNMODELED="owner_missing_normal_continuation"
    PRE_PUBLICATION_UNMODELED="pre_publication_exit"

@dataclass(frozen=True)
class State:
    target_stack_waiter_alive:bool=True
    target_pi_blocked_on_waiter:bool=False
    requeuer_pi_blocked_on_waiter:bool=False
    q_on_original_hash_bucket:bool=True
    q_pi_state_ref:bool=False
    rt_mutex_wait_tree_has_waiter:bool=False
    reported_proxy_result:ProxyResult=ProxyResult.NONE
    original_key_early_exit:bool=False
    @property
    def stale_target_pi_reference(self)->bool:
        return self.target_pi_blocked_on_waiter and not self.target_stack_waiter_alive

def publish_waiter(s:State)->State:
    if not s.target_stack_waiter_alive or s.reported_proxy_result!=ProxyResult.NONE:
        raise ValueError("publication requires live waiter before proxy result")
    return replace(s,target_pi_blocked_on_waiter=True,q_pi_state_ref=True,
                   rt_mutex_wait_tree_has_waiter=True)

def source_visible_late_error_rollback(
        s:State,*,owner_present:bool,corrected_target_identity:bool=False)->State:
    if not s.target_pi_blocked_on_waiter or not s.rt_mutex_wait_tree_has_waiter:
        return replace(s,reported_proxy_result=ProxyResult.PRE_PUBLICATION_UNMODELED)
    if not owner_present:
        return replace(s,reported_proxy_result=ProxyResult.OWNER_MISSING_UNMODELED)
    # Stock clear uses current/requeuer (R); fixed clear uses waiter->task (T).
    return replace(s,rt_mutex_wait_tree_has_waiter=False,q_pi_state_ref=False,
                   target_pi_blocked_on_waiter=(False if corrected_target_identity
                                                else s.target_pi_blocked_on_waiter),
                   requeuer_pi_blocked_on_waiter=False,
                   reported_proxy_result=ProxyResult.LATE_ERROR_ROLLBACK)

def other_task_repairs_target_pi_reference(s:State)->State:
    """Hypothetical repair; no claim it actually happens in Samsung code."""
    return replace(s,target_pi_blocked_on_waiter=False)

def original_key_waiter_returns(s:State)->State:
    if (s.reported_proxy_result!=ProxyResult.LATE_ERROR_ROLLBACK or
        not s.q_on_original_hash_bucket or not s.target_stack_waiter_alive):
        raise ValueError("requires failed rollback and live original-key waiter")
    return replace(s,target_stack_waiter_alive=False,q_on_original_hash_bucket=False,
                   original_key_early_exit=True)

def summarize()->dict:
    base=publish_waiter(State())
    stock=original_key_waiter_returns(
        source_visible_late_error_rollback(base,owner_present=True))
    fixed=original_key_waiter_returns(
        source_visible_late_error_rollback(base,owner_present=True,
                                           corrected_target_identity=True))
    repaired=original_key_waiter_returns(other_task_repairs_target_pi_reference(
        source_visible_late_error_rollback(base,owner_present=True)))
    guard=source_visible_late_error_rollback(base,owner_present=False)
    return {
        "scope":"abstract_conditional_source_transitions_only",
        "different_waiting_and_requeueing_tasks_assumed":True,
        "late_error_and_owner_jointly_feasible_on_factory":None,
        "stock_conditional_stale_pi_pointer":stock.stale_target_pi_reference,
        "fixed_identity_conditional_stale_pi_pointer":fixed.stale_target_pi_reference,
        "intervening_repair_conditional_stale_pi_pointer":repaired.stale_target_pi_reference,
        "owner_missing_suppresses_this_rollback":
            guard.reported_proxy_result==ProxyResult.OWNER_MISSING_UNMODELED,
        "real_target_return_or_stale_dereference_observed":False,
        "device_test_or_root_performed":False,
    }

if __name__=="__main__":
    import json
    print(json.dumps(summarize(),indent=2))
