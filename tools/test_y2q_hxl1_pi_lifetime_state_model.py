"""Source-transition-only HXL1 CVE-2026-43499 ownership model tests."""
import unittest
from tools.y2q_hxl1_pi_lifetime_state_model import (
    State,ProxyResult,publish_waiter,source_visible_late_error_rollback,
    original_key_waiter_returns,other_task_repairs_target_pi_reference,summarize)

class ConditionalLifetimeTests(unittest.TestCase):
    def test_published_waiter_not_stale_while_stack_live(self):
        s=publish_waiter(State())
        self.assertTrue(s.target_pi_blocked_on_waiter)
        self.assertFalse(s.stale_target_pi_reference)

    def test_stock_rollback_clears_current_not_target(self):
        s=source_visible_late_error_rollback(publish_waiter(State()),owner_present=True)
        self.assertTrue(s.target_pi_blocked_on_waiter)
        self.assertFalse(s.requeuer_pi_blocked_on_waiter)
        self.assertFalse(s.rt_mutex_wait_tree_has_waiter)
        self.assertFalse(s.q_pi_state_ref)

    def test_only_conditional_stack_return_makes_stale(self):
        s=source_visible_late_error_rollback(publish_waiter(State()),owner_present=True)
        self.assertFalse(s.stale_target_pi_reference)
        self.assertTrue(original_key_waiter_returns(s).stale_target_pi_reference)

    def test_correct_target_identity_prevents_stale_field(self):
        s=source_visible_late_error_rollback(publish_waiter(State()),
                           owner_present=True,corrected_target_identity=True)
        self.assertFalse(original_key_waiter_returns(s).stale_target_pi_reference)

    def test_intervening_clear_is_explicit_alternative(self):
        s=source_visible_late_error_rollback(publish_waiter(State()),owner_present=True)
        s=other_task_repairs_target_pi_reference(s)
        self.assertFalse(original_key_waiter_returns(s).stale_target_pi_reference)

    def test_missing_lock_owner_blocks_specific_rollback_path(self):
        s=source_visible_late_error_rollback(publish_waiter(State()),owner_present=False)
        self.assertEqual(s.reported_proxy_result,ProxyResult.OWNER_MISSING_UNMODELED)
        with self.assertRaises(ValueError):
            original_key_waiter_returns(s)

    def test_prepublication_exit_not_conflated_with_late_error(self):
        s=source_visible_late_error_rollback(State(),owner_present=True)
        self.assertEqual(s.reported_proxy_result,ProxyResult.PRE_PUBLICATION_UNMODELED)
        self.assertFalse(s.stale_target_pi_reference)

    def test_publication_requires_live_target_stack_object(self):
        with self.assertRaises(ValueError):
            publish_waiter(State(target_stack_waiter_alive=False))

    def test_abstract_model_never_claims_factory_trace(self):
        a=summarize()
        self.assertIsNone(a["late_error_and_owner_jointly_feasible_on_factory"])
        self.assertFalse(a["real_target_return_or_stale_dereference_observed"])
        self.assertFalse(a["device_test_or_root_performed"])

if __name__=="__main__":unittest.main()
