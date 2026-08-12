use ccos_research_lab::event_log::EventLog;
use ccos_research_lab::scientific_intake::import_scientific_bundle;

const FIXTURE: &str = include_str!("fixtures/scientific_bundle_v1.json");

#[test]
fn canonical_bundle_v1_is_accepted_and_attested() {
    let mut log = EventLog::new("canonical-science-fixture".into());
    let receipt = import_scientific_bundle(FIXTURE, &mut log)
        .expect("canonical scientific bundle v1 must be accepted");

    assert_eq!(receipt.paper_id, "fixture-paper-1");
    assert_eq!(
        receipt.claim_ids,
        vec!["claim-fixture-1", "method-fixture-1"]
    );
    assert!(receipt.proposal_ids.is_empty());
    assert_eq!(log.event_count(), 3);
    assert!(log.verify_integrity().valid);
    assert_eq!(receipt.chain_head, log.chain_head());
}
