pub(crate) use crate::certificate_completion_inbox_load_v2::find_exact;
pub(crate) use crate::certificate_completion_inbox_store_v2::{
    complete, completed_receipt, insert_prepared,
};

pub(crate) struct CompletionInboxRecord {
    pub(crate) received_at_epoch_s: u64,
    pub(crate) recovery_deadline_epoch_s: u64,
    pub(crate) state: String,
    pub(crate) completed_at_epoch_s: Option<u64>,
}
