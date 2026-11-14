use crate::guard::rollback::RollbackEngine;
use anyhow::Result;

pub fn execute() -> Result<()> {
    RollbackEngine::undo()
}
