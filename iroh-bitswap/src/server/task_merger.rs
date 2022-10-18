use cid::Cid;

use crate::peer_task_queue::Task;

/// Extra data associated with each task in the request queue.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TaskData {
    /// Tasks can be either want-have or want-block.
    pub is_want_block: bool,
    /// Wether to immediately send a response if teh block is not found.
    pub send_dont_have: bool,
    /// The size of the block corresponding to the task.
    pub block_size: usize,
    /// Wether the block was found.
    pub have_block: bool,
}

#[derive(Default, Debug, Clone, PartialEq, Eq)]
pub struct TaskMerger {}

impl crate::peer_task_queue::TaskMerger<Cid, TaskData> for TaskMerger {
    fn has_new_info(&self, task: &Task<Cid, TaskData>, existing: &[Task<Cid, TaskData>]) -> bool {
        let mut have_size = false;
        let mut is_want_block = false;

        for entry in existing {
            if entry.data.have_block {
                have_size = true;
            }
            if entry.data.is_want_block {
                is_want_block = true;
            }
        }

        // If there is no active want-block and the new task is a want-block
        // the new task is better.
        let new_task_data = &task.data;
        if !is_want_block && new_task_data.is_want_block {
            return true;
        }

        // If there is no size information for the Cid and the new taks has size
        // information, the new task is better.
        if !have_size && new_task_data.have_block {
            return true;
        }

        false
    }

    fn merge(&self, task: &Task<Cid, TaskData>, existing: &mut Task<Cid, TaskData>) {
        let new_task = &task.data;
        let existing_task = &mut existing.data;

        // If we now have block size information, update the task with the new block size.
        if !existing_task.have_block && new_task.have_block {
            existing_task.have_block = new_task.have_block;
            existing_task.block_size = new_task.block_size;
        }

        // If replacing a want-ahve with a want-block
        if !existing_task.is_want_block && new_task.is_want_block {
            // Change the type form want-have to want-block.
            existing_task.is_want_block = true;
            // If the want-have was a DONT_HAVAE, or the want-block has a size
            if !existing_task.have_block || new_task.have_block {
                // Update the entry size
                existing_task.have_block = new_task.have_block;
                existing.work = task.work;
            }
        }

        // If the task is a want-block, make sure the entry size is equal to the block size
        // (because we will send the whole block)
        if existing_task.is_want_block && existing_task.have_block {
            existing.work = existing_task.block_size;
        }
    }
}
