// use crate::{
//     proto::{grouping::ThreeDRange, keys::NamespaceId, wgps::AreaOfInterestHandle},
//     store::{Store, SyncConfig},
//     session::Error,
// };

// pub struct SplitRange<S> {
//     snapshot: Snapshot<S>,
//     args: SplitRangeArgs,
//     config: SyncConfig,
// }
//
// pub struct SplitRangeArgs {
//     namespace: NamespaceId,
//     range: ThreeDRange,
//     our_handle: AreaOfInterestHandle,
//     their_handle: AreaOfInterestHandle,
// }
//
// pub enum Yield {
//     Done,
//     OutboxFull,
// }
//
// fn run<S: Store>(mut state: SplitRange<S>) -> Result<(), Error> {
//     let SplitRange {
//         snapshot: store,
//         args,
//         config,
//     } = &mut state;
//     let iter = store.split_range(args.namespace, &args.range, &config)?;
//     Ok(())
// }
