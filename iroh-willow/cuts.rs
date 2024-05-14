
// async fn recv_bulk<const N: usize>(
//     &self,
//     channel: LogicalChannel,
// ) -> Option<anyhow::Result<SmallVec<[Message; N]>>> {
//     let receiver = self.channels.receiver(channel);
//     let mut buf = SmallVec::<[Message; N]>::new();
//     loop {
//         match receiver.read_message_or_set_notify() {
//             Err(err) => return Some(Err(err)),
//             Ok(outcome) => match outcome {
//                 ReadOutcome::Closed => {
//                     if buf.is_empty() {
//                         debug!("recv: closed");
//                         return None;
//                     } else {
//                         return Some(Ok(buf));
//                     }
//                 }
//                 ReadOutcome::ReadBufferEmpty => {
//                     if buf.is_empty() {
//                         self.co
//                             .yield_(Yield::Pending(Readyness::Channel(channel, Interest::Recv)))
//                             .await;
//                     } else {
//                         return Some(Ok(buf));
//                     }
//                 }
//                 ReadOutcome::Item(message) => {
//                     debug!(%message, "recv");
//                     buf.push(message);
//                     if buf.len() == N {
//                         return Some(Ok(buf));
//                     }
//                 }
//             },
//         }
//     }
// }
