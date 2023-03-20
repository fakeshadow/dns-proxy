use core::time::Duration;

use alloc::sync::Arc;

use std::{collections::HashMap, sync::RwLock, time::Instant};

use tokio::task::JoinHandle;
use tracing::trace;

use crate::dns::{DnsBuf, DnsPacket, DnsRecord};

/// a simple cache just use query bytes and result bytes as key value pair.
pub struct Cache {
    timer: LowResTimer,
    inner: RwLock<HashMap<String, (DnsRecord, Instant)>>,
}

impl Cache {
    pub fn new() -> Self {
        Self {
            timer: LowResTimer::new(),
            inner: RwLock::new(HashMap::new()),
        }
    }

    pub fn set(&self, buf: &mut [u8]) {
        let mut packet = DnsPacket::new();
        if packet.read(&mut DnsBuf::new(buf)).is_ok() {
            let mut guard = self.inner.write().unwrap();
            for a in packet.answers {
                trace!("setting cache record: {a:?}");
                guard.insert(a.name().into(), (a, self.timer.now()));
            }
        }
    }

    pub fn get(&self, buf: &mut [u8]) -> Option<Vec<u8>> {
        let mut packet = DnsPacket::new();

        packet.read(&mut DnsBuf::new(buf)).ok()?;

        {
            let guard = self.inner.read().unwrap();

            for q in packet.questions.iter() {
                let (val, creation) = guard.get(q.name.as_str())?;

                if self.timer.now().duration_since(*creation).as_secs() >= val.ttl() as u64 {
                    return None;
                }

                trace!("got cache record: {val:?}");

                packet.answers.push(val.clone());
            }
        }

        let mut buf = vec![0; 512];
        let dns_buf = &mut DnsBuf::new(&mut buf);
        packet.write(dns_buf).ok().map(|_| {
            buf.truncate(dns_buf.pos);
            buf
        })
    }
}

// a low resolution timer update itself every second.
struct LowResTimer {
    handle: JoinHandle<()>,
    time: Arc<RwLock<Instant>>,
}

impl LowResTimer {
    fn new() -> Self {
        let time = Arc::new(RwLock::new(Instant::now()));
        let time_clone = time.clone();
        let mut interval = tokio::time::interval(Duration::from_secs(1));
        let handle = tokio::task::spawn(async move {
            loop {
                interval.tick().await;
                *time_clone.write().unwrap() = Instant::now();
            }
        });

        Self { handle, time }
    }

    fn now(&self) -> Instant {
        *self.time.read().unwrap()
    }
}

impl Drop for LowResTimer {
    fn drop(&mut self) {
        self.handle.abort();
    }
}

// #[cfg(test)]
// mod test {
//     use super::*;
//
//     #[tokio::test]
//     async fn cache() {
//         let cache = Cache::with_ttl(Duration::from_secs(1));
//
//         let val = cache
//             .set(b"123".to_vec().into(), b"321".to_vec().into())
//             .await;
//
//         assert_eq!(val.as_ref(), b"321");
//         let val2 = cache.try_get(b"123").await.unwrap();
//         assert_eq!(val, val2);
//
//         tokio::time::sleep(Duration::from_secs(2)).await;
//         assert!(cache.try_get(b"123").await.is_none());
//     }
// }
