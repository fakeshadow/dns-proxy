use core::time::Duration;

use alloc::sync::Arc;

use std::{collections::HashMap, sync::RwLock, time::Instant};

use tokio::task::JoinHandle;
use tracing::trace;

use crate::dns::{DnsBuf, DnsPacket, DnsQuestion, DnsRecord};

/// a simple cache just use query bytes and result bytes as key value pair.
pub struct Cache {
    timer: LowResTimer,
    inner: RwLock<HashMap<Key, CacheEntry>>,
}

type Key = Box<[DnsQuestion]>;

struct CacheEntry {
    answers: Box<[DnsRecord]>,
    creation: Instant,
}

impl CacheEntry {
    fn new(answers: Box<[DnsRecord]>) -> Self {
        Self {
            answers,
            creation: Instant::now(),
        }
    }

    fn is_expired(&self, now: Instant) -> bool {
        self.answers
            .iter()
            .any(|answer| now.duration_since(self.creation).as_secs() >= answer.ttl() as u64)
    }

    fn answers(&self) -> &[DnsRecord] {
        &self.answers
    }
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
            let questions = packet.questions.into_boxed_slice();
            trace!("setting cache record: {:?}", questions);
            self.inner.write().unwrap().insert(
                questions,
                CacheEntry::new(packet.answers.into_boxed_slice()),
            );
        }
    }

    pub fn get(&self, buf: &mut [u8]) -> Option<Vec<u8>> {
        let mut packet = DnsPacket::new_ref();

        packet.read(&mut DnsBuf::new(buf)).ok()?;

        let guard = self.inner.read().unwrap();

        let entry = guard.get(packet.questions.as_slice())?;

        if entry.is_expired(self.timer.now()) {
            return None;
        }

        let answers = entry.answers();
        trace!("got cache records: {answers:?}");
        packet.answers = answers;

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
