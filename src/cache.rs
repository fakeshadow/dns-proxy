use core::time::Duration;

use alloc::sync::Arc;

use std::{collections::HashMap, sync::RwLock as StdRwLock, time::Instant};

use tokio::{sync::RwLock, task::JoinHandle};

/// a simple cache just use query bytes and result bytes as key value pair.
pub struct Cache {
    timer: LowResTimer,
    inner: RwLock<HashMap<Key, (Val, Instant)>>,
    ttl: Duration,
}

type Key = Box<[u8]>;
type KeyRef<'a> = &'a [u8];
type Val = Arc<[u8]>;

impl Cache {
    pub fn new() -> Self {
        Self::with_ttl(Duration::from_secs(120))
    }

    pub fn with_ttl(ttl: impl Into<Duration>) -> Self {
        Self {
            timer: LowResTimer::new(),
            inner: RwLock::new(HashMap::new()),
            ttl: ttl.into(),
        }
    }

    pub async fn set(&self, key: Key, val: Val) -> Val {
        self.inner
            .write()
            .await
            .entry(key)
            .or_insert((val, Instant::now()))
            .0
            .clone()
    }

    pub async fn try_get(&self, key: KeyRef<'_>) -> Option<Val> {
        let guard = self.inner.read().await;
        if let Some((val, inst)) = guard.get(key) {
            if (self.timer.now() - *inst) < self.ttl {
                return Some(val.clone());
            }

            drop(guard);
            self.inner.write().await.remove(key);
        }

        None
    }
}

// a low resolution timer update itself every second.
struct LowResTimer {
    handle: JoinHandle<()>,
    time: Arc<StdRwLock<Instant>>,
}

impl LowResTimer {
    fn new() -> Self {
        let time = Arc::new(StdRwLock::new(Instant::now()));
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

#[cfg(test)]
mod test {
    use super::*;

    #[tokio::test]
    async fn cache() {
        let cache = Cache::with_ttl(Duration::from_secs(1));

        let val = cache
            .set(b"123".to_vec().into(), b"321".to_vec().into())
            .await;

        assert_eq!(val.as_ref(), b"321");
        let val2 = cache.try_get(b"123").await.unwrap();
        assert_eq!(val, val2);

        tokio::time::sleep(Duration::from_secs(2)).await;
        assert!(cache.try_get(b"123").await.is_none());
    }
}
