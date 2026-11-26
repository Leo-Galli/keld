//! Simple request-rate limiter for modules.

use std::time::{Duration, Instant};

/// Caps how often work units may start.
///
/// When `per_second` is `None` or zero, [`wait`](Self::wait) is a no-op.
#[derive(Debug, Clone)]
pub struct RateLimiter {
    min_interval: Option<Duration>,
    last: Option<Instant>,
}

impl RateLimiter {
    /// Limit to about `per_second` starts per second.
    pub fn per_second(per_second: Option<u32>) -> Self {
        let min_interval = per_second
            .filter(|&n| n > 0)
            .map(|n| Duration::from_secs_f64(1.0 / f64::from(n)));
        Self {
            min_interval,
            last: None,
        }
    }

    /// Block (async sleep) until the next unit may start.
    pub async fn wait(&mut self) {
        let Some(interval) = self.min_interval else {
            return;
        };
        if let Some(last) = self.last {
            let elapsed = last.elapsed();
            if elapsed < interval {
                tokio::time::sleep(interval - elapsed).await;
            }
        }
        self.last = Some(Instant::now());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn none_is_noop() {
        let mut lim = RateLimiter::per_second(None);
        let start = Instant::now();
        lim.wait().await;
        lim.wait().await;
        assert!(start.elapsed() < Duration::from_millis(50));
    }

    #[tokio::test]
    async fn rate_spaces_calls() {
        let mut lim = RateLimiter::per_second(Some(50));
        let start = Instant::now();
        lim.wait().await;
        lim.wait().await;
        lim.wait().await;
        assert!(start.elapsed() >= Duration::from_millis(30));
    }
}
