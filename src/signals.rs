//! Unix signals handling
use tokio::{
    select,
    signal::unix::{Signal, SignalKind, signal},
    sync::watch,
};
use tracing::{debug, info};

/// Alias for a shutdown channel receiver type
pub type ShutdownReceiver = watch::Receiver<bool>;
/// Alias for a shutdown channel sender type
pub type ShutdownSender = watch::Sender<bool>;

/// Holds handlers to all expected sources
#[derive(Debug)]
pub struct SignalHandler {
    terminate: Signal,
    interrupt: Signal,
    quit: Signal,
    hangup: Signal,
}

impl SignalHandler {
    /// Init struct by handlers
    pub fn new() -> anyhow::Result<Self> {
        Ok(Self {
            terminate: signal(SignalKind::terminate())?,
            interrupt: signal(SignalKind::interrupt())?,
            quit: signal(SignalKind::quit())?,
            hangup: signal(SignalKind::hangup())?,
        })
    }

    /// Wait for ANY signal
    pub async fn wait_for_signal(&mut self) {
        debug!("installing signal handler");
        let signal = select! {
            _ = self.terminate.recv() => "TERM",
            _ = self.interrupt.recv() => "INT",
            _ = self.quit.recv() => "QUIT",
            _ = self.hangup.recv() => "HANGUP",
        };
        info!(%signal, "Signal has been received");
    }
}
