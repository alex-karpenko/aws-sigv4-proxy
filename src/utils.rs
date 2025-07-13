use std::net::SocketAddr;

use crate::{config::Config, signals::ShutdownReceiver};
use http::{Method, Request, Response, StatusCode};
use http_body_util::Full;
use hyper::{
    body::{Bytes, Incoming},
    server::conn::http1,
    service::service_fn,
};
use hyper_util::rt::{TokioIo, TokioTimer};
use tokio::{
    net::TcpListener,
    select,
    task::{self, JoinHandle},
};
use tracing::{debug, error, info};

async fn handler(req: Request<Incoming>) -> anyhow::Result<Response<Full<Bytes>>> {
    match (req.method(), req.uri().path()) {
        (&Method::GET, "/") => health(),
        (&Method::GET, "/health") => health(),
        (&Method::GET, "/metrics") => metrics(),
        // Return "404 Not Found" for other routes.
        _ => {
            let mut not_found = Response::new(Full::from("Not found\n"));
            *not_found.status_mut() = StatusCode::NOT_FOUND;
            Ok(not_found)
        }
    }
}

#[inline]
fn health() -> anyhow::Result<Response<Full<Bytes>>> {
    Ok(Response::new(Full::from("OK\n")))
}

fn metrics() -> anyhow::Result<Response<Full<Bytes>>> {
    let mut response = Response::new(Full::from("Not yet implemented\n"));
    *response.status_mut() = StatusCode::NOT_IMPLEMENTED;
    Ok(response)
    // Implement metrics logic here
}

pub async fn listener(cfg: &Config, mut rx: ShutdownReceiver) -> anyhow::Result<JoinHandle<anyhow::Result<()>>> {
    let addr = SocketAddr::new(cfg.listen_on.ip(), cfg.utility_port);
    let tcp_listener = TcpListener::bind(addr).await?;

    let task = task::spawn(async move {
        let cloned_rx = rx.clone();
        info!("Utility listener started");

        loop {
            select! {
                accepted = tcp_listener.accept() => {
                    let (stream, addr) = accepted?;
                    debug!(from=%addr, "accepted connection");

                    let rx = cloned_rx.clone();
                    let io = TokioIo::new(stream);
                    task::spawn(async move {
                        let _shutdown_guard = rx.has_changed(); // Guard to wait on request completion after shutdown signal
                        if let Err(err) = http1::Builder::new()
                            .timer(TokioTimer::new())
                            .serve_connection(io, service_fn(handler))
                            .await {
                                error!(error = ?err, "Error serving connection");
                        }
                    });
                }
                _ = rx.changed() => {
                    debug!("shutdown signal received");
                    drop(tcp_listener);
                    break;
                }
            }
        }

        Ok(())
    });

    Ok(task)
}
