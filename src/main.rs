use std::{fmt::Display, net::IpAddr, time::Duration};

use anyhow::{Context, anyhow};
use rand::seq::SliceRandom;
use serde::{Serialize, Serializer};
use tracing::{debug, error, instrument};
use trippy_core::{
    CompletionReason, MultipathStrategy, PortDirection, Probe, ProbeComplete, ProbeStatus,
    Protocol, Round,
};

/// Traceroute data for a particular app.
/// It includes the `Flow`s recorded for an app related to `AppDetails`.
#[derive(Debug, Serialize)]
pub struct TracerouteData {
    flows: Vec<Flow>,
    destination_ip: IpAddr,
}

#[instrument(ret)]
fn dublin_traceroute(url: &str, max_ttl: u8, num_rounds: usize) -> anyhow::Result<TracerouteData> {
    let host_lookup = dns_lookup::lookup_host(url)?;
    debug!(?host_lookup);
    let destination_ip = host_lookup
        .first() // just selecting the first resolved ip addr
        .ok_or_else(|| anyhow!("host lookup didn't give an ip"))?
        .clone();

    let random_source_ports = {
        let mut rng = rand::rng();
        let mut ephemeral_source_port_range: Vec<u16> = (49152..=49200).collect();
        ephemeral_source_port_range.shuffle(&mut rng);
        ephemeral_source_port_range
            .into_iter()
            .take(num_rounds)
            .collect::<Vec<_>>()
    };
    debug!(
        ?random_source_ports,
        "going to trace different flows from the following source ports"
    );
    let mut outputs = Vec::new();
    for source_port in random_source_ports {
        debug!("starting traceroute from port {}", source_port);
        let output = dublin_traceroute_single_run(destination_ip, max_ttl, source_port);
        outputs.push(output);
    }

    let traceroutes = outputs
        .into_iter()
        .filter_map(|res| {
            res.map_err(|e| error!(error = ?e, "error in doing a round of traceroute"))
                .ok()
        })
        .collect();
    Ok(TracerouteData {
        flows: traceroutes,
        destination_ip,
    })
}

#[instrument(ret)]
fn dublin_traceroute_single_run(
    destination: IpAddr,
    max_ttl: u8,
    source_port: u16,
) -> anyhow::Result<Flow> {
    debug!("building tracer");
    let tracer = trippy_core::Builder::new(destination)
        .max_round_duration(Duration::from_secs(2))
        .protocol(Protocol::Udp)
        .multipath_strategy(MultipathStrategy::Dublin)
        .port_direction(PortDirection::new_fixed_both(source_port, 33434)) // see https://trippy.rs/guides/recommendation/#udpdublin-with-fixed-target-port-and-variable-source-port
        .max_ttl(max_ttl)
        .max_rounds(Some(1))
        .build()
        .context("should be able to build Tracer")?;

    let (tx, rx) = std::sync::mpsc::channel();

    tracer
        .run_with(move |round| {
            let traced_route = round.into();
            _ = tx.send(traced_route).unwrap(); //unwrapping cus receiver is there to receive it
        })
        .context("should be able to spawn traceroute rounds")?;

    let traced_route = rx
        .recv()
        .map_err(|e| anyhow!("tracer didn't send the flow data: {}", e))?;

    Ok(traced_route)
}

#[derive(Debug, Serialize)]
pub struct Flow {
    hops: Vec<Hop>,
    max_ttl: u8,
    #[serde(serialize_with = "serialize_completion_reason")]
    completion_reason: CompletionReason,
}

impl From<&Round<'_>> for Flow {
    fn from(round: &Round) -> Self {
        let hops = round
            .probes
            .iter()
            .filter_map(|probe| probe.try_into().ok())
            .collect::<Vec<Hop>>();

        Self {
            hops,
            max_ttl: round.largest_ttl.0,
            completion_reason: round.reason,
        }
    }
}

impl Display for Flow {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "flow: ")?;
        for hop in &self.hops {
            write!(f, "{}", hop)?;
        }
        writeln!(f)
    }
}

#[derive(Debug, Serialize)]
pub enum Hop {
    Completed {
        ttl: u8,
        #[serde(serialize_with = "serialize_duration_as_ms")]
        rtt: Duration,
        host: IpAddr,
    },
    TimedOut {
        ttl: u8,
    },
}

impl<'a> TryFrom<&'a ProbeStatus> for Hop {
    type Error = anyhow::Error;

    fn try_from(probe: &ProbeStatus) -> Result<Self, Self::Error> {
        use ProbeStatus::*;
        match probe {
            NotSent | Skipped | Failed(_) => Err(anyhow!("probe could not be sent")),
            Awaited(Probe { ttl, .. }) => Ok(Hop::TimedOut { ttl: ttl.0 }),
            Complete(ProbeComplete {
                ttl,
                sent,
                received,
                host,
                ..
            }) => Ok(Hop::Completed {
                ttl: ttl.0,
                rtt: received.duration_since(*sent)?,
                host: *host,
            }),
        }
    }
}

impl Display for Hop {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Hop::Completed { ttl, rtt, host } => {
                write!(f, "({}: {}ms {})", ttl, rtt.as_millis(), host)
            }
            Hop::TimedOut { ttl } => write!(f, "({}: *)", ttl),
        }
    }
}

fn serialize_duration_as_ms<S>(duration: &Duration, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    serializer.serialize_u128(duration.as_millis())
}

fn serialize_completion_reason<S>(
    reason: &CompletionReason,
    serializer: S,
) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    match reason {
        CompletionReason::TargetFound => serializer.serialize_str("target found"),
        CompletionReason::RoundTimeLimitExceeded => {
            serializer.serialize_str("round time limit exceeded")
        }
    }
}

/// Spawns a traceroute worker task that will periodically gather traceroute data
/// for all apps in `APP_DETAILS`and returns a handle to it that can be used to
/// receive the polled data through `Self::try_to_get_traceroute_data`
pub fn spawn_traceroute_worker() -> TracerouteHandle {
    TracerouteHandle::new(Duration::from_secs(60), vec!["example.com".into()])
}

/// A handle to a spawned task that will take
/// care of gathering traceroute data for all apps within APP_DETAILS.
pub struct TracerouteHandle {
    receiver: tokio::sync::mpsc::Receiver<Vec<TracerouteData>>,
}

impl TracerouteHandle {
    /// gathers all the `TracerouteData` queued in the channel from the spawned traceroute task
    /// and returns it
    pub async fn try_to_get_traceroute_data(&mut self) -> Vec<TracerouteData> {
        self.receiver.try_recv().unwrap_or_default()
    }

    fn new(interval: Duration, urls: Vec<String>) -> Self {
        let mut interval = tokio::time::interval(interval);
        let (tx, rx) = tokio::sync::mpsc::channel(1);
        let _ = tokio::spawn(async move {
            loop {
                interval.tick().await;

                let mut results = Vec::new();

                for url in &urls {
                    let url = url.clone();
                    let join_handle =
                        tokio::task::spawn_blocking(move || dublin_traceroute(&url, 64, 5));
                    let result = join_handle.await.ok().and_then(|inner| inner.ok());
                    if let Some(traceroute_data) = result {
                        results.push(traceroute_data);
                    }
                }

                let _ = tx.send(results).await;
            }
        });

        Self { receiver: rx }
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let filter = "info,testing-traceroute=debug,trippy_core=debug";

    tracing_subscriber::fmt().with_env_filter(filter).init();

    let mut traceroute_handle = spawn_traceroute_worker();

    loop {
        let data = traceroute_handle.try_to_get_traceroute_data().await;
        if !data.is_empty() {
            debug!(?data, "got some traceroute data");
        }
    }

    Ok(())
}
