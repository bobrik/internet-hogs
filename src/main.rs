use std::{
    collections::{BTreeMap, HashMap},
    env,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    process::exit,
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use axum::{extract::State, routing::get, Router};
use clickhouse::{Client, Row};
use netflow_parser::{
    variable_versions::{data_number::FieldValue, ipfix_lookup::IPFixField},
    NetflowPacket, NetflowParser,
};
use prometheus_client::{
    encoding::text::encode,
    metrics::{counter::Counter, family::Family},
    registry::Registry,
};
use serde::Serialize;
use tokio::{
    net::{TcpListener, UdpSocket},
    spawn,
};

const EMPTY_MAC: &str = "00:00:00:00:00:00";

#[derive(Default)]
struct AppState {
    registry: Registry,
}

#[tokio::main]
async fn main() {
    let mut args = env::args().skip(1);

    let Some(ipfix_addr) = args.next() else {
        eprintln!("Missing ipfix address. Expected arguments: <ipfix bind address> <metrics bind address>");
        exit(1);
    };

    let Some(metrics_addr) = args.next() else {
        eprintln!("Missing metrics address. Expected arguments: <ipfix bind address> <metrics bind address>");
        exit(1);
    };

    let socket = UdpSocket::bind(ipfix_addr).await.unwrap();

    let mut registry = Registry::default();
    let family = Family::<Vec<(String, String)>, Counter>::default();

    registry.register(
        "ipfix_bytes_received_total",
        "Total number of bytes received by a local IP.",
        family.clone(),
    );

    let client = Client::default().with_url("http://ip6-localhost:8123");

    spawn(measure(socket, client, family));

    let state = Arc::new(AppState { registry });

    let app = Router::new()
        .route("/metrics", get(metrics))
        .with_state(state);

    let listener = TcpListener::bind(metrics_addr).await.unwrap();

    axum::serve(listener, app).await.unwrap();
}

#[derive(Row, Serialize)]
struct IpFixRow {
    #[serde(rename = "insertionTime")]
    insertion_time: i64,
    #[serde(rename = "clientMac")]
    client_mac: u64,
    #[serde(rename = "clientIPv4", with = "clickhouse::serde::ipv4")]
    client_ipv4: Ipv4Addr,
    #[serde(rename = "clientIPv6")]
    client_ipv6: Ipv6Addr,
    #[serde(rename = "clientPort")]
    client_port: u16,
    #[serde(rename = "serverIPv4", with = "clickhouse::serde::ipv4")]
    server_ipv4: Ipv4Addr,
    #[serde(rename = "serverIPv6")]
    server_ipv6: Ipv6Addr,
    #[serde(rename = "serverPort")]
    server_port: u16,
    protocol: u8,
    packets: u32,
    bytes: u32,
    is_download: bool,
}

impl IpFixRow {
    #[allow(clippy::too_many_arguments)]
    fn new(
        client_mac: &str,
        client_addr: IpAddr,
        client_port: u16,
        server_addr: IpAddr,
        server_port: u16,
        protocol: u8,
        packets: u32,
        bytes: u32,
        is_download: bool,
    ) -> Self {
        let insertion_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;

        let (client_ipv4, client_ipv6) = match client_addr {
            IpAddr::V4(ipv4_addr) => (ipv4_addr, Ipv6Addr::UNSPECIFIED),
            IpAddr::V6(ipv6_addr) => (Ipv4Addr::UNSPECIFIED, ipv6_addr),
        };

        let (server_ipv4, server_ipv6) = match server_addr {
            IpAddr::V4(ipv4_addr) => (ipv4_addr, Ipv6Addr::UNSPECIFIED),
            IpAddr::V6(ipv6_addr) => (Ipv4Addr::UNSPECIFIED, ipv6_addr),
        };

        let client_mac = u64::from_str_radix(&client_mac.replace(':', ""), 16).unwrap();

        Self {
            insertion_time,
            client_mac,
            client_ipv4,
            client_ipv6,
            client_port,
            server_ipv4,
            server_ipv6,
            server_port,
            protocol,
            is_download,
            packets,
            bytes,
        }
    }
}

macro_rules! extract_field {
    ($map:ident, $key:expr, $output:ty) => {
        <$output>::try_from($map.get(&$key).unwrap()).unwrap()
    };

    ($map:ident, $key:expr, $fallback:expr, $output:ty) => {
        <$output>::try_from($map.get(&$key).or_else(|| $map.get(&$fallback)).unwrap()).unwrap()
    };
}

async fn measure(
    socket: UdpSocket,
    client: Client,
    family: Family<Vec<(String, String)>, Counter>,
) {
    let mut inserter = client
        .inserter("ipfix")
        .unwrap()
        .with_timeouts(Some(Duration::from_secs(5)), Some(Duration::from_secs(20)))
        .with_max_bytes(1024 * 1024)
        .with_max_rows(1000)
        .with_period(Some(Duration::from_secs(5)));

    let mut local_ip_to_mac = HashMap::<IpAddr, String>::default();

    let mut parser = NetflowParser::default();

    let mut buf = vec![0u8; 4096];

    while let Ok(size) = socket.recv(&mut buf).await {
        for packet in parser.parse_bytes(&buf[..size]) {
            let NetflowPacket::IPFix(ipfix) = packet else {
                panic!("not ipfix packet: {packet:?}");
            };

            for flowset in ipfix.flowsets {
                if let Some(data) = &flowset.body.data {
                    for data_field in &data.data_fields {
                        let map: BTreeMap<IPFixField, FieldValue> =
                            data_field.values().cloned().collect();

                        let src_mac = extract_field!(
                            map,
                            IPFixField::SourceMacaddress,
                            IPFixField::PostSourceMacaddress,
                            String
                        );

                        let src_addr = extract_field!(
                            map,
                            IPFixField::SourceIpv4address,
                            IPFixField::SourceIpv6address,
                            IpAddr
                        );

                        let src_port = extract_field!(map, IPFixField::SourceTransportPort, u16);

                        let dst_addr = extract_field!(
                            map,
                            IPFixField::DestinationIpv4address,
                            IPFixField::DestinationIpv6address,
                            IpAddr
                        );

                        let dst_port =
                            extract_field!(map, IPFixField::DestinationTransportPort, u16);

                        let protocol = extract_field!(map, IPFixField::ProtocolIdentifier, u8);

                        let packets = extract_field!(map, IPFixField::PacketDeltaCount, u32);

                        let bytes = extract_field!(map, IPFixField::OctetDeltaCount, u32);

                        let direction = extract_field!(map, IPFixField::FlowDirection, u8);

                        let is_download = direction == 0;

                        let (client_addr, client_port, server_addr, server_port, arrow) =
                            if is_download {
                                (dst_addr, dst_port, src_addr, src_port, "<-")
                            } else {
                                (src_addr, src_port, dst_addr, dst_port, "->")
                            };

                        let client = format!("{client_addr}:{client_port}");
                        let server = format!("{server_addr}:{server_port}");

                        let client_mac = if is_download {
                            match local_ip_to_mac.get(&client_addr) {
                                Some(mac) => mac,
                                None => EMPTY_MAC,
                            }
                        } else {
                            if Some(&src_mac) != local_ip_to_mac.get(&client_addr) {
                                local_ip_to_mac.insert(client_addr.clone(), src_mac.clone());
                            }

                            &src_mac
                        };

                        eprintln!("{client_mac} | {client:50} {arrow} {server:50} : [0x{protocol:02x}] {packets:10} packets, {bytes:10} bytes");

                        if is_download {
                            family
                                .get_or_create(&vec![("mac".to_owned(), client_mac.to_string())])
                                .inc_by(bytes as u64);
                        }

                        inserter
                            .write(&IpFixRow::new(
                                client_mac,
                                client_addr,
                                client_port,
                                server_addr,
                                server_port,
                                protocol,
                                packets,
                                bytes,
                                is_download,
                            ))
                            .unwrap();

                        inserter.commit().await.unwrap();
                    }
                }
            }
        }
    }
}

async fn metrics(State(state): State<Arc<AppState>>) -> String {
    let mut buffer = String::new();

    encode(&mut buffer, &state.registry).unwrap();

    buffer
}
