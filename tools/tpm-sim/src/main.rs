//! Serves the firmware's TPM over the TPM simulator's socket protocol, so
//! `tpm2-tools` and anything else that speaks to `swtpm` or the Microsoft
//! simulator can drive it:
//!
//!     tpm-sim [--fused] [PORT]
//!     TPM2TOOLS_TCTI=mssim:host=127.0.0.1,port=PORT tpm2_getcap properties-fixed
//!
//! The command port is PORT (2321) and the platform port PORT + 1. `--fused`
//! gives the TPM a test device private key, so the primary keys are the same on
//! every run.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::Mutex;
use std::thread;

use tpm_sim::{otp, tpm2};

const SEND_COMMAND: u32 = 8;
const SESSION_END: u32 = 20;
const STOP: u32 = 21;

/// One command at a time, as the TPM takes them.
static LOCK: Mutex<()> = Mutex::new(());

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn u32_from(stream: &mut TcpStream) -> std::io::Result<u32> {
    let mut b = [0u8; 4];
    stream.read_exact(&mut b)?;
    Ok(u32::from_be_bytes(b))
}

fn platform(mut stream: TcpStream) {
    while let Ok(_command) = u32_from(&mut stream) {
        if stream.write_all(&0u32.to_be_bytes()).is_err() {
            break;
        }
    }
}

fn commands(mut stream: TcpStream) {
    while let Ok(command) = u32_from(&mut stream) {
        match command {
            SEND_COMMAND => {
                let mut locality = [0u8; 1];
                let Ok(()) = stream.read_exact(&mut locality) else { break };
                let Ok(length) = u32_from(&mut stream) else { break };
                let mut request = vec![0u8; length as usize];
                let Ok(()) = stream.read_exact(&mut request) else { break };
                let mut response = vec![0u8; tpm2::MAX_COMMAND];
                let n = {
                    let _one = LOCK.lock().unwrap();
                    if request.len() > tpm2::MAX_COMMAND {
                        break;
                    }
                    let n = tpm2::execute(&request, &mut response);
                    if std::env::var_os("TPM_SIM_TRACE").is_some() {
                        eprintln!("> {}\n< {}", hex(&request), hex(&response[..n]));
                    }
                    n
                };
                let mut reply = Vec::new();
                reply.extend_from_slice(&(n as u32).to_be_bytes());
                reply.extend_from_slice(&response[..n]);
                reply.extend_from_slice(&0u32.to_be_bytes());
                if stream.write_all(&reply).is_err() {
                    break;
                }
            }
            SESSION_END | STOP => break,
            _ => {
                if stream.write_all(&0u32.to_be_bytes()).is_err() {
                    break;
                }
            }
        }
    }
}

fn serve(port: u16, handler: fn(TcpStream)) -> thread::JoinHandle<()> {
    let listener = TcpListener::bind(("127.0.0.1", port)).unwrap_or_else(|e| panic!("port {port}: {e}"));
    thread::spawn(move || {
        for stream in listener.incoming().flatten() {
            thread::spawn(move || handler(stream));
        }
    })
}

fn main() {
    let mut port = 2321u16;
    for arg in std::env::args().skip(1) {
        match arg.as_str() {
            "--fused" => {
                let mut rows = otp::ROWS.lock().unwrap();
                for (i, row) in rows.iter_mut().enumerate() {
                    *row = 0xc0de_2001 + 0x1111 * i as u32;
                }
            }
            other => port = other.parse().unwrap_or_else(|_| panic!("not a port: {other}")),
        }
    }
    let commands = serve(port, commands);
    let _platform = serve(port + 1, platform);
    eprintln!("tpm-sim: commands on port {port}, platform on port {}", port + 1);
    commands.join().unwrap();
}
