use aegisguard::{audit, evaluate, EvaluateRequest};
use std::{env, fs, io::{BufRead, BufReader, Write}, os::unix::net::{UnixListener, UnixStream}, path::PathBuf, thread};

fn client(stream: UnixStream, audit_path: PathBuf) {
    let reader = BufReader::new(stream.try_clone().expect("clone socket")); let mut writer = stream;
    for line in reader.lines() {
        let output = match line { Ok(line) => match EvaluateRequest::from_json_line(&line) { Ok(request) => { let response = evaluate(&request); let _ = audit::record(&audit_path, &request.command, &response); response.to_json() }, Err(error) => format!("{{\"error\":\"{}\"}}", error) }, Err(_) => break };
        if writer.write_all(output.as_bytes()).and_then(|_| writer.write_all(b"\n")).is_err() { break; }
    }
}

fn main() -> std::io::Result<()> {
    let socket = env::var_os("AEGISGUARD_SOCKET").map(PathBuf::from).unwrap_or_else(|| PathBuf::from("/tmp/aegisguard.sock")); let _ = fs::remove_file(&socket);
    if let Some(parent) = socket.parent() { fs::create_dir_all(parent)?; }
    let listener = UnixListener::bind(&socket)?; let audit = env::var_os("AEGISGUARD_AUDIT").map(PathBuf::from).unwrap_or_else(|| PathBuf::from("aegisguard.audit.jsonl"));
    for stream in listener.incoming() { match stream { Ok(stream) => { let audit = audit.clone(); thread::spawn(move || client(stream, audit)); }, Err(error) => eprintln!("aegisguardd: {error}"), } }
    Ok(())
}
