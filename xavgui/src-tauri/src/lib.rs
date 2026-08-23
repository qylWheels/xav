// Learn more about Tauri commands at https://tauri.app/develop/calling-rust/
#[tauri::command]
fn greet(name: &str) -> String {
    format!("Hello, {}! You've been greeted from Rust!", name)
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_websocket::init())
        .plugin(tauri_plugin_opener::init())
        .invoke_handler(tauri::generate_handler![greet])
        .setup(|app| {
            use tauri::async_runtime;
            use tauri::Emitter;
            use tokio_seqpacket::UnixSeqpacket;

            let app_handle = app.handle().clone();
            println!("ready to start async task");
            async_runtime::spawn(async move {
                let mut socket =
                    UnixSeqpacket::connect("\0xavcore_on_access_scanning_module_socket").await;
                if let Err(e) = socket {
                    println!("error while connecting to socket: {}", e);
                    return Ok(());
                }
                let socket = socket.unwrap();
                let mut buffer = vec![0u8; 1024];
                loop {
                    let msg = socket.recv(&mut buffer).await?;
                    let len = msg.bytes_read();
                    let path = String::from_utf8_lossy(&buffer[..len]);
                    println!("len: {}, content: {}", len, path);
                    app_handle.emit("threat-detected", path);
                }
                Ok::<(), std::io::Error>(())
            });

            Ok(())
        })
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
