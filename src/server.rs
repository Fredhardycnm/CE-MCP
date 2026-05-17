//! TCP 客户端模块
//!
//! 本模块实现了一个 TCP 客户端，用于连接 Python Bridge 服务器（bridge_server.py）。
//! 它在一个独立的后台线程中运行，持续监听来自 AI 端的命令，
//! 并通过 crossbeam-channel 将命令传递给 CE 主线程处理。
//!
//! 通信协议：纯文本，一行一条命令。格式为 "COMMAND:参数1,参数2,..."

// 标准库 IO 相关：Read 用于从 TCP 流读取数据，Write 用于发送数据
use std::io::{Read, Write};
// TCP 流连接
use std::net::TcpStream;
// 原子布尔类型，用于线程安全地控制服务器运行状态
use std::sync::atomic::{AtomicBool, Ordering};
// 线程安全共享所有权：Arc（原子引用计数）和 Mutex（互斥锁）
use std::sync::{Arc, Mutex};
// 线程创建和控制
use std::thread;
// 时间间隔，用于连接重试和读取超时
use std::time::Duration;
// crossbeam 通道的发送端，用于将命令发送到主线程
use crossbeam_channel::Sender;
// 命令枚举类型
use crate::protocol::Command;

/// TCP 服务器结构体
///
/// 管理到 Python Bridge 的 TCP 连接，接收命令并转发给主线程处理。
pub struct Server {
    /// 运行状态标志，控制后台线程的启停
    running: Arc<AtomicBool>,
    /// 命令通道的发送端，将解析后的命令发给主线程
    sender: Sender<Command>,
    /// 后台线程的句柄，用于在停止时通过 join 等待线程结束
    handle: Option<thread::JoinHandle<()>>,
    /// TCP 流对象的线程安全包装，用于从主线程发送响应回 AI
    stream: Arc<Mutex<Option<TcpStream>>>,
}

impl Server {
    /// 创建新的 Server 实例
    ///
    /// # 参数
    /// * `sender` - 用于向主线程发送 Command 的通道发送端
    ///
    /// # 返回值
    /// 返回一个初始化但未启动的 Server（需要调用 start 方法）
    pub fn new(sender: Sender<Command>) -> Self {
        Server {
            // 初始状态为未运行
            running: Arc::new(AtomicBool::new(false)),
            sender,
            handle: None,
            stream: Arc::new(Mutex::new(None)),
        }
    }

    /// 启动后台连接线程
    ///
    /// 创建一个独立线程，循环尝试连接 Bridge 服务器（127.0.0.1:8888）。
    /// 连接成功后进入命令接收循环，使用 100ms 的读取超时来保持对 running 标志的响应。
    pub fn start(&mut self) {
        // 防止重复启动
        if self.running.load(Ordering::SeqCst) {
            return;
        }

        self.running.store(true, Ordering::SeqCst);
        let running = self.running.clone();
        let sender = self.sender.clone();
        let stream_arc = self.stream.clone();

        // 启动后台线程
        self.handle = Some(thread::spawn(move || {
            log::info!("Server thread started");

            // 接收缓冲区，每次最多读取 1024 字节
            let mut buffer = [0u8; 1024];

            //  ];

            // 主循环：只要 running 标志为 true 就持续运行
            while running.load(Ordering::SeqCst) {
                // 尝试连接到本地 Bridge 服务器
                match TcpStream::connect("127.0.0.1:8888") {
                    Ok(mut stream) => {
                        log::info!("Connected to AI Server");

                        // 设置 100ms 读取超时，这样 recv 不会永久阻塞
                        // 可以定期检查 running 标志来决定是否退出
                        stream.set_read_timeout(Some(Duration::from_millis(100))).ok();

                        // 克隆一个 stream 用于发送响应
                        // 读取和发送使用不同的 stream 实例，避免竞争
                        if let Ok(mut guard) = stream_arc.lock() {
                            *guard = Some(stream.try_clone().unwrap_or_else(|_| stream.try_clone().unwrap()));
                        }

                        // 命令接收循环
                        while running.load(Ordering::SeqCst) {
                            match stream.read(&mut buffer) {
                                // 读取到 0 字节表示对方关闭了连接
                                Ok(0) => {
                                    log::info!("Server closed connection");
                                    break;
                                }
                                // 成功读取到 n 字节
                                Ok(n) => {
                                    // 将字节数据转为 UTF-8 字符串
                                    if let Ok(s) = std::str::from_utf8(&buffer[0..n]) {
                                        // 解析文本命令为 Command 枚举
                                        let cmd = Command::from_string(s);
                                        // 通过通道发送给主线程处理
                                        if let Err(e) = sender.send(cmd) {
                                            log::error!("Failed to send command to main thread: {}", e);
                                            break;
                                        }
                                    }
                                }
                                // 读取超时或 WouldBlock（非阻塞模式下无数据）
                                // 这两种情况不是真正的错误，继续循环
                                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock || e.kind() == std::io::ErrorKind::TimedOut => {
                                    continue;
                                }
                                // 真正的 IO 错误
                                Err(e) => {
                                    log::error!("Connection error: {}", e);
                                    break;
                                }
                            }
                        }

                        // 断开连接后清理 stream
                        if let Ok(mut guard) = stream_arc.lock() {
                            *guard = None;
                        }
                    }
                    // 连接失败（Bridge 服务器还没启动），等待 1 秒后重试
                    Err(_) => {
                        thread::sleep(Duration::from_secs(1));
                    }
                }
            }
            log::info!("Server thread stopped");
        }));
    }

    /// 停止后台线程
    ///
    /// 设置 running 为 false，等待线程自然退出。
    /// 线程会在下一次读取超时或循环检查时检测到退出信号。
    pub fn stop(&mut self) {
        self.running.store(false, Ordering::SeqCst);
        if let Some(handle) = self.handle.take() {
            handle.join().ok();
        }
    }

    /// 向 Bridge 服务器发送响应消息
    ///
    /// # 参数
    /// * `msg` - 要发送的消息字符串
    ///
    /// # 返回值
    /// 发送成功返回 true，失败返回 false
    pub fn send(&self, msg: &str) -> bool {
        if let Ok(mut guard) = self.stream.lock() {
            if let Some(stream) = guard.as_mut() {
                // 将消息作为字节写入 TCP 流
                return stream.write_all(msg.as_bytes()).is_ok();
            }
        }
        false
    }
}