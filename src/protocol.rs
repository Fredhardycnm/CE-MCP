//! 命令协议模块
//!
//! 定义 MCP 插件支持的 75 个命令枚举及 TCP 文本协议解析器。
//! 文本协议格式: `COMMAND:参数1,参数2,...`
//!
//! 本模块是 AI ↔ CE 通信的协议层，负责将 AI 发来的文本指令
//! 解析为 Rust 枚举，供 lib.rs 中的命令处理器分发执行。

/// MCP 命令枚举
///
/// 每个变体对应一个 Cheat Engine 操作命令，包含所需参数。
/// 遵循 JSON-RPC 风格但使用更轻量的文本协议在 TCP 上传输。
#[derive(Debug, Clone)]
pub enum Command {
    /// 弹出消息框
    ShowMessage(String),
    /// 读取指定地址内存 [地址, 类型]
    ReadMemory { address: usize, type_: String },
    /// 写入指定地址内存 [地址, 值, 类型]
    WriteMemory { address: usize, value: String, type_: String },
    /// 汇编指令到指定地址
    Assemble { address: usize, instruction: String },
    /// 反汇编指定地址
    Disassemble { address: usize },
    /// 执行 Auto Assembler 脚本
    AutoAssemble { script: String },
    // ── UI 控件 ──
    /// 创建表单
    CreateForm,
    /// 创建面板（需父控件指针）
    CreatePanel { owner: usize },
    /// 创建按钮
    CreateButton { owner: usize },
    /// 创建标签
    CreateLabel { owner: usize },
    /// 创建编辑框
    CreateEdit { owner: usize },
    /// 创建图片控件
    CreateImage { owner: usize },
    /// 创建多行文本框
    CreateMemo { owner: usize },
    /// 创建分组框
    CreateGroupBox { owner: usize },
    /// 创建定时器
    CreateTimer { owner: usize },
    // ── UI 控件属性 ──
    /// 设置控件标题
    SetCaption { control: usize, caption: String },
    /// 获取控件标题
    GetCaption { control: usize },
    /// 设置控件位置 [X, Y]
    SetPosition { control: usize, x: i32, y: i32 },
    /// 获取控件位置
    GetPosition { control: usize },
    /// 设置控件尺寸 [宽, 高]
    SetSize { control: usize, width: i32, height: i32 },
    /// 获取控件尺寸
    GetSize { control: usize },
    /// 销毁控件
    DestroyObject { object: usize },
    /// 表单居中
    FormCenterScreen { form: usize },
    /// 隐藏表单
    FormHide { form: usize },
    /// 显示表单
    FormShow { form: usize },
    /// 从文件加载图片
    ImageLoadFromFile { image: usize, filename: String },
    /// 设置图片透明
    ImageTransparent { image: usize, transparent: bool },
    /// 设置图片拉伸
    ImageStretch { image: usize, stretch: bool },
    /// 设置定时器间隔（毫秒）
    TimerSetInterval { timer: usize, interval: i32 },
    // ── 内存表管理 ──
    /// 创建内存表条目 [描述, 地址, 类型]
    CreateTableEntry { description: String, address: String, type_: String },
    /// 按索引获取条目
    GetTableEntry { index: i32 },
    /// 设置条目描述
    SetEntryDescription { index: i32, description: String },
    /// 获取条目描述
    GetEntryDescription { index: i32 },
    /// 设置条目地址
    SetEntryAddress { index: i32, address: String },
    /// 获取条目地址
    GetEntryAddress { index: i32 },
    /// 设置条目类型
    SetEntryType { index: i32, type_: String },
    /// 获取条目类型
    GetEntryType { index: i32 },
    /// 设置条目值
    SetEntryValue { index: i32, value: String },
    /// 获取条目值
    GetEntryValue { index: i32 },
    /// 设置条目脚本
    SetEntryScript { index: i32, script: String },
    /// 获取条目脚本
    GetEntryScript { index: i32 },
    /// 冻结条目
    FreezeEntry { index: i32 },
    /// 解冻条目
    UnfreezeEntry { index: i32 },
    /// 删除条目
    DeleteEntry { index: i32 },
    // ── 进程管理 ──
    /// 获取进程列表
    ProcessList,
    /// 按 PID 打开进程
    OpenProcess { process_id: u32 },
    /// 按名称获取 PID
    GetProcessId { process_name: String },
    /// 暂停进程
    PauseProcess,
    /// 恢复进程
    UnpauseProcess,
    /// 调试模式附加进程
    DebugProcess { process_id: u32 },
    // ── 高级功能 ──
    /// 修改寄存器值
    ChangeRegister { address: usize, reg: String, value: String },
    /// 注入 DLL
    InjectDll { path: String, function: String },
    /// 变速齿轮 [倍率]
    Speedhack { speed: f32 },
    /// 地址转符号名
    AddressToName { address: usize },
    /// 符号名转地址
    NameToAddress { name: String },
    /// 多级指针解析
    GetAddressFromPointer { base: usize, offsets: Vec<i32> },
    /// 获取上一条指令地址
    PreviousOpcode { address: usize },
    /// 获取下一条指令地址
    NextOpcode { address: usize },
    /// 设置断点 [地址, 大小, 触发条件]
    SetBreakpoint { address: usize, size: i32, trigger: i32 },
    /// 移除断点
    RemoveBreakpoint { address: usize },
    /// 从断点继续执行
    ContinueFromBreakpoint { option: i32 },
    /// 未识别命令
    Unknown(String),
}

impl Command {
    /// 从 TCP 文本协议字符串解析出命令
    ///
    /// 格式: `COMMAND:参数1,参数2,...`
    /// 例如: `READ_MEMORY:0x12345678,float`
    ///
    /// 命令名使用 `obfstr!` 宏编译时混淆，
    /// 防止杀软通过明文字符串特征检测 CE 插件。
    pub fn from_string(input: &str) -> Self {
        // 按冒号分割命令名与参数
        let parts: Vec<&str> = input.splitn(2, ':').collect();
        let cmd = parts[0];
        let param = if parts.len() > 1 { parts[1] } else { "" };

        // For simplicity and obfuscation, we'll switch to if/else if.
        
        if cmd == obfstr::obfstr!("SHOW_MESSAGE") {
            Command::ShowMessage(param.to_string())
        } else if cmd == obfstr::obfstr!("READ_MEMORY") {
            // Format: READ_MEMORY:address,type
            let params: Vec<&str> = param.split(',').collect();
            if params.len() >= 2 {
                if let Ok(address) = parse_address(params[0]) {
                    return Command::ReadMemory {
                        address,
                        type_: params[1].to_string(),
                    };
                }
            }
            Command::Unknown(input.to_string())
        // ── 内存：写入 ──
        } else if cmd == obfstr::obfstr!("WRITE_MEMORY") {
            // Format: WRITE_MEMORY:address,value,type
            let params: Vec<&str> = param.split(',').collect();
            if params.len() >= 3 {
                if let Ok(address) = parse_address(params[0]) {
                    return Command::WriteMemory {
                        address,
                        value: params[1].to_string(),
                        type_: params[2].to_string(),
                    };
                }
            }
            Command::Unknown(input.to_string())
        } else if cmd == obfstr::obfstr!("ASSEMBLE") {
            // Format: ASSEMBLE:address,instruction
            let params: Vec<&str> = param.splitn(2, ',').collect();
            if params.len() >= 2 {
                if let Ok(address) = parse_address(params[0]) {
                    return Command::Assemble {
                        address,
                        instruction: params[1].to_string(),
                    };
                }
            }
            Command::Unknown(input.to_string())
        } else if cmd == obfstr::obfstr!("DISASSEMBLE") {
            // Format: DISASSEMBLE:address
            if let Ok(address) = parse_address(param) {
                return Command::Disassemble { address };
            }
            Command::Unknown(input.to_string())
        } else if cmd == obfstr::obfstr!("AUTO_ASSEMBLE") {
            Command::AutoAssemble { script: param.to_string() }
        } else if cmd == obfstr::obfstr!("CREATE_FORM") {
            Command::CreateForm
        } else if cmd == obfstr::obfstr!("CREATE_PANEL") {
            if let Ok(owner) = parse_address(param) { Command::CreatePanel { owner } } else { Command::Unknown(input.to_string()) }
        } else if cmd == obfstr::obfstr!("CREATE_BUTTON") {
            if let Ok(owner) = parse_address(param) { Command::CreateButton { owner } } else { Command::Unknown(input.to_string()) }
        } else if cmd == obfstr::obfstr!("CREATE_LABEL") {
            if let Ok(owner) = parse_address(param) { Command::CreateLabel { owner } } else { Command::Unknown(input.to_string()) }
        } else if cmd == obfstr::obfstr!("CREATE_EDIT") {
            if let Ok(owner) = parse_address(param) { Command::CreateEdit { owner } } else { Command::Unknown(input.to_string()) }
        } else if cmd == obfstr::obfstr!("CREATE_IMAGE") {
            if let Ok(owner) = parse_address(param) { Command::CreateImage { owner } } else { Command::Unknown(input.to_string()) }
        } else if cmd == obfstr::obfstr!("CREATE_MEMO") {
            if let Ok(owner) = parse_address(param) { Command::CreateMemo { owner } } else { Command::Unknown(input.to_string()) }
        } else if cmd == obfstr::obfstr!("CREATE_GROUP_BOX") {
            if let Ok(owner) = parse_address(param) { Command::CreateGroupBox { owner } } else { Command::Unknown(input.to_string()) }
        } else if cmd == obfstr::obfstr!("CREATE_TIMER") {
            if let Ok(owner) = parse_address(param) { Command::CreateTimer { owner } } else { Command::Unknown(input.to_string()) }
        } else if cmd == obfstr::obfstr!("SET_CAPTION") {
            // Format: SET_CAPTION:control,caption
            let params: Vec<&str> = param.splitn(2, ',').collect();
            if params.len() >= 2 {
                if let Ok(control) = parse_address(params[0]) {
                    return Command::SetCaption { control, caption: params[1].to_string() };
                }
            }
            Command::Unknown(input.to_string())
        } else if cmd == obfstr::obfstr!("GET_CAPTION") {
            if let Ok(control) = parse_address(param) { Command::GetCaption { control } } else { Command::Unknown(input.to_string()) }
        } else if cmd == obfstr::obfstr!("SET_POSITION") {
            // Format: SET_POSITION:control,x,y
            let params: Vec<&str> = param.split(',').collect();
            if params.len() >= 3 {
                if let Ok(control) = parse_address(params[0]) {
                    if let (Ok(x), Ok(y)) = (params[1].parse(), params[2].parse()) {
                        return Command::SetPosition { control, x, y };
                    }
                }
            }
            Command::Unknown(input.to_string())
        } else if cmd == obfstr::obfstr!("GET_POSITION") {
            if let Ok(control) = parse_address(param) { Command::GetPosition { control } } else { Command::Unknown(input.to_string()) }
        } else if cmd == obfstr::obfstr!("SET_SIZE") {
            // Format: SET_SIZE:control,width,height
            let params: Vec<&str> = param.split(',').collect();
            if params.len() >= 3 {
                if let Ok(control) = parse_address(params[0]) {
                    if let (Ok(width), Ok(height)) = (params[1].parse(), params[2].parse()) {
                        return Command::SetSize { control, width, height };
                    }
                }
            }
            Command::Unknown(input.to_string())
        } else if cmd == obfstr::obfstr!("GET_SIZE") {
            if let Ok(control) = parse_address(param) { Command::GetSize { control } } else { Command::Unknown(input.to_string()) }
        } else if cmd == obfstr::obfstr!("DESTROY_OBJECT") {
            if let Ok(object) = parse_address(param) { Command::DestroyObject { object } } else { Command::Unknown(input.to_string()) }
        } else if cmd == obfstr::obfstr!("FORM_CENTER_SCREEN") {
            if let Ok(form) = parse_address(param) { Command::FormCenterScreen { form } } else { Command::Unknown(input.to_string()) }
        } else if cmd == obfstr::obfstr!("FORM_HIDE") {
            if let Ok(form) = parse_address(param) { Command::FormHide { form } } else { Command::Unknown(input.to_string()) }
        } else if cmd == obfstr::obfstr!("FORM_SHOW") {
            if let Ok(form) = parse_address(param) { Command::FormShow { form } } else { Command::Unknown(input.to_string()) }
        } else if cmd == obfstr::obfstr!("IMAGE_LOAD_IMAGE_FROM_FILE") {
            // Format: IMAGE_LOAD_IMAGE_FROM_FILE:image,filename
            let params: Vec<&str> = param.splitn(2, ',').collect();
            if params.len() >= 2 {
                if let Ok(image) = parse_address(params[0]) {
                    return Command::ImageLoadFromFile { image, filename: params[1].to_string() };
                }
            }
            Command::Unknown(input.to_string())
        } else if cmd == obfstr::obfstr!("IMAGE_TRANSPARENT") {
            // Format: IMAGE_TRANSPARENT:image,transparent
            let params: Vec<&str> = param.split(',').collect();
            if params.len() >= 2 {
                if let Ok(image) = parse_address(params[0]) {
                    // "1" or "true" = true
                    let transparent = params[1] == "1" || params[1].eq_ignore_ascii_case("true");
                    return Command::ImageTransparent { image, transparent };
                }
            }
            Command::Unknown(input.to_string())
        } else if cmd == obfstr::obfstr!("IMAGE_STRETCH") {
            // Format: IMAGE_STRETCH:image,stretch
            let params: Vec<&str> = param.split(',').collect();
            if params.len() >= 2 {
                if let Ok(image) = parse_address(params[0]) {
                    let stretch = params[1] == "1" || params[1].eq_ignore_ascii_case("true");
                    return Command::ImageStretch { image, stretch };
                }
            }
            Command::Unknown(input.to_string())
        } else if cmd == obfstr::obfstr!("TIMER_SET_INTERVAL") {
            // Format: TIMER_SET_INTERVAL:timer,interval
            let params: Vec<&str> = param.split(',').collect();
            if params.len() >= 2 {
                if let Ok(timer) = parse_address(params[0]) {
                    if let Ok(interval) = params[1].parse() {
                        return Command::TimerSetInterval { timer, interval };
                    }
                }
            }
            Command::Unknown(input.to_string())
        } else if cmd == obfstr::obfstr!("CREATE_TABLE_ENTRY") {
            // CREATE_TABLE_ENTRY:description,address,type
            let params: Vec<&str> = param.splitn(3, ',').collect();
            if params.len() >= 3 {
                Command::CreateTableEntry { description: params[0].to_string(), address: params[1].to_string(), type_: params[2].to_string() }
            } else {
                Command::Unknown(input.to_string())
            }
        } else if cmd == obfstr::obfstr!("GET_TABLE_ENTRY") {
            if let Ok(index) = param.parse() { Command::GetTableEntry { index } } else { Command::Unknown(input.to_string()) }
        } else if cmd == obfstr::obfstr!("SET_ENTRY_DESCRIPTION") {
            let params: Vec<&str> = param.splitn(2, ',').collect();
            if params.len() >= 2 {
                if let Ok(index) = params[0].parse() {
                    Command::SetEntryDescription { index, description: params[1].to_string() }
                } else { Command::Unknown(input.to_string()) }
            } else { Command::Unknown(input.to_string()) }
        } else if cmd == obfstr::obfstr!("GET_ENTRY_DESCRIPTION") {
            if let Ok(index) = param.parse() { Command::GetEntryDescription { index } } else { Command::Unknown(input.to_string()) }
        } else if cmd == obfstr::obfstr!("SET_ENTRY_ADDRESS") {
            let params: Vec<&str> = param.splitn(2, ',').collect();
            if params.len() >= 2 {
                if let Ok(index) = params[0].parse() {
                    Command::SetEntryAddress { index, address: params[1].to_string() }
                } else { Command::Unknown(input.to_string()) }
            } else { Command::Unknown(input.to_string()) }
        } else if cmd == obfstr::obfstr!("GET_ENTRY_ADDRESS") {
            if let Ok(index) = param.parse() { Command::GetEntryAddress { index } } else { Command::Unknown(input.to_string()) }
        } else if cmd == obfstr::obfstr!("SET_ENTRY_TYPE") {
            let params: Vec<&str> = param.splitn(2, ',').collect();
            if params.len() >= 2 {
                if let Ok(index) = params[0].parse() {
                    Command::SetEntryType { index, type_: params[1].to_string() }
                } else { Command::Unknown(input.to_string()) }
            } else { Command::Unknown(input.to_string()) }
        } else if cmd == obfstr::obfstr!("GET_ENTRY_TYPE") {
            if let Ok(index) = param.parse() { Command::GetEntryType { index } } else { Command::Unknown(input.to_string()) }
        } else if cmd == obfstr::obfstr!("SET_ENTRY_VALUE") {
            let params: Vec<&str> = param.splitn(2, ',').collect();
            if params.len() >= 2 {
                if let Ok(index) = params[0].parse() {
                    Command::SetEntryValue { index, value: params[1].to_string() }
                } else { Command::Unknown(input.to_string()) }
            } else { Command::Unknown(input.to_string()) }
        } else if cmd == obfstr::obfstr!("GET_ENTRY_VALUE") {
            if let Ok(index) = param.parse() { Command::GetEntryValue { index } } else { Command::Unknown(input.to_string()) }
        } else if cmd == obfstr::obfstr!("SET_ENTRY_SCRIPT") {
            let params: Vec<&str> = param.splitn(2, ',').collect();
            if params.len() >= 2 {
                if let Ok(index) = params[0].parse() {
                    Command::SetEntryScript { index, script: params[1].to_string() }
                } else { Command::Unknown(input.to_string()) }
            } else { Command::Unknown(input.to_string()) }
        } else if cmd == obfstr::obfstr!("GET_ENTRY_SCRIPT") {
            if let Ok(index) = param.parse() { Command::GetEntryScript { index } } else { Command::Unknown(input.to_string()) }
        } else if cmd == obfstr::obfstr!("FREEZE_ENTRY") {
            if let Ok(index) = param.parse() { Command::FreezeEntry { index } } else { Command::Unknown(input.to_string()) }
        } else if cmd == obfstr::obfstr!("UNFREEZE_ENTRY") {
            if let Ok(index) = param.parse() { Command::UnfreezeEntry { index } } else { Command::Unknown(input.to_string()) }
        } else if cmd == obfstr::obfstr!("DELETE_ENTRY") {
            if let Ok(index) = param.parse() { Command::DeleteEntry { index } } else { Command::Unknown(input.to_string()) }
        } else if cmd == obfstr::obfstr!("PROCESS_LIST") {
            Command::ProcessList
        } else if cmd == obfstr::obfstr!("OPEN_PROCESS") {
            if let Ok(process_id) = param.parse() { Command::OpenProcess { process_id } } else { Command::Unknown(input.to_string()) }
        } else if cmd == obfstr::obfstr!("GET_PROCESS_ID") {
            Command::GetProcessId { process_name: param.to_string() }
        } else if cmd == obfstr::obfstr!("PAUSE_PROCESS") {
            Command::PauseProcess
        } else if cmd == obfstr::obfstr!("UNPAUSE_PROCESS") {
            Command::UnpauseProcess
        } else if cmd == obfstr::obfstr!("DEBUG_PROCESS") {
            if let Ok(process_id) = param.parse() { Command::DebugProcess { process_id } } else { Command::Unknown(input.to_string()) }
        } else if cmd == obfstr::obfstr!("CHANGE_REGISTER") {
            // CHANGE_REGISTER:address,reg,value
            let params: Vec<&str> = param.splitn(3, ',').collect();
            if params.len() >= 3 {
                if let Ok(address) = parse_address(params[0]) {
                    Command::ChangeRegister { address, reg: params[1].to_string(), value: params[2].to_string() }
                } else { Command::Unknown(input.to_string()) }
            } else { Command::Unknown(input.to_string()) }
        } else if cmd == obfstr::obfstr!("INJECT_DLL") {
            // INJECT_DLL:path,function
            let params: Vec<&str> = param.splitn(2, ',').collect();
            if params.len() >= 1 {
                let function = if params.len() > 1 { params[1] } else { "" };
                Command::InjectDll { path: params[0].to_string(), function: function.to_string() }
            } else { Command::Unknown(input.to_string()) }
        } else if cmd == obfstr::obfstr!("SPEEDHACK") {
            if let Ok(speed) = param.parse() { Command::Speedhack { speed } } else { Command::Unknown(input.to_string()) }
        } else if cmd == obfstr::obfstr!("ADDRESS_TO_NAME") {
            if let Ok(address) = parse_address(param) { Command::AddressToName { address } } else { Command::Unknown(input.to_string()) }
        } else if cmd == obfstr::obfstr!("NAME_TO_ADDRESS") {
            Command::NameToAddress { name: param.to_string() }
        } else if cmd == obfstr::obfstr!("GET_ADDRESS_FROM_POINTER") {
            // GET_ADDRESS_FROM_POINTER:base,offset1,offset2...
            let params: Vec<&str> = param.split(',').collect();
            if params.len() >= 1 {
                if let Ok(base) = parse_address(params[0]) {
                    let mut offsets = Vec::new();
                    for i in 1..params.len() {
                        if let Ok(offset) = parse_address(params[i]) {
                            offsets.push(offset as i32);
                        }
                    }
                    Command::GetAddressFromPointer { base, offsets }
                } else { Command::Unknown(input.to_string()) }
            } else { Command::Unknown(input.to_string()) }
        } else if cmd == obfstr::obfstr!("PREVIOUS_OPCODE") {
            if let Ok(address) = parse_address(param) { Command::PreviousOpcode { address } } else { Command::Unknown(input.to_string()) }
        } else if cmd == obfstr::obfstr!("NEXT_OPCODE") {
            if let Ok(address) = parse_address(param) { Command::NextOpcode { address } } else { Command::Unknown(input.to_string()) }
        } else if cmd == obfstr::obfstr!("SET_BREAKPOINT") {
            // SET_BREAKPOINT:address,size,trigger
            let params: Vec<&str> = param.splitn(3, ',').collect();
            if params.len() >= 3 {
                if let Ok(address) = parse_address(params[0]) {
                    if let (Ok(size), Ok(trigger)) = (params[1].parse(), params[2].parse()) {
                        Command::SetBreakpoint { address, size, trigger }
                    } else { Command::Unknown(input.to_string()) }
                } else { Command::Unknown(input.to_string()) }
            } else { Command::Unknown(input.to_string()) }
        } else if cmd == obfstr::obfstr!("REMOVE_BREAKPOINT") {
            if let Ok(address) = parse_address(param) { Command::RemoveBreakpoint { address } } else { Command::Unknown(input.to_string()) }
        } else if cmd == obfstr::obfstr!("CONTINUE_FROM_BREAKPOINT") {
            if let Ok(option) = param.parse() { Command::ContinueFromBreakpoint { option } } else { Command::Unknown(input.to_string()) }
        } else {
            Command::Unknown(input.to_string())
        }
    }
}

/// 解析 16/10 进制地址字符串为 usize
///
/// 支持 `0x`/`0X` 前缀的十六进制和不带前缀的十进制。
fn parse_address(s: &str) -> Result<usize, std::num::ParseIntError> {
    let s = s.trim();
    if s.starts_with("0x") || s.starts_with("0X") {
        usize::from_str_radix(&s[2..], 16)
    } else {
        s.parse()
    }
}
