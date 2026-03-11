# CE-MCP-Plugin 使用手册

## 简介 (Introduction)
**CE-MCP-Plugin** 是一个专为 Cheat Engine 设计的下一代插件，它实现了 **Model Context Protocol (MCP)** 标准。
这使得像 Claude 3.5/3.7 或 Trae 这样的 AI 助手能够**直接控制 Cheat Engine**，协助您进行逆向工程、游戏修改和内存调试。

## 📂 交付物清单
在 `rust-CE-MCP` 文件夹中，您会找到以下文件：

1.  **`rust_ce_mcp_plugin_x64.dll`** (推荐)
    *   适用于 64 位 Cheat Engine (目前主流版本)。
2.  **`rust_ce_mcp_plugin_x86.dll`**
    *   适用于 32 位 Cheat Engine (老旧版本或特定需求)。
3.  **`bridge_server.py`**
    *   Python 桥接服务器，负责在 AI (标准输入输出) 和 CE 插件 (TCP) 之间转发消息。
4.  **`mcp_config.json`**
    *   MCP 配置文件模板。

---

## 🚀 安装与配置

### 第一步：安装 Cheat Engine 插件
1.  找到您的 Cheat Engine 安装目录（通常是 `C:\Program Files\Cheat Engine 7.5\`）。
2.  打开 `autorun` 文件夹。
3.  将 **`rust_ce_mcp_plugin_x64.dll`** 复制到该 `autorun` 文件夹中。
    *   *注意：如果您的 CE 是 32 位的，请复制 x86 版本。*
4.  启动 Cheat Engine。
    *   如果安装成功，您会看到一个弹窗提示：**"Rust Plugin Initialized! Server starting..."**。

### 第二步：配置 MCP 客户端 (Trae / Claude Desktop)
您需要告诉 AI 客户端如何启动这个插件的桥接服务。

1.  **安装 Python (关键)**
    *   下载并安装最新版 Python。
    *   **⚠️ 务必勾选 "Add Python to PATH" (添加到环境变量)**，否则 AI 无法找到 Python。
    *   安装完成后，打开命令行输入 `python --version` 验证是否成功。

2.  打开 `rust-CE-MCP` 文件夹中的 **`mcp_config.json`**。
3.  修改 `"args"` 中的路径，使其指向您电脑上 `bridge_server.py` 的**绝对路径**。
    *   *例如：* `"c:\\Tools\\rust-CE-MCP\\bridge_server.py"`
4.  将配置应用到您的客户端：
    *   **Claude Desktop**: 编辑 `%APPDATA%\Claude\claude_desktop_config.json`。
    *   **Trae**: 在设置中添加 MCP Server。

---

## 🎮 如何使用

一旦配置完成，您就可以在 AI 对话框中直接使用自然语言指令：

### 1. 内存读写
*   **用户**: "请帮我读取地址 0x12345678 的值，它是浮点数。"
*   **AI**: 调用 `read_memory(address="0x12345678", type="float")`
*   **结果**: CE 返回数值，AI 进行分析。

### 2. 汇编与反汇编
*   **用户**: "把 0x00401000 处的指令改成 NOP。"
*   **AI**: 调用 `assemble(address="0x00401000", instruction="nop")`
*   **用户**: "分析一下这个函数的开头指令。"
*   **AI**: 调用 `disassemble` 循环读取指令。

### 3. 自动化脚本 (Auto Assembler)
*   **用户**: "给我写一个无限血量的脚本并激活它。"
*   **AI**: 生成 CE AA 脚本并调用 `auto_assemble` 直接注入游戏进程。

### 4. Lua 脚本交互
*   **高级用法**: 您可以在 CE 的 Lua 脚本窗口中调用 `aiSendCommand("Hello from Lua")`，AI 会收到这条消息。这允许您编写复杂的 Lua 逻辑并与 AI 联动。

---

## ❓ 常见问题排查

### Q: 启动 Cheat Engine 时报错 "EDotNetException"？
*   **原因**: DLL 架构不匹配。
*   **解决**: 您正在用 64 位 CE 加载 32 位 DLL（或反之）。请删除错误的 DLL，只保留与您 CE 标题栏架构一致的版本（x86_64 用 x64.dll）。

### Q: AI 提示 "Error: Cheat Engine not connected"？
*   **原因**: CE 插件未连接到 Python 桥接器。
*   **解决**:
    1.  确保 Cheat Engine 已打开。
    2.  确保插件已加载（看到过欢迎弹窗）。
    3.  插件会自动每秒重试连接本地 8888 端口，通常稍等片刻即可。

### Q: 中文显示乱码？
*   **解决**: 插件内部已处理 UTF-8 转换，但请确保您的系统和 CE 字体支持中文显示。

---
https://github.com/Eruditi/CE-MCP-Plugin
