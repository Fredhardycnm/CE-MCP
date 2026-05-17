"""
CE-MCP 桥接服务器（Python）

本模块是 AI ↔ Cheat Engine 通信的中间桥梁，实现 MCP（Model Context Protocol）协议。

工作流程:
  AI (Claude/Cursor 等)  ──JSON-RPC──>  bridge_server.py  ──TCP文本协议──>  CE 插件 (Rust DLL)

角色定位:
  1. 作为 MCP Server，通过 stdin/stdout 接收 AI 的 JSON-RPC 2.0 请求
  2. 解析 AI 的 tool 调用请求，将其翻译为 CE 插件能理解的 TCP 文本命令
  3. 维护 TCP Server 端口（默认 8888），等待 CE 插件连接
  4. 将 CE 插件返回的响应转发回 AI

通信协议:
  - AI → 本服务器: JSON-RPC 2.0 over stdin/stdout（标准 MCP 协议）
  - 本服务器 → CE 插件: TCP 文本命令（格式: COMMAND:参数1,参数2,...）
"""

import socket
import sys
import json
import threading
import queue
import time
import argparse
from typing import Optional, Dict, Any


class BridgeServer:
    """MCP 桥接服务器

    职责:
      1. 启动 TCP Server 等待 CE 插件连接
      2. 通过 stdin 读取 AI 的 JSON-RPC 请求
      3. 将 AI 请求转换为文本命令转发到 CE
      4. 将 CE 响应回传给 AI

    属性:
      host: TCP 绑定地址（默认 127.0.0.1）
      port: TCP 端口（默认 8888）
      conn: CE 插件的 TCP 连接
      response_queue: CE 响应队列（线程安全）
      running: 服务器运行标志
    """

    def __init__(self, host='127.0.0.1', port=8888):
        """初始化桥接服务器

        Args:
            host: TCP 服务器绑定地址
            port: TCP 服务器端口
        """
        self.host = host
        self.port = port
        self.conn: Optional[socket.socket] = None       # CE 插件 TCP 连接
        self.response_queue = queue.Queue()             # 接收 CE 响应的队列
        self.running = True
        self.lock = threading.Lock()                    # 线程锁，保证发送/接收同步

    def start_tcp_server(self):
        """启动 TCP 服务器，监听 CE 插件连接

        在独立线程中运行，接受 CE 插件连接后调用 handle_connection 处理。
        支持断线重连，服务器不会因单次连接断开而退出。
        """
        server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server_sock.bind((self.host, self.port))
        server_sock.listen(1)

        while self.running:
            try:
                conn, addr = server_sock.accept()
                self.conn = conn
                self.handle_connection(conn)
            except Exception as e:
                if self.running:
                    print(f"Server error: {e}", file=sys.stderr)
                    time.sleep(1)

    def handle_connection(self, conn):
        """处理与 CE 插件的 TCP 连接

        持续接收 CE 插件发来的响应数据，存入 response_queue。

        Args:
            conn: 已建立的 TCP socket 连接
        """
        while self.running:
            try:
                data = conn.recv(4096)
                if not data:
                    break

                text = data.decode('utf-8', errors='ignore')
                self.response_queue.put(text)

            except Exception as e:
                print(f"Connection error: {e}", file=sys.stderr)
                break
        self.conn = None

    def send_command(self, cmd: str) -> str:
        """向 CE 插件发送文本命令并等待响应

        Args:
            cmd: 文本命令字符串（如 "READ_MEMORY:0x123456,float"）

        Returns:
            CE 插件的响应字符串，或错误信息
        """
        if not self.conn:
            return "Error: Cheat Engine not connected"

        try:
            with self.lock:
                # 清空响应队列
                while not self.response_queue.empty():
                    self.response_queue.get()

                self.conn.sendall(cmd.encode('utf-8'))

                # 等待 CE 响应（超时 5 秒）
                try:
                    return self.response_queue.get(timeout=5)
                except queue.Empty:
                    return "Error: Timeout waiting for response"
        except Exception as e:
            return f"Error: {e}"

    def run_mcp_loop(self):
        """运行 MCP 主循环

        1. 启动 TCP 服务器线程等待 CE 连接
        2. 通过 sys.stdin 读取 AI 发来的 JSON-RPC 请求
        3. 逐个请求调用 handle_rpc_request 处理
        4. 将处理结果（JSON-RPC 响应）打印到 stdout
        """
        # 在后台线程中启动 TCP 服务器
        t = threading.Thread(target=self.start_tcp_server, daemon=True)
        t.start()

        # 主线程：从 stdin 读取 AI 的 JSON-RPC 请求
        for line in sys.stdin:
            try:
                request = json.loads(line)
                response = self.handle_rpc_request(request)
                if response:
                    print(json.dumps(response))
                    sys.stdout.flush()
            except json.JSONDecodeError:
                continue
            except Exception as e:
                print(f"Error handling request: {e}", file=sys.stderr)

    def handle_rpc_request(self, request: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """处理单个 JSON-RPC 请求

        支持三种 MCP 方法:
          1. initialize            — MCP 握手初始化
          2. notifications/initialized — 初始化完成通知（无响应）
          3. tools/list            — 返回所有可用工具列表
          4. tools/call            — 调用具体工具（翻译为 TCP 文本命令）

        Args:
            request: JSON-RPC 请求字典

        Returns:
            JSON-RPC 响应字典，或 None（无需响应的情况）
        """
        if "method" not in request:
            return None

        method = request["method"]
        msg_id = request.get("id")
        params = request.get("params", {})

        # ── MCP 握手：返回服务器信息与能力声明 ──
        if method == "initialize":
            return {
                "jsonrpc": "2.0",
                "id": msg_id,
                "result": {
                    "protocolVersion": "2024-11-05",
                    "capabilities": {
                        "tools": {}
                    },
                    "serverInfo": {
                        "name": "cheat-engine-bridge",
                        "version": "1.0.0"
                    }
                }
            }

        # ── MCP 初始化完成通知：无需响应 ──
        if method == "notifications/initialized":
            return None

        # ── 工具列表查询：返回所有 CE 操作工具的定义 ──
        if method == "tools/list":
            return {
                "jsonrpc": "2.0",
                "id": msg_id,
                "result": {
                    "tools": [
                        # ── 基础 ──
                        {
                            "name": "show_message",
                            "description": "Show a message box in Cheat Engine",
                            "inputSchema": { "type": "object", "properties": { "message": {"type": "string"} }, "required": ["message"] }
                        },
                        # ── 进程管理 ──
                        {
                            "name": "open_process",
                            "description": "Open a process by ID",
                            "inputSchema": { "type": "object", "properties": { "process_id": {"type": "integer"} }, "required": ["process_id"] }
                        },
                        {
                            "name": "get_process_id",
                            "description": "Get process ID by name",
                            "inputSchema": { "type": "object", "properties": { "process_name": {"type": "string"} }, "required": ["process_name"] }
                        },
                        {
                            "name": "pause_process",
                            "description": "Pause the target process",
                            "inputSchema": { "type": "object", "properties": {}, "required": [] }
                        },
                        {
                            "name": "unpause_process",
                            "description": "Unpause the target process",
                            "inputSchema": { "type": "object", "properties": {}, "required": [] }
                        },
                        {
                            "name": "debug_process",
                            "description": "Attach debugger to process",
                            "inputSchema": { "type": "object", "properties": { "process_id": {"type": "integer"} }, "required": ["process_id"] }
                        },
                        # ── 高级功能 ──
                        {
                            "name": "change_register",
                            "description": "Change register value at address",
                            "inputSchema": { "type": "object", "properties": { "address": {"type": "string"}, "reg": {"type": "string"}, "value": {"type": "string"} }, "required": ["address", "reg", "value"] }
                        },
                        {
                            "name": "inject_dll",
                            "description": "Inject DLL into target process",
                            "inputSchema": { "type": "object", "properties": { "path": {"type": "string"}, "function": {"type": "string"} }, "required": ["path"] }
                        },
                        {
                            "name": "speedhack",
                            "description": "Set speedhack speed",
                            "inputSchema": { "type": "object", "properties": { "speed": {"type": "number"} }, "required": ["speed"] }
                        },
                        {
                            "name": "address_to_name",
                            "description": "Convert address to symbol name",
                            "inputSchema": { "type": "object", "properties": { "address": {"type": "string"} }, "required": ["address"] }
                        },
                        {
                            "name": "name_to_address",
                            "description": "Convert symbol name to address",
                            "inputSchema": { "type": "object", "properties": { "name": {"type": "string"} }, "required": ["name"] }
                        },
                        {
                            "name": "get_address_from_pointer",
                            "description": "Get address from pointer chain",
                            "inputSchema": { "type": "object", "properties": { "base": {"type": "string"}, "offsets": {"type": "array", "items": {"type": "string"}} }, "required": ["base", "offsets"] }
                        },
                        {
                            "name": "previous_opcode",
                            "description": "Get previous opcode address",
                            "inputSchema": { "type": "object", "properties": { "address": {"type": "string"} }, "required": ["address"] }
                        },
                        {
                            "name": "next_opcode",
                            "description": "Get next opcode address",
                            "inputSchema": { "type": "object", "properties": { "address": {"type": "string"} }, "required": ["address"] }
                        },
                        {
                            "name": "set_breakpoint",
                            "description": "Set breakpoint",
                            "inputSchema": { "type": "object", "properties": { "address": {"type": "string"}, "size": {"type": "integer"}, "trigger": {"type": "integer"} }, "required": ["address", "size", "trigger"] }
                        },
                        {
                            "name": "remove_breakpoint",
                            "description": "Remove breakpoint",
                            "inputSchema": { "type": "object", "properties": { "address": {"type": "string"} }, "required": ["address"] }
                        },
                        {
                            "name": "continue_from_breakpoint",
                            "description": "Continue from breakpoint",
                            "inputSchema": { "type": "object", "properties": { "option": {"type": "integer"} }, "required": ["option"] }
                        },
                        # ── 内存读写 ──
                        {
                            "name": "read_memory",
                            "description": "Read memory from the current process in Cheat Engine",
                            "inputSchema": { "type": "object", "properties": { "address": {"type": "string"}, "type": {"type": "string"} }, "required": ["address", "type"] }
                        },
                        {
                            "name": "write_memory",
                            "description": "Write value to memory",
                            "inputSchema": { "type": "object", "properties": { "address": {"type": "string"}, "value": {"type": "string"}, "type": {"type": "string"} }, "required": ["address", "value", "type"] }
                        },
                        # ── 汇编与反汇编 ──
                        {
                            "name": "assemble",
                            "description": "Assemble instruction at address",
                            "inputSchema": { "type": "object", "properties": { "address": {"type": "string"}, "instruction": {"type": "string"} }, "required": ["address", "instruction"] }
                        },
                        {
                            "name": "disassemble",
                            "description": "Disassemble instruction at address",
                            "inputSchema": { "type": "object", "properties": { "address": {"type": "string"} }, "required": ["address"] }
                        },
                        {
                            "name": "auto_assemble",
                            "description": "Execute Auto Assembler script",
                            "inputSchema": { "type": "object", "properties": { "script": {"type": "string"} }, "required": ["script"] }
                        },
                        # ── 地址列表（Table）管理 ──
                        {
                            "name": "create_table_entry",
                            "description": "Create a new entry in the cheat table",
                            "inputSchema": { "type": "object", "properties": { "description": {"type": "string"}, "address": {"type": "string"}, "type": {"type": "string"} }, "required": ["description", "address", "type"] }
                        },
                        {
                            "name": "get_table_entry",
                            "description": "Get handle of a table entry by index",
                            "inputSchema": { "type": "object", "properties": { "index": {"type": "integer"} }, "required": ["index"] }
                        },
                        {
                            "name": "set_entry_description",
                            "description": "Set description for a table entry",
                            "inputSchema": { "type": "object", "properties": { "index": {"type": "integer"}, "description": {"type": "string"} }, "required": ["index", "description"] }
                        },
                        {
                            "name": "get_entry_description",
                            "description": "Get description of a table entry",
                            "inputSchema": { "type": "object", "properties": { "index": {"type": "integer"} }, "required": ["index"] }
                        },
                        {
                            "name": "set_entry_address",
                            "description": "Set address for a table entry",
                            "inputSchema": { "type": "object", "properties": { "index": {"type": "integer"}, "address": {"type": "string"} }, "required": ["index", "address"] }
                        },
                        {
                            "name": "get_entry_address",
                            "description": "Get address of a table entry",
                            "inputSchema": { "type": "object", "properties": { "index": {"type": "integer"} }, "required": ["index"] }
                        },
                        {
                            "name": "set_entry_type",
                            "description": "Set type for a table entry",
                            "inputSchema": { "type": "object", "properties": { "index": {"type": "integer"}, "type": {"type": "string"} }, "required": ["index", "type"] }
                        },
                        {
                            "name": "get_entry_type",
                            "description": "Get type of a table entry",
                            "inputSchema": { "type": "object", "properties": { "index": {"type": "integer"} }, "required": ["index"] }
                        },
                        {
                            "name": "set_entry_value",
                            "description": "Set value for a table entry",
                            "inputSchema": { "type": "object", "properties": { "index": {"type": "integer"}, "value": {"type": "string"} }, "required": ["index", "value"] }
                        },
                        {
                            "name": "get_entry_value",
                            "description": "Get value of a table entry",
                            "inputSchema": { "type": "object", "properties": { "index": {"type": "integer"} }, "required": ["index"] }
                        },
                        {
                            "name": "set_entry_script",
                            "description": "Set script for a table entry",
                            "inputSchema": { "type": "object", "properties": { "index": {"type": "integer"}, "script": {"type": "string"} }, "required": ["index", "script"] }
                        },
                        {
                            "name": "get_entry_script",
                            "description": "Get script of a table entry",
                            "inputSchema": { "type": "object", "properties": { "index": {"type": "integer"} }, "required": ["index"] }
                        },
                        {
                            "name": "freeze_entry",
                            "description": "Freeze a table entry",
                            "inputSchema": { "type": "object", "properties": { "index": {"type": "integer"} }, "required": ["index"] }
                        },
                        {
                            "name": "unfreeze_entry",
                            "description": "Unfreeze a table entry",
                            "inputSchema": { "type": "object", "properties": { "index": {"type": "integer"} }, "required": ["index"] }
                        },
                        {
                            "name": "delete_entry",
                            "description": "Delete a table entry",
                            "inputSchema": { "type": "object", "properties": { "index": {"type": "integer"} }, "required": ["index"] }
                        },
                        # ── UI 控件 ──
                        {
                            "name": "create_form",
                            "description": "Create a new form",
                            "inputSchema": { "type": "object", "properties": {}, "required": [] }
                        },
                        {
                            "name": "create_control",
                            "description": "Create a UI control",
                            "inputSchema": { "type": "object", "properties": { "owner": {"type": "integer"}, "type_id": {"type": "integer", "description": "0:Panel, 1:Button, 2:Label, 3:Edit, 4:Image, 5:Memo, 6:GroupBox, 7:Timer"} }, "required": ["owner", "type_id"] }
                        },
                        {
                            "name": "control_set_caption",
                            "description": "Set control caption",
                            "inputSchema": { "type": "object", "properties": { "control": {"type": "integer"}, "caption": {"type": "string"} }, "required": ["control", "caption"] }
                        },
                        {
                            "name": "control_get_caption",
                            "description": "Get control caption",
                            "inputSchema": { "type": "object", "properties": { "control": {"type": "integer"} }, "required": ["control"] }
                        },
                        {
                            "name": "control_set_position",
                            "description": "Set control position",
                            "inputSchema": { "type": "object", "properties": { "control": {"type": "integer"}, "x": {"type": "integer"}, "y": {"type": "integer"} }, "required": ["control", "x", "y"] }
                        },
                        {
                            "name": "control_get_position",
                            "description": "Get control position",
                            "inputSchema": { "type": "object", "properties": { "control": {"type": "integer"} }, "required": ["control"] }
                        },
                        {
                            "name": "control_set_size",
                            "description": "Set control size",
                            "inputSchema": { "type": "object", "properties": { "control": {"type": "integer"}, "width": {"type": "integer"}, "height": {"type": "integer"} }, "required": ["control", "width", "height"] }
                        },
                        {
                            "name": "control_get_size",
                            "description": "Get control size",
                            "inputSchema": { "type": "object", "properties": { "control": {"type": "integer"} }, "required": ["control"] }
                        },
                        {
                            "name": "object_destroy",
                            "description": "Destroy an object/control",
                            "inputSchema": { "type": "object", "properties": { "object": {"type": "integer"} }, "required": ["object"] }
                        },
                        {
                            "name": "form_action",
                            "description": "Perform action on form (0:Center, 1:Hide, 2:Show)",
                            "inputSchema": { "type": "object", "properties": { "form": {"type": "integer"}, "action": {"type": "integer"} }, "required": ["form", "action"] }
                        },
                        {
                            "name": "image_load",
                            "description": "Load image from file",
                            "inputSchema": { "type": "object", "properties": { "image": {"type": "integer"}, "filename": {"type": "string"} }, "required": ["image", "filename"] }
                        },
                        {
                            "name": "image_bool",
                            "description": "Set image boolean property (0:Transparent, 1:Stretch)",
                            "inputSchema": { "type": "object", "properties": { "image": {"type": "integer"}, "value": {"type": "boolean"}, "type_id": {"type": "integer"} }, "required": ["image", "value", "type_id"] }
                        },
                        {
                            "name": "timer_set_interval",
                            "description": "Set timer interval",
                            "inputSchema": { "type": "object", "properties": { "timer": {"type": "integer"}, "interval": {"type": "integer"} }, "required": ["timer", "interval"] }
                        }
                    ]
                }
            }

        # ── 工具调用：翻译 AI 请求为 TCP 文本命令发送到 CE ──
        if method == "tools/call":
            tool_name = params.get("name")
            args = params.get("arguments", {})
            result_text = ""

            # ── 基础 ──
            if tool_name == "show_message":
                result_text = self.send_command(f"SHOW_MESSAGE:{args['message']}")

            # ── 进程管理 ──
            elif tool_name == "open_process":
                result_text = self.send_command(f"OPEN_PROCESS:{args['process_id']}")
            elif tool_name == "get_process_id":
                result_text = self.send_command(f"GET_PROCESS_ID:{args['process_name']}")
            elif tool_name == "pause_process":
                result_text = self.send_command("PAUSE_PROCESS")
            elif tool_name == "unpause_process":
                result_text = self.send_command("UNPAUSE_PROCESS")
            elif tool_name == "debug_process":
                result_text = self.send_command(f"DEBUG_PROCESS:{args['process_id']}")

            # ── 高级功能 ──
            elif tool_name == "change_register":
                result_text = self.send_command(f"CHANGE_REGISTER:{args['address']},{args['reg']},{args['value']}")
            elif tool_name == "inject_dll":
                func = args.get('function', '')
                result_text = self.send_command(f"INJECT_DLL:{args['path']},{func}")
            elif tool_name == "speedhack":
                result_text = self.send_command(f"SPEEDHACK:{args['speed']}")
            elif tool_name == "address_to_name":
                result_text = self.send_command(f"ADDRESS_TO_NAME:{args['address']}")
            elif tool_name == "name_to_address":
                result_text = self.send_command(f"NAME_TO_ADDRESS:{args['name']}")
            elif tool_name == "get_address_from_pointer":
                offsets = ",".join(args['offsets'])
                result_text = self.send_command(f"GET_ADDRESS_FROM_POINTER:{args['base']},{offsets}")
            elif tool_name == "previous_opcode":
                result_text = self.send_command(f"PREVIOUS_OPCODE:{args['address']}")
            elif tool_name == "next_opcode":
                result_text = self.send_command(f"NEXT_OPCODE:{args['address']}")
            elif tool_name == "set_breakpoint":
                result_text = self.send_command(f"SET_BREAKPOINT:{args['address']},{args['size']},{args['trigger']}")
            elif tool_name == "remove_breakpoint":
                result_text = self.send_command(f"REMOVE_BREAKPOINT:{args['address']}")
            elif tool_name == "continue_from_breakpoint":
                result_text = self.send_command(f"CONTINUE_FROM_BREAKPOINT:{args['option']}")

            # ── 内存读写 ──
            elif tool_name == "read_memory":
                result_text = self.send_command(f"READ_MEMORY:{args['address']},{args['type']}")
            elif tool_name == "write_memory":
                result_text = self.send_command(f"WRITE_MEMORY:{args['address']},{args['value']},{args['type']}")

            # ── 汇编与反汇编 ──
            elif tool_name == "assemble":
                result_text = self.send_command(f"ASSEMBLE:{args['address']},{args['instruction']}")
            elif tool_name == "disassemble":
                result_text = self.send_command(f"DISASSEMBLE:{args['address']}")
            elif tool_name == "auto_assemble":
                result_text = self.send_command(f"AUTO_ASSEMBLE:{args['script']}")

            # ── 地址列表（Table）管理 ──
            elif tool_name == "create_table_entry":
                result_text = self.send_command(f"CREATE_TABLE_ENTRY:{args['description']},{args['address']},{args['type']}")
            elif tool_name == "get_table_entry":
                result_text = self.send_command(f"GET_TABLE_ENTRY:{args['index']}")
            elif tool_name == "set_entry_description":
                result_text = self.send_command(f"SET_ENTRY_DESCRIPTION:{args['index']},{args['description']}")
            elif tool_name == "get_entry_description":
                result_text = self.send_command(f"GET_ENTRY_DESCRIPTION:{args['index']}")
            elif tool_name == "set_entry_address":
                result_text = self.send_command(f"SET_ENTRY_ADDRESS:{args['index']},{args['address']}")
            elif tool_name == "get_entry_address":
                result_text = self.send_command(f"GET_ENTRY_ADDRESS:{args['index']}")
            elif tool_name == "set_entry_type":
                result_text = self.send_command(f"SET_ENTRY_TYPE:{args['index']},{args['type']}")
            elif tool_name == "get_entry_type":
                result_text = self.send_command(f"GET_ENTRY_TYPE:{args['index']}")
            elif tool_name == "set_entry_value":
                result_text = self.send_command(f"SET_ENTRY_VALUE:{args['index']},{args['value']}")
            elif tool_name == "get_entry_value":
                result_text = self.send_command(f"GET_ENTRY_VALUE:{args['index']}")
            elif tool_name == "set_entry_script":
                result_text = self.send_command(f"SET_ENTRY_SCRIPT:{args['index']},{args['script']}")
            elif tool_name == "get_entry_script":
                result_text = self.send_command(f"GET_ENTRY_SCRIPT:{args['index']}")
            elif tool_name == "freeze_entry":
                result_text = self.send_command(f"FREEZE_ENTRY:{args['index']}")
            elif tool_name == "unfreeze_entry":
                result_text = self.send_command(f"UNFREEZE_ENTRY:{args['index']}")
            elif tool_name == "delete_entry":
                result_text = self.send_command(f"DELETE_ENTRY:{args['index']}")

            # ── UI 控件 ──
            elif tool_name == "create_form":
                result_text = self.send_command("CREATE_FORM")
            elif tool_name == "create_control":
                result_text = self.send_command(f"CREATE_CONTROL:{args['owner']},{args['type_id']}")
            elif tool_name == "control_set_caption":
                result_text = self.send_command(f"CONTROL_SET_CAPTION:{args['control']},{args['caption']}")
            elif tool_name == "control_get_caption":
                result_text = self.send_command(f"CONTROL_GET_CAPTION:{args['control']}")
            elif tool_name == "control_set_position":
                result_text = self.send_command(f"CONTROL_SET_POSITION:{args['control']},{args['x']},{args['y']}")
            elif tool_name == "control_get_position":
                result_text = self.send_command(f"CONTROL_GET_POSITION:{args['control']}")
            elif tool_name == "control_set_size":
                result_text = self.send_command(f"CONTROL_SET_SIZE:{args['control']},{args['width']},{args['height']}")
            elif tool_name == "control_get_size":
                result_text = self.send_command(f"CONTROL_GET_SIZE:{args['control']}")
            elif tool_name == "object_destroy":
                result_text = self.send_command(f"OBJECT_DESTROY:{args['object']}")
            elif tool_name == "form_action":
                result_text = self.send_command(f"FORM_ACTION:{args['form']},{args['action']}")
            elif tool_name == "image_load":
                result_text = self.send_command(f"IMAGE_LOAD:{args['image']},{args['filename']}")
            elif tool_name == "image_bool":
                val_str = "true" if args['value'] else "false"
                result_text = self.send_command(f"IMAGE_BOOL:{args['image']},{val_str},{args['type_id']}")
            elif tool_name == "timer_set_interval":
                result_text = self.send_command(f"TIMER_SET_INTERVAL:{args['timer']},{args['interval']}")

            else:
                result_text = f"Unknown tool: {tool_name}"

            # 统一返回 JSON-RPC 响应
            return {
                "jsonrpc": "2.0",
                "id": msg_id,
                "result": {
                    "content": [
                        {
                            "type": "text",
                            "text": result_text
                        }
                    ]
                }
            }

        # ── 未知方法：返回错误 ──
        return {
            "jsonrpc": "2.0",
            "id": msg_id,
            "error": {
                "code": -32601,
                "message": "Method not found"
            }
        }


if __name__ == "__main__":
    # 命令行参数解析
    parser = argparse.ArgumentParser(description='Cheat Engine MCP Bridge Server')
    parser.add_argument('--host', default='127.0.0.1', help='TCP Host to bind to (default: 127.0.0.1)')
    parser.add_argument('--port', type=int, default=8888, help='TCP Port to bind to (default: 8888)')
    args = parser.parse_args()

    # 启动桥接服务器
    server = BridgeServer(host=args.host, port=args.port)
    try:
        server.run_mcp_loop()
    except KeyboardInterrupt:
        server.running = False