import socket
import sys
import json
import threading
import queue
import time
import argparse
from typing import Optional, Dict, Any

# Simple MCP Protocol Implementation
# Reads from stdin, writes to stdout
# JSON-RPC 2.0

class BridgeServer:
    def __init__(self, host='127.0.0.1', port=8888):
        self.host = host
        self.port = port
        self.conn: Optional[socket.socket] = None
        self.response_queue = queue.Queue()
        self.running = True
        self.lock = threading.Lock()

    def start_tcp_server(self):
        server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server_sock.bind((self.host, self.port))
        server_sock.listen(1)
        # print(f"Listening on {self.host}:{self.port} for CE Plugin...", file=sys.stderr)
        
        while self.running:
            try:
                conn, addr = server_sock.accept()
                # print(f"Connected by {addr}", file=sys.stderr)
                self.conn = conn
                self.handle_connection(conn)
            except Exception as e:
                if self.running:
                    print(f"Server error: {e}", file=sys.stderr)
                    time.sleep(1)

    def handle_connection(self, conn):
        buffer = ""
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
        if not self.conn:
            return "Error: Cheat Engine not connected"
        
        try:
            with self.lock:
                # Clear queue
                while not self.response_queue.empty():
                    self.response_queue.get()
                
                self.conn.sendall(cmd.encode('utf-8'))
                
                # Wait for response (timeout 5s)
                try:
                    return self.response_queue.get(timeout=5)
                except queue.Empty:
                    return "Error: Timeout waiting for response"
        except Exception as e:
            return f"Error: {e}"

    def run_mcp_loop(self):
        # Start TCP server in background
        t = threading.Thread(target=self.start_tcp_server, daemon=True)
        t.start()

        # Read JSON-RPC from stdin
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
        if "method" not in request:
            return None
        
        method = request["method"]
        msg_id = request.get("id")
        params = request.get("params", {})

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
        
        if method == "notifications/initialized":
            return None

        if method == "tools/list":
            return {
                "jsonrpc": "2.0",
                "id": msg_id,
                "result": {
                    "tools": [
                        # --- Basic ---
                        {
                            "name": "show_message",
                            "description": "Show a message box in Cheat Engine",
                            "inputSchema": { "type": "object", "properties": { "message": {"type": "string"} }, "required": ["message"] }
                        },
                        # --- Process ---
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
                        # --- Advanced ---
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
                        # --- Memory ---
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
                        # --- Assembly ---
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
                        # --- Table Management ---
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
                        # --- UI Controls ---
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
                            "description": "Set boolean property for image (0:Transparent, 1:Stretch)",
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

        if method == "tools/call":
            tool_name = params.get("name")
            args = params.get("arguments", {})
            result_text = ""
            
            # --- Basic ---
            if tool_name == "show_message":
                result_text = self.send_command(f"SHOW_MESSAGE:{args['message']}")
            
            # --- Process ---
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

            # --- Advanced ---
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

            # --- Memory ---
            elif tool_name == "read_memory":
                result_text = self.send_command(f"READ_MEMORY:{args['address']},{args['type']}")
            elif tool_name == "write_memory":
                result_text = self.send_command(f"WRITE_MEMORY:{args['address']},{args['value']},{args['type']}")

            # --- Assembly ---
            elif tool_name == "assemble":
                result_text = self.send_command(f"ASSEMBLE:{args['address']},{args['instruction']}")
            elif tool_name == "disassemble":
                result_text = self.send_command(f"DISASSEMBLE:{args['address']}")
            elif tool_name == "auto_assemble":
                result_text = self.send_command(f"AUTO_ASSEMBLE:{args['script']}")

            # --- Table Management ---
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

            # --- UI Controls ---
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

        return {
            "jsonrpc": "2.0",
            "id": msg_id,
            "error": {
                "code": -32601,
                "message": "Method not found"
            }
        }

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Cheat Engine MCP Bridge Server')
    parser.add_argument('--host', default='127.0.0.1', help='TCP Host to bind to (default: 127.0.0.1)')
    parser.add_argument('--port', type=int, default=8888, help='TCP Port to bind to (default: 8888)')
    args = parser.parse_args()

    server = BridgeServer(host=args.host, port=args.port)
    try:
        server.run_mcp_loop()
    except KeyboardInterrupt:
        server.running = False
