//! CE-MCP 插件主模块
//!
//! 本文件是 Cheat Engine MCP (Model Context Protocol) 插件的核心实现。
//! 插件通过 CE SDK 与 Cheat Engine 深度集成，提供 75+ 个 MCP 命令，
//! 涵盖内存读写、汇编/反汇编、UI 控件管理、地址列表操作、进程控制、
//! 调试断点、DLL 注入、变速齿轮等功能。
//!
//! 架构概述:
//! - `DllMain`: DLL 入口点
//! - `CEPlugin_GetVersion`: 返回 CE SDK 版本信息
//! - `CEPlugin_InitializePlugin`: 初始化插件，启动 TCP Server 线程，注册 Lua 函数
//! - `CEPlugin_DisablePlugin`: 清理资源
//! - `timer_callback`: CE 定时器回调，轮询处理 TCP 命令
//! - `handle_*`: 各命令的具体处理函数
//!
//! 命令处理流程:
//! AI → TCP → Server::start() (后台线程) → channel → timer_callback (CE 主线程) → handle_* → CE API

extern crate obfstr;

mod ce_sys;
mod protocol;
mod server;

use std::ffi::CString;
use std::ptr;
use std::sync::Mutex;
use winapi::ctypes::{c_void, c_int};
use winapi::shared::minwindef::{BOOL, DWORD, HINSTANCE, LPVOID, TRUE, BYTE};
use winapi::um::winnt::{DLL_PROCESS_DETACH, PVOID};
use winapi::shared::basetsd::SIZE_T;
use crossbeam_channel::{unbounded, Receiver, Sender};
use lazy_static::lazy_static;
use winapi::um::libloaderapi::{GetModuleHandleA, GetProcAddress};
// 引入 CE SDK 导出函数表
use crate::ce_sys::{
    ExportedFunctions, MainMenuPluginInit, PluginType, PluginVersion, CESDK_VERSION, 
    CepReadProcessMemory, CepWriteProcessMemory, CepAutoAssemble, CepAssembler, CepDisassembler,
    CepCreateForm, CepCreatePanel, CepCreateButton, CepCreateLabel, CepCreateEdit, CepCreateImage,
    CepCreateMemo, CepCreateGroupBox, CepCreateTimer, CepControlSetCaption, CepControlGetCaption,
    CepControlSetPosition, CepControlGetX, CepControlGetY, CepControlSetSize, CepControlGetWidth,
    CepControlGetHeight, CepObjectDestroy, CepFormCenterScreen, CepFormHide, CepFormShow,
    CepImageLoadImageFromFile, CepImageTransparent, CepImageStretch, CepTimerSetInterval, CepTimerOnTimer,
    CepCreateTableEntry, CepGetTableEntry, CepSetEntryDescription, CepGetEntryDescription,
    CepSetEntryAddress, CepGetEntryAddress, CepSetEntryType, CepGetEntryType, CepSetEntryValue,
    CepGetEntryValue, CepSetEntryScript, CepGetEntryScript, CepFreezeEntry, CepUnfreezeEntry,
    CepDeleteEntry, CepOpenProcess, CepGetProcessIdFromProcessName, CepPause, CepUnpause, CepDebugProcess,
    CepChangeRegistersAtAddress, CepInjectDLL, CepSpeedhackSetSpeed, CepSymAddressToName, CepSymNameToAddress,
    CepGetAddressFromPointer, CepPreviousOpcode, CepNextOpcode, CepDebugSetBreakpoint, CepDebugRemoveBreakpoint,
    CepDebugContinueFromBreakpoint,
    lua_State, LuaGetTop, LuaPushString, LuaTolString, LuaRegister
};
use crate::protocol::Command;
use crate::server::Server;

// ── 全局状态 ──
// EXPORTED 和 PLUGIN_ID 是全局变量，在 CEPlugin_InitializePlugin 中初始化，
// 之后被所有 handle_* 函数读取。由于 CE SDK 是单线程调用的，使用 unsafe static 即可。

/// CE SDK 导出函数表全局引用
static mut EXPORTED: Option<ExportedFunctions> = None;
/// 当前插件 ID
static mut PLUGIN_ID: i32 = -1;

lazy_static! { // 服务器线程
    static ref SERVER: Mutex<Option<Server>> = Mutex::new(None); // 服务器实例
    static ref CHANNEL: (Sender<Command>, Receiver<Command>) = unbounded(); // 命令通道
}

// ── 汇编：Auto Assembler ──
/// 执行 Auto Assembler 脚本
unsafe fn handle_auto_assemble(script: &str) {
    if let Some(exported) = unsafe { &*ptr::addr_of!(EXPORTED) }.as_ref() { // 检查导出函数表是否初始化
        if exported.auto_assemble.is_null() {
            return;
        }
        let auto_assemble: CepAutoAssemble = std::mem::transmute(exported.auto_assemble); // 转换为 CE SDK 函数指针
        let c_script = CString::new(script).unwrap_or_default(); 
        let result = auto_assemble(c_script.as_ptr()); // 调用 CE SDK 函数
        
        let msg = format!("AutoAssemble result: {}", result); // 格式化结果
        send_response(msg);
    }
}

// ── 汇编：写入指令 ──
/// 汇编指令到指定地址
unsafe fn handle_assemble(address: usize, instruction: &str) {
    if let Some(exported) = unsafe { &*ptr::addr_of!(EXPORTED) }.as_ref() { // 检查导出函数表是否初始化
        if exported.assembler.is_null() {
            return;
        }
        let assembler: CepAssembler = std::mem::transmute(exported.assembler); // 转换为 CE SDK 函数指针
        let c_instruction = CString::new(instruction).unwrap_or_default();
        let mut output = [0u8; 16];
        let mut returned_size: c_int = 0;
        
        let result = assembler(
            address,
            c_instruction.as_ptr(),
            output.as_mut_ptr() as *mut BYTE,
            output.len() as c_int,
            &mut returned_size
        );

        if result == TRUE {
            let mut hex_output = String::new();
            for i in 0..returned_size {
                hex_output.push_str(&format!("{:02X} ", output[i as usize]));
            }
            
            let msg = format!("Assemble result: {}\nBytes: {}", instruction, hex_output.trim());
            send_response(msg);
        } else {
             send_response("Assemble failed".to_string());
        }
    }
}

// ── 汇编：反汇编 ──
/// 反汇编指定地址
unsafe fn handle_disassemble(address: usize) {
    if let Some(exported) = unsafe { &*ptr::addr_of!(EXPORTED) }.as_ref() {
        if exported.disassembler.is_null() {
            return;
        }
        let disassembler: CepDisassembler = std::mem::transmute(exported.disassembler);
        let mut output = [0u8; 256];
        
        let result = disassembler(
            address,
            output.as_mut_ptr() as *mut i8,
            output.len() as c_int
        );

        if result == TRUE {
            // 找到 null 终止符或缓冲区长
            let len = output.iter().position(|&c| c == 0).unwrap_or(output.len());
            let instruction = String::from_utf8_lossy(&output[0..len]);
            
            let msg = format!("Disassemble result (0x{:X}): {}", address, instruction);
            send_response(msg);
        } else {
             send_response("Disassemble failed".to_string());
        }
    }
}

// ── UI 控件：表单 ──
/// 创建新表单
unsafe fn handle_create_form() {
    if let Some(exported) = unsafe { &*ptr::addr_of!(EXPORTED) }.as_ref() {
        if exported.create_form.is_null() { return; }
        let create_form: CepCreateForm = std::mem::transmute(exported.create_form);
        let form = create_form();
        send_response(format!("CreateForm result: Form pointer = 0x{:X}", form as usize));
    }
}

/// 创建子控件（Panel/Button/Label 等）
unsafe fn handle_create_control(owner: usize, type_id: i32) {
    if let Some(exported) = unsafe { &*ptr::addr_of!(EXPORTED) }.as_ref() {
        let owner_ptr = owner as PVOID;
        let result_ptr = match type_id {
            0 => { // 面板
                if exported.create_panel.is_null() { return; }
                let func: CepCreatePanel = std::mem::transmute(exported.create_panel);
                func(owner_ptr)
            },
            1 => { // 按钮
                if exported.create_button.is_null() { return; }
                let func: CepCreateButton = std::mem::transmute(exported.create_button);
                func(owner_ptr)
            },
            2 => { // 标签
                if exported.create_label.is_null() { return; }
                let func: CepCreateLabel = std::mem::transmute(exported.create_label);
                func(owner_ptr)
            },
            3 => { // 编辑框
                if exported.create_edit.is_null() { return; }
                let func: CepCreateEdit = std::mem::transmute(exported.create_edit);
                func(owner_ptr)
            },
            4 => { // 图片
                if exported.create_image.is_null() { return; }
                let func: CepCreateImage = std::mem::transmute(exported.create_image);
                func(owner_ptr)
            },
            5 => { // 多行文本框
                if exported.create_memo.is_null() { return; }
                let func: CepCreateMemo = std::mem::transmute(exported.create_memo);
                func(owner_ptr)
            },
            6 => { // 分组框
                if exported.create_group_box.is_null() { return; }
                let func: CepCreateGroupBox = std::mem::transmute(exported.create_group_box);
                func(owner_ptr)
            },
            7 => { // 定时器
                if exported.create_timer.is_null() { return; }
                let func: CepCreateTimer = std::mem::transmute(exported.create_timer);
                func(owner_ptr)
            },
            _ => return,
        };
        send_response(format!("CreateControl result: 0x{:X}", result_ptr as usize));
    }
}

// ── UI 控件：标题 ──
/// 设置控件标题
unsafe fn handle_set_caption(control: usize, caption: &str) {
    if let Some(exported) = unsafe { &*ptr::addr_of!(EXPORTED) }.as_ref() {
        if exported.control_set_caption.is_null() { return; }
        let set_caption: CepControlSetCaption = std::mem::transmute(exported.control_set_caption);
        let c_caption = CString::new(caption).unwrap_or_default();
        set_caption(control as PVOID, c_caption.as_ptr());
    }
}

unsafe fn handle_get_caption(control: usize) {
    if let Some(exported) = unsafe { &*ptr::addr_of!(EXPORTED) }.as_ref() {
        if exported.control_get_caption.is_null() { return; }
        let get_caption: CepControlGetCaption = std::mem::transmute(exported.control_get_caption);
        let mut buffer = [0u8; 256];
        if get_caption(control as PVOID, buffer.as_mut_ptr() as *mut i8, 255) == TRUE {
             let len = buffer.iter().position(|&c| c == 0).unwrap_or(buffer.len());
             let caption = String::from_utf8_lossy(&buffer[0..len]);
             send_response(format!("GetCaption result: {}", caption));
        }
    }
}

unsafe fn handle_set_position(control: usize, x: i32, y: i32) {
    if let Some(exported) = unsafe { &*ptr::addr_of!(EXPORTED) }.as_ref() {
        if exported.control_set_position.is_null() { return; }
        let set_pos: CepControlSetPosition = std::mem::transmute(exported.control_set_position);
        set_pos(control as PVOID, x, y);
    }
}

unsafe fn handle_get_position(control: usize) {
    if let Some(exported) = unsafe { &*ptr::addr_of!(EXPORTED) }.as_ref() {
        if exported.control_get_x.is_null() || exported.control_get_y.is_null() { return; }
        let get_x: CepControlGetX = std::mem::transmute(exported.control_get_x);
        let get_y: CepControlGetY = std::mem::transmute(exported.control_get_y);
        let x = get_x(control as PVOID);
        let y = get_y(control as PVOID);
        send_response(format!("GetPosition result: X={}, Y={}", x, y));
    }
}

unsafe fn handle_set_size(control: usize, width: i32, height: i32) {
    if let Some(exported) = unsafe { &*ptr::addr_of!(EXPORTED) }.as_ref() {
        if exported.control_set_size.is_null() { return; }
        let set_size: CepControlSetSize = std::mem::transmute(exported.control_set_size);
        set_size(control as PVOID, width, height);
    }
}

unsafe fn handle_get_size(control: usize) {
    if let Some(exported) = unsafe { &*ptr::addr_of!(EXPORTED) }.as_ref() {
        if exported.control_get_width.is_null() || exported.control_get_height.is_null() { return; }
        let get_w: CepControlGetWidth = std::mem::transmute(exported.control_get_width);
        let get_h: CepControlGetHeight = std::mem::transmute(exported.control_get_height);
        let w = get_w(control as PVOID);
        let h = get_h(control as PVOID);
        send_response(format!("GetSize result: W={}, H={}", w, h));
    }
}

unsafe fn handle_destroy_object(object: usize) {
    if let Some(exported) = unsafe { &*ptr::addr_of!(EXPORTED) }.as_ref() {
        if exported.object_destroy.is_null() { return; }
        let destroy: CepObjectDestroy = std::mem::transmute(exported.object_destroy);
        destroy(object as PVOID);
    }
}

unsafe fn handle_form_action(form: usize, action: i32) {
    if let Some(exported) = unsafe { &*ptr::addr_of!(EXPORTED) }.as_ref() {
        match action {
            0 => { // 居中
                if exported.form_center_screen.is_null() { return; }
                let func: CepFormCenterScreen = std::mem::transmute(exported.form_center_screen);
                func(form as PVOID);
            },
            1 => { // 隐藏
                if exported.form_hide.is_null() { return; }
                let func: CepFormHide = std::mem::transmute(exported.form_hide);
                func(form as PVOID);
            },
            2 => { // 显示
                if exported.form_show.is_null() { return; }
                let func: CepFormShow = std::mem::transmute(exported.form_show);
                func(form as PVOID);
            },
            _ => {}
        }
    }
}

unsafe fn handle_image_load(image: usize, filename: &str) {
    if let Some(exported) = unsafe { &*ptr::addr_of!(EXPORTED) }.as_ref() {
        if exported.image_load_image_from_file.is_null() { return; }
        let load: CepImageLoadImageFromFile = std::mem::transmute(exported.image_load_image_from_file);
        let c_filename = CString::new(filename).unwrap_or_default();
        load(image as PVOID, c_filename.as_ptr());
    }
}

unsafe fn handle_image_bool(image: usize, value: bool, type_id: i32) {
    if let Some(exported) = unsafe { &*ptr::addr_of!(EXPORTED) }.as_ref() {
        let val = if value { TRUE } else { 0 };
        match type_id {
            0 => { // 透明
                if exported.image_transparent.is_null() { return; }
                let func: CepImageTransparent = std::mem::transmute(exported.image_transparent);
                func(image as PVOID, val);
            },
            1 => { // 拉伸
                if exported.image_stretch.is_null() { return; }
                let func: CepImageStretch = std::mem::transmute(exported.image_stretch);
                func(image as PVOID, val);
            },
            _ => {}
        }
    }
}

unsafe fn handle_timer_set_interval(timer: usize, interval: i32) {
    if let Some(exported) = unsafe { &*ptr::addr_of!(EXPORTED) }.as_ref() {
        if exported.timer_set_interval.is_null() { return; }
        let func: CepTimerSetInterval = std::mem::transmute(exported.timer_set_interval);
        func(timer as PVOID, interval);
    }
}

// ── 地址列表：创建条目 ──
/// 创建内存表条目
unsafe fn handle_create_table_entry(description: &str, address: &str, type_: &str) {
    if let Some(exported) = unsafe { &*ptr::addr_of!(EXPORTED) }.as_ref() {
        if exported.create_table_entry.is_null() { return; }
        let create_entry: CepCreateTableEntry = std::mem::transmute(exported.create_table_entry);
        let entry = create_entry();
        
        if !entry.is_null() {
            // 设置属性
            if !exported.set_entry_description.is_null() {
                let set_desc: CepSetEntryDescription = std::mem::transmute(exported.set_entry_description);
                let c_desc = CString::new(description).unwrap_or_default();
                set_desc(entry, c_desc.as_ptr());
            }
            if !exported.set_entry_address.is_null() {
                let set_addr: CepSetEntryAddress = std::mem::transmute(exported.set_entry_address);
                let c_addr = CString::new(address).unwrap_or_default();
                set_addr(entry, c_addr.as_ptr());
            }
            
            // 类型映射（简化版）
            let type_id = match type_.to_uppercase().as_str() {
                "BYTE" => 0, "WORD" => 1, "DWORD" => 2, "FLOAT" => 3, "DOUBLE" => 4,
                "STRING" => 6, "BYTE_ARRAY" => 7, _ => 2
            };
            if !exported.set_entry_type.is_null() {
                let set_type: CepSetEntryType = std::mem::transmute(exported.set_entry_type);
                set_type(entry, type_id);
            }

            send_response(format!("CreateTableEntry result: 0x{:X}", entry as usize));
        } else {
            send_response("CreateTableEntry failed".to_string());
        }
    }
}

unsafe fn handle_get_table_entry(index: i32) {
    if let Some(exported) = unsafe { &*ptr::addr_of!(EXPORTED) }.as_ref() {
        if exported.get_table_entry.is_null() { return; }
        let get_entry: CepGetTableEntry = std::mem::transmute(exported.get_table_entry);
        let entry = get_entry(index);
        send_response(format!("GetTableEntry result: 0x{:X}", entry as usize));
    }
}

unsafe fn handle_set_entry_description(index: i32, description: &str) {
    if let Some(exported) = unsafe { &*ptr::addr_of!(EXPORTED) }.as_ref() {
        if exported.get_table_entry.is_null() || exported.set_entry_description.is_null() { return; }
        let get_entry: CepGetTableEntry = std::mem::transmute(exported.get_table_entry);
        let entry = get_entry(index);
        if !entry.is_null() {
            let set_desc: CepSetEntryDescription = std::mem::transmute(exported.set_entry_description);
            let c_desc = CString::new(description).unwrap_or_default();
            set_desc(entry, c_desc.as_ptr());
        }
    }
}

unsafe fn handle_get_entry_description(index: i32) {
    if let Some(exported) = unsafe { &*ptr::addr_of!(EXPORTED) }.as_ref() {
        if exported.get_table_entry.is_null() || exported.get_entry_description.is_null() { return; }
        let get_entry: CepGetTableEntry = std::mem::transmute(exported.get_table_entry);
        let entry = get_entry(index);
        if !entry.is_null() {
            let get_desc: CepGetEntryDescription = std::mem::transmute(exported.get_entry_description);
            let mut buffer = [0u8; 256];
            if get_desc(entry, buffer.as_mut_ptr() as *mut i8, 255) == TRUE {
                let len = buffer.iter().position(|&c| c == 0).unwrap_or(buffer.len());
                let desc = String::from_utf8_lossy(&buffer[0..len]);
                send_response(format!("GetEntryDescription result: {}", desc));
            }
        }
    }
}

unsafe fn handle_set_entry_address(index: i32, address: &str) {
    if let Some(exported) = unsafe { &*ptr::addr_of!(EXPORTED) }.as_ref() {
        if exported.get_table_entry.is_null() || exported.set_entry_address.is_null() { return; }
        let get_entry: CepGetTableEntry = std::mem::transmute(exported.get_table_entry);
        let entry = get_entry(index);
        if !entry.is_null() {
            let set_addr: CepSetEntryAddress = std::mem::transmute(exported.set_entry_address);
            let c_addr = CString::new(address).unwrap_or_default();
            set_addr(entry, c_addr.as_ptr());
        }
    }
}

unsafe fn handle_get_entry_address(index: i32) {
    if let Some(exported) = unsafe { &*ptr::addr_of!(EXPORTED) }.as_ref() {
        if exported.get_table_entry.is_null() || exported.get_entry_address.is_null() { return; }
        let get_entry: CepGetTableEntry = std::mem::transmute(exported.get_table_entry);
        let entry = get_entry(index);
        if !entry.is_null() {
            let get_addr: CepGetEntryAddress = std::mem::transmute(exported.get_entry_address);
            let mut buffer = [0u8; 256];
            if get_addr(entry, buffer.as_mut_ptr() as *mut i8, 255) == TRUE {
                let len = buffer.iter().position(|&c| c == 0).unwrap_or(buffer.len());
                let addr = String::from_utf8_lossy(&buffer[0..len]);
                send_response(format!("GetEntryAddress result: {}", addr));
            }
        }
    }
}

unsafe fn handle_set_entry_type(index: i32, type_: &str) {
    if let Some(exported) = unsafe { &*ptr::addr_of!(EXPORTED) }.as_ref() {
        if exported.get_table_entry.is_null() || exported.set_entry_type.is_null() { return; }
        let get_entry: CepGetTableEntry = std::mem::transmute(exported.get_table_entry);
        let entry = get_entry(index);
        if !entry.is_null() {
            let type_id = match type_.to_uppercase().as_str() {
                "BYTE" => 0, "WORD" => 1, "DWORD" => 2, "FLOAT" => 3, "DOUBLE" => 4,
                "STRING" => 6, "BYTE_ARRAY" => 7, _ => 2
            };
            let set_type: CepSetEntryType = std::mem::transmute(exported.set_entry_type);
            set_type(entry, type_id);
        }
    }
}

unsafe fn handle_get_entry_type(index: i32) {
    if let Some(exported) = unsafe { &*ptr::addr_of!(EXPORTED) }.as_ref() {
        if exported.get_table_entry.is_null() || exported.get_entry_type.is_null() { return; }
        let get_entry: CepGetTableEntry = std::mem::transmute(exported.get_table_entry);
        let entry = get_entry(index);
        if !entry.is_null() {
            let get_type: CepGetEntryType = std::mem::transmute(exported.get_entry_type);
            let type_id = get_type(entry);
            send_response(format!("GetEntryType result: {}", type_id));
        }
    }
}

unsafe fn handle_set_entry_value(index: i32, value: &str) {
    if let Some(exported) = unsafe { &*ptr::addr_of!(EXPORTED) }.as_ref() {
        if exported.get_table_entry.is_null() || exported.set_entry_value.is_null() { return; }
        let get_entry: CepGetTableEntry = std::mem::transmute(exported.get_table_entry);
        let entry = get_entry(index);
        if !entry.is_null() {
            let set_val: CepSetEntryValue = std::mem::transmute(exported.set_entry_value);
            let c_val = CString::new(value).unwrap_or_default();
            set_val(entry, c_val.as_ptr());
        }
    }
}

unsafe fn handle_get_entry_value(index: i32) {
    if let Some(exported) = unsafe { &*ptr::addr_of!(EXPORTED) }.as_ref() {
        if exported.get_table_entry.is_null() || exported.get_entry_value.is_null() { return; }
        let get_entry: CepGetTableEntry = std::mem::transmute(exported.get_table_entry);
        let entry = get_entry(index);
        if !entry.is_null() {
            let get_val: CepGetEntryValue = std::mem::transmute(exported.get_entry_value);
            let mut buffer = [0u8; 256];
            if get_val(entry, buffer.as_mut_ptr() as *mut i8, 255) == TRUE {
                let len = buffer.iter().position(|&c| c == 0).unwrap_or(buffer.len());
                let val = String::from_utf8_lossy(&buffer[0..len]);
                send_response(format!("GetEntryValue result: {}", val));
            }
        }
    }
}

unsafe fn handle_set_entry_script(index: i32, script: &str) {
    if let Some(exported) = unsafe { &*ptr::addr_of!(EXPORTED) }.as_ref() {
        if exported.get_table_entry.is_null() || exported.set_entry_script.is_null() { return; }
        let get_entry: CepGetTableEntry = std::mem::transmute(exported.get_table_entry);
        let entry = get_entry(index);
        if !entry.is_null() {
            let set_script: CepSetEntryScript = std::mem::transmute(exported.set_entry_script);
            let c_script = CString::new(script).unwrap_or_default();
            set_script(entry, c_script.as_ptr());
        }
    }
}

unsafe fn handle_get_entry_script(index: i32) {
    if let Some(exported) = unsafe { &*ptr::addr_of!(EXPORTED) }.as_ref() {
        if exported.get_table_entry.is_null() || exported.get_entry_script.is_null() { return; }
        let get_entry: CepGetTableEntry = std::mem::transmute(exported.get_table_entry);
        let entry = get_entry(index);
        if !entry.is_null() {
            let get_script: CepGetEntryScript = std::mem::transmute(exported.get_entry_script);
            let mut buffer = [0u8; 4096]; // 脚本用大缓冲区
            if get_script(entry, buffer.as_mut_ptr() as *mut i8, 4095) == TRUE {
                let len = buffer.iter().position(|&c| c == 0).unwrap_or(buffer.len());
                let script = String::from_utf8_lossy(&buffer[0..len]);
                send_response(format!("GetEntryScript result: {}", script));
            }
        }
    }
}

unsafe fn handle_freeze_entry(index: i32) {
    if let Some(exported) = unsafe { &*ptr::addr_of!(EXPORTED) }.as_ref() {
        if exported.get_table_entry.is_null() || exported.freeze_entry.is_null() { return; }
        let get_entry: CepGetTableEntry = std::mem::transmute(exported.get_table_entry);
        let entry = get_entry(index);
        if !entry.is_null() {
            let freeze: CepFreezeEntry = std::mem::transmute(exported.freeze_entry);
            freeze(entry);
        }
    }
}

unsafe fn handle_unfreeze_entry(index: i32) {
    if let Some(exported) = unsafe { &*ptr::addr_of!(EXPORTED) }.as_ref() {
        if exported.get_table_entry.is_null() || exported.unfreeze_entry.is_null() { return; }
        let get_entry: CepGetTableEntry = std::mem::transmute(exported.get_table_entry);
        let entry = get_entry(index);
        if !entry.is_null() {
            let unfreeze: CepUnfreezeEntry = std::mem::transmute(exported.unfreeze_entry);
            unfreeze(entry);
        }
    }
}

unsafe fn handle_delete_entry(index: i32) {
    if let Some(exported) = unsafe { &*ptr::addr_of!(EXPORTED) }.as_ref() {
        if exported.get_table_entry.is_null() || exported.delete_entry.is_null() { return; }
        let get_entry: CepGetTableEntry = std::mem::transmute(exported.get_table_entry);
        let entry = get_entry(index);
        if !entry.is_null() {
            let del_entry: CepDeleteEntry = std::mem::transmute(exported.delete_entry);
            del_entry(entry);
        }
    }
}

// ── 进程管理：打开进程 ──
/// 按 PID 打开目标进程
unsafe fn handle_open_process(process_id: u32) {
    if let Some(exported) = unsafe { &*ptr::addr_of!(EXPORTED) }.as_ref() {
        if exported.open_process.is_null() { return; }
        let open_proc: CepOpenProcess = std::mem::transmute(exported.open_process);
        let result = open_proc(process_id as DWORD);
        if result == TRUE {
            send_response(format!("OpenProcess success: {}", process_id));
        } else {
            send_response(format!("OpenProcess failed: {}", process_id));
        }
    }
}

unsafe fn handle_get_process_id(process_name: &str) {
    if let Some(exported) = unsafe { &*ptr::addr_of!(EXPORTED) }.as_ref() {
        if exported.get_process_id_from_process_name.is_null() { return; }
        let get_pid: CepGetProcessIdFromProcessName = std::mem::transmute(exported.get_process_id_from_process_name);
        let c_name = CString::new(process_name).unwrap_or_default();
        let pid = get_pid(c_name.as_ptr());
        send_response(format!("GetProcessId result: {}", pid));
    }
}

unsafe fn handle_pause_process() {
    if let Some(exported) = unsafe { &*ptr::addr_of!(EXPORTED) }.as_ref() {
        if exported.pause.is_null() { return; }
        let pause: CepPause = std::mem::transmute(exported.pause);
        pause();
    }
}

unsafe fn handle_unpause_process() {
    if let Some(exported) = unsafe { &*ptr::addr_of!(EXPORTED) }.as_ref() {
        if exported.unpause.is_null() { return; }
        let unpause: CepUnpause = std::mem::transmute(exported.unpause);
        unpause();
    }
}

unsafe fn handle_debug_process(process_id: u32) {
    if let Some(exported) = unsafe { &*ptr::addr_of!(EXPORTED) }.as_ref() {
        if exported.debug_process.is_null() { return; }
        let debug: CepDebugProcess = std::mem::transmute(exported.debug_process);
        let result = debug(process_id as DWORD);
        if result == TRUE {
            send_response(format!("DebugProcess success: {}", process_id));
        } else {
            send_response(format!("DebugProcess failed: {}", process_id));
        }
    }
}

// 高级功能
// ── 高级功能：寄存器修改 ──
/// 修改指定地址的寄存器值
unsafe fn handle_change_register(address: usize, reg: &str, value: &str) {
    if let Some(exported) = unsafe { &*ptr::addr_of!(EXPORTED) }.as_ref() {
        if exported.change_registers_at_address.is_null() { return; }
        let change_reg: CepChangeRegistersAtAddress = std::mem::transmute(exported.change_registers_at_address);
        // 构建 "REG=VALUE" 字符串
        let change_str = format!("{}={}", reg, value);
        let c_str = CString::new(change_str).unwrap_or_default();
        let result = change_reg(address, c_str.as_ptr());
        if result == TRUE {
             send_response(format!("ChangeRegister success at 0x{:X}", address));
        } else {
             send_response("ChangeRegister failed".to_string());
        }
    }
}

unsafe fn handle_inject_dll(path: &str, function: &str) {
    if let Some(exported) = unsafe { &*ptr::addr_of!(EXPORTED) }.as_ref() {
        if exported.inject_dll.is_null() { return; }
        let inject: CepInjectDLL = std::mem::transmute(exported.inject_dll);
        let c_path = CString::new(path).unwrap_or_default();
        let c_func = CString::new(function).unwrap_or_default();
        // 函数名为空时传 null 指针
        let func_ptr = if function.is_empty() { ptr::null() } else { c_func.as_ptr() };
        
        let result = inject(c_path.as_ptr(), func_ptr);
        if result == TRUE {
             send_response(format!("InjectDLL success: {}", path));
        } else {
             send_response("InjectDLL failed".to_string());
        }
    }
}

unsafe fn handle_speedhack(speed: f32) {
    if let Some(exported) = unsafe { &*ptr::addr_of!(EXPORTED) }.as_ref() {
        if exported.speedhack_set_speed.is_null() { return; }
        let set_speed: CepSpeedhackSetSpeed = std::mem::transmute(exported.speedhack_set_speed);
        set_speed(speed);
        send_response(format!("Speedhack set to {}", speed));
    }
}

unsafe fn handle_address_to_name(address: usize) {
    if let Some(exported) = unsafe { &*ptr::addr_of!(EXPORTED) }.as_ref() {
        if exported.sym_address_to_name.is_null() { return; }
        let addr_to_name: CepSymAddressToName = std::mem::transmute(exported.sym_address_to_name);
        let mut buffer = [0u8; 256];
        if addr_to_name(address, buffer.as_mut_ptr() as *mut i8, 255) == TRUE {
            let len = buffer.iter().position(|&c| c == 0).unwrap_or(buffer.len());
            let name = String::from_utf8_lossy(&buffer[0..len]);
            send_response(format!("AddressToName result: {}", name));
        } else {
            send_response("AddressToName failed".to_string());
        }
    }
}

unsafe fn handle_name_to_address(name: &str) {
    if let Some(exported) = unsafe { &*ptr::addr_of!(EXPORTED) }.as_ref() {
        if exported.sym_name_to_address.is_null() { return; }
        let name_to_addr: CepSymNameToAddress = std::mem::transmute(exported.sym_name_to_address);
        let c_name = CString::new(name).unwrap_or_default();
        let mut address: usize = 0;
        if name_to_addr(c_name.as_ptr(), &mut address) == TRUE {
            send_response(format!("NameToAddress result: 0x{:X}", address));
        } else {
            send_response("NameToAddress failed".to_string());
        }
    }
}

unsafe fn handle_get_address_from_pointer(base: usize, offsets: Vec<i32>) {
    if let Some(exported) = unsafe { &*ptr::addr_of!(EXPORTED) }.as_ref() {
        if exported.get_address_from_pointer.is_null() { return; }
        let get_addr: CepGetAddressFromPointer = std::mem::transmute(exported.get_address_from_pointer);
        // 将偏移量转为 c_int 数组
        let c_offsets: Vec<c_int> = offsets.iter().map(|&x| x as c_int).collect();
        let result = get_addr(base, c_offsets.len() as c_int, c_offsets.as_ptr());
        send_response(format!("GetAddressFromPointer result: 0x{:X}", result));
    }
}

unsafe fn handle_previous_opcode(address: usize) {
    if let Some(exported) = unsafe { &*ptr::addr_of!(EXPORTED) }.as_ref() {
        if exported.previous_opcode.is_null() { return; }
        let prev_op: CepPreviousOpcode = std::mem::transmute(exported.previous_opcode);
        let result = prev_op(address);
        send_response(format!("PreviousOpcode result: 0x{:X}", result));
    }
}

unsafe fn handle_next_opcode(address: usize) {
    if let Some(exported) = unsafe { &*ptr::addr_of!(EXPORTED) }.as_ref() {
        if exported.next_opcode.is_null() { return; }
        let next_op: CepNextOpcode = std::mem::transmute(exported.next_opcode);
        let result = next_op(address);
        send_response(format!("NextOpcode result: 0x{:X}", result));
    }
}

unsafe fn handle_set_breakpoint(address: usize, size: i32, trigger: i32) {
    if let Some(exported) = unsafe { &*ptr::addr_of!(EXPORTED) }.as_ref() {
        if exported.debug_set_breakpoint.is_null() { return; }
        let set_bp: CepDebugSetBreakpoint = std::mem::transmute(exported.debug_set_breakpoint);
        if set_bp(address, size, trigger) == TRUE {
             send_response(format!("SetBreakpoint success at 0x{:X}", address));
        } else {
             send_response("SetBreakpoint failed".to_string());
        }
    }
}

unsafe fn handle_remove_breakpoint(address: usize) {
    if let Some(exported) = unsafe { &*ptr::addr_of!(EXPORTED) }.as_ref() {
        if exported.debug_remove_breakpoint.is_null() { return; }
        let remove_bp: CepDebugRemoveBreakpoint = std::mem::transmute(exported.debug_remove_breakpoint);
        if remove_bp(address) == TRUE {
             send_response(format!("RemoveBreakpoint success at 0x{:X}", address));
        } else {
             send_response("RemoveBreakpoint failed".to_string());
        }
    }
}

unsafe fn handle_continue_from_breakpoint(option: i32) {
    if let Some(exported) = unsafe { &*ptr::addr_of!(EXPORTED) }.as_ref() {
        if exported.debug_continue_from_breakpoint.is_null() { return; }
        let cont_bp: CepDebugContinueFromBreakpoint = std::mem::transmute(exported.debug_continue_from_breakpoint);
        if cont_bp(option) == TRUE {
             send_response("ContinueFromBreakpoint success".to_string());
        } else {
             send_response("ContinueFromBreakpoint failed".to_string());
        }
    }
}

// ── 响应发送 ──
/// 向 CE GUI 和 TCP Bridge 发送响应消息
unsafe fn send_response(msg: String) {
    // 发送到 CE 弹窗
    if let Some(exported) = unsafe { &*ptr::addr_of!(EXPORTED) }.as_ref() {
        if let Some(show_message) = exported.show_message {
            let c_msg = CString::new(msg.clone()).unwrap_or_default();
            show_message(c_msg.as_ptr());
        }
    }
    
    // 发送到 TCP Bridge
    if let Ok(server_lock) = SERVER.lock() {
        if let Some(server) = server_lock.as_ref() {
            server.send(&msg);
        }
    }
}

// ── CE SDK 入口：DLL 主入口 ──
/// DLL 入口点
#[no_mangle]
#[allow(non_snake_case)]
pub extern "system" fn DllMain(
    _h_module: HINSTANCE,
    ul_reason_for_call: DWORD,
    _lp_reserved: LPVOID,
) -> BOOL {
    match ul_reason_for_call {
        DLL_PROCESS_DETACH => {
            // 清理（如需）
        }
        _ => {}
    }
    TRUE
}

// ── CE SDK 导出：版本信息 ──
/// 返回插件版本与名称
#[no_mangle]
#[allow(non_snake_case)]
pub unsafe extern "system" fn CEPlugin_GetVersion(
    pv: *mut PluginVersion,
    _sizeofpluginversion: i32,
) -> BOOL {
    if pv.is_null() {
        return 0; // FALSE
    }
    
    (*pv).version = CESDK_VERSION;
    // 需要静态字符串，不能被释放
    let name = CString::new(obfstr::obfstr!("CE-MCP-Plugin (Rust Version) v0.1.0")).unwrap();
    // 泄漏内存保活（CE 不会释放它）
    (*pv).pluginname = name.into_raw();
    
    TRUE
}

// ── Lua：AI 命令桥接 ──
/// Lua 回调：从 CE Lua 脚本发送命令到 AI Bridge
unsafe extern "C" fn lua_ai_send_command(l: *mut lua_State) -> c_int {
    // 动态加载 Lua 函数
    let lua_module_name = CString::new(obfstr::obfstr!("lua53-64.dll")).unwrap();
    let mut h_module = unsafe { GetModuleHandleA(lua_module_name.as_ptr()) };
    if h_module.is_null() {
         let lua_module_name_32 = CString::new(obfstr::obfstr!("lua53-32.dll")).unwrap();
         h_module = unsafe { GetModuleHandleA(lua_module_name_32.as_ptr()) };
    }
    if h_module.is_null() {
         let lua_module_name_generic = CString::new(obfstr::obfstr!("lua53.dll")).unwrap();
         h_module = unsafe { GetModuleHandleA(lua_module_name_generic.as_ptr()) };
    }

    if h_module.is_null() {
        return 0; // 需要 Lua 函数，没有就无法工作
    }

    let name_gettop = CString::new(obfstr::obfstr!("lua_gettop")).unwrap();
    let name_pushstring = CString::new(obfstr::obfstr!("lua_pushstring")).unwrap();
    let name_tolstring = CString::new(obfstr::obfstr!("lua_tolstring")).unwrap();

    let func_gettop = unsafe { GetProcAddress(h_module, name_gettop.as_ptr()) };
    let func_pushstring = unsafe { GetProcAddress(h_module, name_pushstring.as_ptr()) };
    let func_tolstring = unsafe { GetProcAddress(h_module, name_tolstring.as_ptr()) };

    if func_gettop.is_null() || func_pushstring.is_null() || func_tolstring.is_null() {
        return 0;
    }

    let lua_gettop: LuaGetTop = std::mem::transmute(func_gettop);
    let lua_pushstring: LuaPushString = std::mem::transmute(func_pushstring);
    let lua_tolstring: LuaTolString = std::mem::transmute(func_tolstring);

    if lua_gettop(l) < 1 {
        let msg = CString::new(obfstr::obfstr!("Error: Missing command parameter")).unwrap();
        lua_pushstring(l, msg.as_ptr());
        return 1;
    }

    let cmd_ptr = crate::ce_sys::lua_tostring(l, 1, lua_tolstring);
    if cmd_ptr.is_null() {
        let msg = CString::new(obfstr::obfstr!("Error: Invalid command")).unwrap();
        lua_pushstring(l, msg.as_ptr());
        return 1;
    }

    let c_str = std::ffi::CStr::from_ptr(cmd_ptr);
    let cmd_str = c_str.to_string_lossy().into_owned();

    let mut success = false;
    if let Ok(server_lock) = SERVER.lock() {
        if let Some(server) = server_lock.as_ref() {
            success = server.send(&cmd_str);
        }
    }

    if success {
        let msg = CString::new(obfstr::obfstr!("Command sent successfully")).unwrap();
        lua_pushstring(l, msg.as_ptr());
    } else {
        let msg = CString::new(obfstr::obfstr!("Error: Failed to send command")).unwrap();
        lua_pushstring(l, msg.as_ptr());
    }
    
    1
}

// ── CE SDK 导出：插件初始化 ──
/// 插件入口：被 CE 加载时调用
#[no_mangle]
#[allow(non_snake_case)]
pub unsafe extern "system" fn CEPlugin_InitializePlugin(
    ef: *mut ExportedFunctions,
    pluginid: i32,
) -> BOOL {
    if ef.is_null() {
        return 0;
    }

    // 保存全局状态
    unsafe {
        EXPORTED = Some(ptr::read(ef));
        PLUGIN_ID = pluginid;
    }

    // 可选：初始化日志
    // simplelog::WriteLogger::init(...)

    // 启动 Server 后台线程
    let sender = CHANNEL.0.clone();
    let mut server = Server::new(sender);
    server.start();
    *SERVER.lock().unwrap() = Some(server);

    // 注册 Lua 函数
    if let Some(exported) = unsafe { &*ptr::addr_of!(EXPORTED) }.as_ref() {
        if let Some(get_lua_state) = exported.get_lua_state {
            let lua_state = get_lua_state();
            if !lua_state.is_null() {
                // 动态加载 Lua 函数
                let lua_module_name = CString::new(obfstr::obfstr!("lua53-64.dll")).unwrap(); // 优先尝试 64 位
                let mut h_module = unsafe { GetModuleHandleA(lua_module_name.as_ptr()) };
                
                if h_module.is_null() {
                     let lua_module_name_32 = CString::new(obfstr::obfstr!("lua53-32.dll")).unwrap(); // 尝试 32 位
                     h_module = unsafe { GetModuleHandleA(lua_module_name_32.as_ptr()) };
                }
                
                if h_module.is_null() {
                     let lua_module_name_generic = CString::new(obfstr::obfstr!("lua53.dll")).unwrap(); // 尝试通用名
                     h_module = unsafe { GetModuleHandleA(lua_module_name_generic.as_ptr()) };
                }

                if !h_module.is_null() {
                    let name_register = CString::new(obfstr::obfstr!("lua_register")).unwrap();
                    let func_register = unsafe { GetProcAddress(h_module, name_register.as_ptr()) };
                    
                    if !func_register.is_null() {
                        let lua_register: LuaRegister = unsafe { std::mem::transmute(func_register) };
                        let name = CString::new(obfstr::obfstr!("aiSendCommand")).unwrap();
                        lua_register(lua_state, name.as_ptr(), lua_ai_send_command);
                    }
                }
            }
        }
    }

    // 弹窗确认插件已加载
    if let Some(exported) = unsafe { &*ptr::addr_of!(EXPORTED) }.as_ref() {
        if let Some(show_message) = exported.show_message {
            let msg = CString::new(obfstr::obfstr!("Rust Plugin Initialized! Server starting...")).unwrap();
            show_message(msg.as_ptr());
        }

        // 注册主菜单项
        // 重要：传给 CE 的 C 字符串必须泄漏内存，否则被释放后 CE 会崩溃
        let name = CString::new(obfstr::obfstr!("Rust Plugin Menu")).unwrap();
        let shortcut = CString::new(obfstr::obfstr!("Ctrl+R")).unwrap();    
        let mut init = MainMenuPluginInit {
            name: name.into_raw() as *const i8, // 泄漏内存
            callbackroutine: main_menu_callback,
            shortcut: shortcut.into_raw() as *const i8, // 泄漏内存
        };

        if let Some(register_function) = exported.register_function {
            // 转为 *mut c_void 传给 CE SDK
            register_function(pluginid, PluginType::PtMainMenu, &mut init as *mut _ as *mut c_void);
        }
        
        // 设置定时器轮询命令
        setup_timer(exported);
    }

    TRUE
}

// ── 定时器：命令轮询 ──
/// 创建 CE 定时器用于轮询命令
unsafe fn setup_timer(exported: &ExportedFunctions) {
    if exported.create_timer.is_null() || exported.timer_set_interval.is_null() || exported.timer_on_timer.is_null() {
        return;
    }

    let create_timer: CepCreateTimer = std::mem::transmute(exported.create_timer);
    let set_interval: CepTimerSetInterval = std::mem::transmute(exported.timer_set_interval);
    let on_timer: CepTimerOnTimer = std::mem::transmute(exported.timer_on_timer);

    // 创建无主定时器（owner = NULL）
    let timer = create_timer(ptr::null_mut());
    if !timer.is_null() {
        set_interval(timer, 100); // 100ms 间隔
        on_timer(timer, timer_callback as PVOID);
    }
}

// ── 定时器回调：命令处理器 ──
/// 定时器回调：在 CE 主线程中处理待执行的命令
unsafe extern "system" fn timer_callback(_timer: PVOID) {
    let receiver = &CHANNEL.1;
    // 处理所有待执行命令
    while let Ok(cmd) = receiver.try_recv() {
        match cmd {
            Command::ShowMessage(msg) => {
                if let Some(exported) = unsafe { &*ptr::addr_of!(EXPORTED) }.as_ref() {
                    if let Some(show_message) = exported.show_message {
                        let c_msg = CString::new(msg).unwrap_or_default();
                        show_message(c_msg.as_ptr());
                    }
                }
            }
            Command::ReadMemory { address, type_ } => {
                handle_read_memory(address, &type_);
            }
            Command::WriteMemory { address, value, type_ } => {
                handle_write_memory(address, &value, &type_);
            }
            Command::Assemble { address, instruction } => {
                handle_assemble(address, &instruction);
            }
            Command::Disassemble { address } => {
                handle_disassemble(address);
            }
            Command::AutoAssemble { script } => {
                handle_auto_assemble(&script);
            }
            // UI 控件
            Command::CreateForm => handle_create_form(),
            Command::CreatePanel { owner } => handle_create_control(owner, 0),
            Command::CreateButton { owner } => handle_create_control(owner, 1),
            Command::CreateLabel { owner } => handle_create_control(owner, 2),
            Command::CreateEdit { owner } => handle_create_control(owner, 3),
            Command::CreateImage { owner } => handle_create_control(owner, 4),
            Command::CreateMemo { owner } => handle_create_control(owner, 5),
            Command::CreateGroupBox { owner } => handle_create_control(owner, 6),
            Command::CreateTimer { owner } => handle_create_control(owner, 7),
            Command::SetCaption { control, caption } => handle_set_caption(control, &caption),
            Command::GetCaption { control } => handle_get_caption(control),
            Command::SetPosition { control, x, y } => handle_set_position(control, x, y),
            Command::GetPosition { control } => handle_get_position(control),
            Command::SetSize { control, width, height } => handle_set_size(control, width, height),
            Command::GetSize { control } => handle_get_size(control),
            Command::DestroyObject { object } => handle_destroy_object(object),
            Command::FormCenterScreen { form } => handle_form_action(form, 0),
            Command::FormHide { form } => handle_form_action(form, 1),
            Command::FormShow { form } => handle_form_action(form, 2),
            Command::ImageLoadFromFile { image, filename } => handle_image_load(image, &filename),
            Command::ImageTransparent { image, transparent } => handle_image_bool(image, transparent, 0),
            Command::ImageStretch { image, stretch } => handle_image_bool(image, stretch, 1),
            Command::TimerSetInterval { timer, interval } => handle_timer_set_interval(timer, interval),
            // 地址列表
            Command::CreateTableEntry { description, address, type_ } => handle_create_table_entry(&description, &address, &type_),
            Command::GetTableEntry { index } => handle_get_table_entry(index),
            Command::SetEntryDescription { index, description } => handle_set_entry_description(index, &description),
            Command::GetEntryDescription { index } => handle_get_entry_description(index),
            Command::SetEntryAddress { index, address } => handle_set_entry_address(index, &address),
            Command::GetEntryAddress { index } => handle_get_entry_address(index),
            Command::SetEntryType { index, type_ } => handle_set_entry_type(index, &type_),
            Command::GetEntryType { index } => handle_get_entry_type(index),
            Command::SetEntryValue { index, value } => handle_set_entry_value(index, &value),
            Command::GetEntryValue { index } => handle_get_entry_value(index),
            Command::SetEntryScript { index, script } => handle_set_entry_script(index, &script),
            Command::GetEntryScript { index } => handle_get_entry_script(index),
            Command::FreezeEntry { index } => handle_freeze_entry(index),
            Command::UnfreezeEntry { index } => handle_unfreeze_entry(index),
            Command::DeleteEntry { index } => handle_delete_entry(index),
            // 进程管理
            Command::ProcessList => {}, // 暂未实现
            Command::OpenProcess { process_id } => handle_open_process(process_id),
            Command::GetProcessId { process_name } => handle_get_process_id(&process_name),
            Command::PauseProcess => handle_pause_process(),
            Command::UnpauseProcess => handle_unpause_process(),
            Command::DebugProcess { process_id } => handle_debug_process(process_id),
            // 高级功能
            Command::ChangeRegister { address, reg, value } => handle_change_register(address, &reg, &value),
            Command::InjectDll { path, function } => handle_inject_dll(&path, &function),
            Command::Speedhack { speed } => handle_speedhack(speed),
            Command::AddressToName { address } => handle_address_to_name(address),
            Command::NameToAddress { name } => handle_name_to_address(&name),
            Command::GetAddressFromPointer { base, offsets } => handle_get_address_from_pointer(base, offsets),
            Command::PreviousOpcode { address } => handle_previous_opcode(address),
            Command::NextOpcode { address } => handle_next_opcode(address),
            Command::SetBreakpoint { address, size, trigger } => handle_set_breakpoint(address, size, trigger),
            Command::RemoveBreakpoint { address } => handle_remove_breakpoint(address),
            Command::ContinueFromBreakpoint { option } => handle_continue_from_breakpoint(option),
            Command::Unknown(_raw) => {
                // 记录未识别命令
            }
        }
    }
}

// ── 内存读写：读取 ──
/// 从指定地址读取并解析内存值
unsafe fn handle_read_memory(address: usize, type_: &str) {
    if let Some(exported) = unsafe { &*ptr::addr_of!(EXPORTED) }.as_ref() {
        if exported.read_process_memory.is_null() {
            return;
        }
        // 安全：前面已判空，此处安全
        // 注意指针类型的正确转换
        // 在 Rust 中将裸指针转为函数指针是 unsafe 操作
        let read_process_memory: CepReadProcessMemory = std::mem::transmute(exported.read_process_memory);

        let h_process = *exported.opened_process_handle;

        let mut buffer = [0u8; 256]; // 最大缓冲区大小
        let mut bytes_read: SIZE_T = 0;
        let size = match type_ {
            "byte" | "BYTE" => 1,
            "word" | "WORD" => 2,
            "dword" | "DWORD" => 4,
            "float" | "FLOAT" => 4,
            "double" | "DOUBLE" => 8,
            "int64" | "INT64" => 8,
            _ => 0,
        };

        if size > 0 {
            let success = read_process_memory(
                h_process,
                address as *const c_void,
                buffer.as_mut_ptr() as *mut c_void,
                size,
                &mut bytes_read,
            );

            if success == TRUE && bytes_read == size {
                let msg = match type_ {
                    "byte" | "BYTE" => format!("ReadMemory: 0x{:X} = {}", address, buffer[0]),
                    "word" | "WORD" => format!("ReadMemory: 0x{:X} = {}", address, u16::from_le_bytes(buffer[0..2].try_into().unwrap())),
                    "dword" | "DWORD" => format!("ReadMemory: 0x{:X} = {}", address, u32::from_le_bytes(buffer[0..4].try_into().unwrap())),
                    "float" | "FLOAT" => format!("ReadMemory: 0x{:X} = {:.4}", address, f32::from_le_bytes(buffer[0..4].try_into().unwrap())),
                    "double" | "DOUBLE" => format!("ReadMemory: 0x{:X} = {:.4}", address, f64::from_le_bytes(buffer[0..8].try_into().unwrap())),
                    "int64" | "INT64" => format!("ReadMemory: 0x{:X} = {}", address, i64::from_le_bytes(buffer[0..8].try_into().unwrap())),
                    _ => String::new(),
                };
                
                send_response(msg);
            } else {
                 send_response(format!("ReadMemory failed at 0x{:X}", address));
            }
        }
    }
}

// ── 内存读写：写入 ──
unsafe fn handle_write_memory(address: usize, value: &str, type_: &str) {
    if let Some(exported) = unsafe { &*ptr::addr_of!(EXPORTED) }.as_ref() {
        if exported.write_process_memory.is_null() {
            return;
        }
        let write_process_memory: CepWriteProcessMemory = std::mem::transmute(exported.write_process_memory);
        let h_process = *exported.opened_process_handle;

        let mut buffer = [0u8; 8];
        let size = match type_ {
            "byte" | "BYTE" => {
                if let Ok(val) = value.parse::<u8>() {
                    buffer[0] = val;
                    1
                } else { 0 }
            },
            "word" | "WORD" => {
                if let Ok(val) = value.parse::<u16>() {
                    buffer[0..2].copy_from_slice(&val.to_le_bytes());
                    2
                } else { 0 }
            },
            "dword" | "DWORD" => {
                if let Ok(val) = value.parse::<u32>() {
                    buffer[0..4].copy_from_slice(&val.to_le_bytes());
                    4
                } else { 0 }
            },
             "float" | "FLOAT" => {
                if let Ok(val) = value.parse::<f32>() {
                    buffer[0..4].copy_from_slice(&val.to_le_bytes());
                    4
                } else { 0 }
            },
            "double" | "DOUBLE" => {
                if let Ok(val) = value.parse::<f64>() {
                    buffer[0..8].copy_from_slice(&val.to_le_bytes());
                    8
                } else { 0 }
            },
             "int64" | "INT64" => {
                if let Ok(val) = value.parse::<i64>() {
                    buffer[0..8].copy_from_slice(&val.to_le_bytes());
                    8
                } else { 0 }
            },
            _ => 0,
        };

        if size > 0 {
            let mut bytes_written: SIZE_T = 0;
            let success = write_process_memory(
                h_process,
                address as *mut c_void,
                buffer.as_ptr() as *const c_void,
                size,
                &mut bytes_written,
            );

            let msg = if success == TRUE && bytes_written == size {
                format!("WriteMemory success: 0x{:X} = {}", address, value)
            } else {
                format!("WriteMemory failed at 0x{:X}", address)
            };

            send_response(msg);
        }
    }
}

// ── CE SDK 导出：插件卸载 ──
/// 插件卸载时被 CE 调用
#[no_mangle]
#[allow(non_snake_case)]
pub unsafe extern "system" fn CEPlugin_DisablePlugin() -> BOOL {
    // 停止 Server 后台线程
    if let Ok(mut server_lock) = SERVER.lock() {
        if let Some(server) = server_lock.as_mut() {
            server.stop();
        }
    }
    TRUE
}

// 主菜单项回调函数
unsafe extern "system" fn main_menu_callback() {
    if let Some(exported) = unsafe { &*ptr::addr_of!(EXPORTED) }.as_ref() {
        if let Some(show_message) = exported.show_message {
            let msg = CString::new("Hello from Rust Main Menu!").unwrap();
            show_message(msg.as_ptr());
        }
    }
}
