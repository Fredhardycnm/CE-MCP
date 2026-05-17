//! CE SDK FFI 类型与函数签名定义
//!
//! 本模块定义了与 Cheat Engine SDK 交互所需的所有外部函数类型（FFI）。
//! 由于 CE SDK 以 C 接口导出，所有函数都使用 `extern "system"` (stdcall) 调用约定。
//! 这些类型定义用于从 `ExportedFunctions` 结构体中动态加载函数指针并调用。
//!
//! 包含: 内存读写、汇编/反汇编、UI 控件、地址列表管理、进程管理、调试断点等功能。

use winapi::ctypes::{c_char, c_int, c_void};
use winapi::shared::basetsd::{SIZE_T, UINT_PTR};
use winapi::shared::minwindef::{BOOL, BYTE, LPCVOID, LPVOID, PULONG, DWORD};

use winapi::um::winnt::{HANDLE, PVOID};

/// CE SDK 版本号
pub const CESDK_VERSION: u32 = 6;

// ── 内存读写 ──
#[allow(non_snake_case)]
pub type CepReadProcessMemory = unsafe extern "system" fn(
    hProcess: HANDLE,
    lpBaseAddress: LPCVOID,
    lpBuffer: LPVOID,
    nSize: SIZE_T,
    lpNumberOfBytesRead: *mut SIZE_T
) -> BOOL;

#[allow(non_snake_case)]
pub type CepWriteProcessMemory = unsafe extern "system" fn(
    hProcess: HANDLE,
    lpBaseAddress: LPVOID,
    lpBuffer: LPCVOID,
    nSize: SIZE_T,
    lpNumberOfBytesWritten: *mut SIZE_T
) -> BOOL;

// ── 汇编与反汇编 ──
#[allow(non_snake_case)]
pub type CepAutoAssemble = unsafe extern "system" fn(script: *const c_char) -> BOOL;

#[allow(non_snake_case)]
pub type CepAssembler = unsafe extern "system" fn(
    address: UINT_PTR,
    instruction: *const c_char,
    output: *mut BYTE,
    maxlength: c_int,
    returnedsize: *mut c_int
) -> BOOL;

#[allow(non_snake_case)]
pub type CepDisassembler = unsafe extern "system" fn(
    address: UINT_PTR,
    output: *mut c_char,
    maxsize: c_int
) -> BOOL;

// ── UI 控件创建 ──
#[allow(non_snake_case)]
pub type CepCreateForm = unsafe extern "system" fn() -> PVOID;
#[allow(non_snake_case)]
pub type CepCreatePanel = unsafe extern "system" fn(owner: PVOID) -> PVOID;
#[allow(non_snake_case)]
pub type CepCreateButton = unsafe extern "system" fn(owner: PVOID) -> PVOID;
#[allow(non_snake_case)]
pub type CepCreateLabel = unsafe extern "system" fn(owner: PVOID) -> PVOID;
#[allow(non_snake_case)]
pub type CepCreateEdit = unsafe extern "system" fn(owner: PVOID) -> PVOID;
#[allow(non_snake_case)]
pub type CepCreateImage = unsafe extern "system" fn(owner: PVOID) -> PVOID;
#[allow(non_snake_case)]
pub type CepCreateMemo = unsafe extern "system" fn(owner: PVOID) -> PVOID;
#[allow(non_snake_case)]
pub type CepCreateGroupBox = unsafe extern "system" fn(owner: PVOID) -> PVOID;
#[allow(non_snake_case)]
pub type CepCreateTimer = unsafe extern "system" fn(owner: PVOID) -> PVOID;

#[allow(non_snake_case)]
pub type CepControlSetCaption = unsafe extern "system" fn(control: PVOID, caption: *const c_char);
#[allow(non_snake_case)]
pub type CepControlGetCaption = unsafe extern "system" fn(control: PVOID, caption: *mut c_char, maxsize: c_int) -> BOOL;
#[allow(non_snake_case)]
pub type CepControlSetPosition = unsafe extern "system" fn(control: PVOID, x: c_int, y: c_int);
#[allow(non_snake_case)]
pub type CepControlGetX = unsafe extern "system" fn(control: PVOID) -> c_int;
#[allow(non_snake_case)]
pub type CepControlGetY = unsafe extern "system" fn(control: PVOID) -> c_int;
#[allow(non_snake_case)]
pub type CepControlSetSize = unsafe extern "system" fn(control: PVOID, width: c_int, height: c_int);
#[allow(non_snake_case)]
pub type CepControlGetWidth = unsafe extern "system" fn(control: PVOID) -> c_int;
#[allow(non_snake_case)]
pub type CepControlGetHeight = unsafe extern "system" fn(control: PVOID) -> c_int;
#[allow(non_snake_case)]
pub type CepObjectDestroy = unsafe extern "system" fn(object: PVOID);

#[allow(non_snake_case)]
pub type CepFormCenterScreen = unsafe extern "system" fn(form: PVOID);
#[allow(non_snake_case)]
pub type CepFormHide = unsafe extern "system" fn(form: PVOID);
#[allow(non_snake_case)]
pub type CepFormShow = unsafe extern "system" fn(form: PVOID);

#[allow(non_snake_case)]
pub type CepImageLoadImageFromFile = unsafe extern "system" fn(image: PVOID, filename: *const c_char) -> BOOL;
#[allow(non_snake_case)]
pub type CepImageTransparent = unsafe extern "system" fn(image: PVOID, transparent: BOOL);
#[allow(non_snake_case)]
pub type CepImageStretch = unsafe extern "system" fn(image: PVOID, stretch: BOOL);

#[allow(non_snake_case)]
pub type CepTimerSetInterval = unsafe extern "system" fn(timer: PVOID, interval: c_int);
#[allow(non_snake_case)]
pub type CepTimerOnTimer = unsafe extern "system" fn(timer: PVOID, function: PVOID);

// ── 地址列表（内存表）管理 ──
#[allow(non_snake_case)]
pub type CepCreateTableEntry = unsafe extern "system" fn() -> PVOID;
#[allow(non_snake_case)]
pub type CepGetTableEntry = unsafe extern "system" fn(index: c_int) -> PVOID;
#[allow(non_snake_case)]
pub type CepSetEntryDescription = unsafe extern "system" fn(entry: PVOID, description: *const c_char);
#[allow(non_snake_case)]
pub type CepGetEntryDescription = unsafe extern "system" fn(entry: PVOID, description: *mut c_char, maxsize: c_int) -> BOOL;
#[allow(non_snake_case)]
pub type CepSetEntryAddress = unsafe extern "system" fn(entry: PVOID, address: *const c_char);
#[allow(non_snake_case)]
pub type CepGetEntryAddress = unsafe extern "system" fn(entry: PVOID, address: *mut c_char, maxsize: c_int) -> BOOL;
#[allow(non_snake_case)]
pub type CepSetEntryType = unsafe extern "system" fn(entry: PVOID, type_: c_int); // Using int for type enum
#[allow(non_snake_case)]
pub type CepGetEntryType = unsafe extern "system" fn(entry: PVOID) -> c_int;
#[allow(non_snake_case)]
pub type CepSetEntryValue = unsafe extern "system" fn(entry: PVOID, value: *const c_char);
#[allow(non_snake_case)]
pub type CepGetEntryValue = unsafe extern "system" fn(entry: PVOID, value: *mut c_char, maxsize: c_int) -> BOOL;
#[allow(non_snake_case)]
pub type CepSetEntryScript = unsafe extern "system" fn(entry: PVOID, script: *const c_char);
#[allow(non_snake_case)]
pub type CepGetEntryScript = unsafe extern "system" fn(entry: PVOID, script: *mut c_char, maxsize: c_int) -> BOOL;
#[allow(non_snake_case)]
pub type CepFreezeEntry = unsafe extern "system" fn(entry: PVOID);
#[allow(non_snake_case)]
pub type CepUnfreezeEntry = unsafe extern "system" fn(entry: PVOID);
#[allow(non_snake_case)]
pub type CepDeleteEntry = unsafe extern "system" fn(entry: PVOID);

// ── 进程管理 ──
#[allow(non_snake_case)]
pub type CepOpenProcess = unsafe extern "system" fn(process_id: DWORD) -> BOOL;
#[allow(non_snake_case)]
pub type CepGetProcessIdFromProcessName = unsafe extern "system" fn(name: *const c_char) -> DWORD;
#[allow(non_snake_case)]
pub type CepPause = unsafe extern "system" fn();
#[allow(non_snake_case)]
pub type CepUnpause = unsafe extern "system" fn();
#[allow(non_snake_case)]
pub type CepDebugProcess = unsafe extern "system" fn(process_id: DWORD) -> BOOL;

// ── 高级功能：寄存器、注入、变速、断点 ──
#[allow(non_snake_case)]
pub type CepChangeRegistersAtAddress = unsafe extern "system" fn(address: UINT_PTR, changereg: *const c_char) -> BOOL;
#[allow(non_snake_case)]
pub type CepInjectDLL = unsafe extern "system" fn(dll_path: *const c_char, function_to_call: *const c_char) -> BOOL;
#[allow(non_snake_case)]
pub type CepSpeedhackSetSpeed = unsafe extern "system" fn(speed: f32);
#[allow(non_snake_case)]
pub type CepSymAddressToName = unsafe extern "system" fn(address: UINT_PTR, name: *mut c_char, maxsize: c_int) -> BOOL;
#[allow(non_snake_case)]
pub type CepSymNameToAddress = unsafe extern "system" fn(name: *const c_char, address: *mut UINT_PTR) -> BOOL;
#[allow(non_snake_case)]
pub type CepGetAddressFromPointer = unsafe extern "system" fn(base: UINT_PTR, offset_count: c_int, offsets: *const c_int) -> UINT_PTR;
#[allow(non_snake_case)]
pub type CepPreviousOpcode = unsafe extern "system" fn(address: UINT_PTR) -> UINT_PTR;
#[allow(non_snake_case)]
pub type CepNextOpcode = unsafe extern "system" fn(address: UINT_PTR) -> UINT_PTR;
#[allow(non_snake_case)]
pub type CepDebugSetBreakpoint = unsafe extern "system" fn(address: UINT_PTR, size: c_int, trigger: c_int) -> BOOL;
#[allow(non_snake_case)]
pub type CepDebugRemoveBreakpoint = unsafe extern "system" fn(address: UINT_PTR) -> BOOL;
#[allow(non_snake_case)]
pub type CepDebugContinueFromBreakpoint = unsafe extern "system" fn(continue_option: c_int) -> BOOL;

// ── Lua 引擎交互 ──
// 使用 extern "C" (cdecl) 调用约定，与 Lua 5.3 DLL 一致
#[repr(C)]
pub struct lua_State {
    _unused: [u8; 0],
}

#[allow(non_snake_case)]
pub type LuaCFunction = unsafe extern "C" fn(L: *mut lua_State) -> c_int;

#[allow(non_snake_case)]
pub type CepGetLuaState = unsafe extern "system" fn() -> *mut lua_State;

// Note: Lua functions use C calling convention (cdecl), not stdcall/system
// We can't link to lua53.lib because it's not present at compile time.
// Instead, we should define function pointers for Lua API and load them dynamically
// OR rely on CE to provide them (via GetProcAddress on lua53.dll if loaded, or via CE's exported function table if available)

// CE's lua53.dll should be loaded in the process.
// We will define function pointers for Lua functions we need.

#[allow(non_snake_case)]
pub type LuaGetTop = unsafe extern "C" fn(L: *mut lua_State) -> c_int;
#[allow(non_snake_case)]
pub type LuaPushString = unsafe extern "C" fn(L: *mut lua_State, s: *const c_char);
#[allow(non_snake_case)]
pub type LuaTolString = unsafe extern "C" fn(L: *mut lua_State, idx: c_int, len: *mut usize) -> *const c_char;
#[allow(non_snake_case)]
pub type LuaRegister = unsafe extern "C" fn(L: *mut lua_State, n: *const c_char, f: LuaCFunction);

// Helper for lua_tostring macro - now needs dynamic resolution or we pass the function pointer
#[allow(non_snake_case)]
pub unsafe fn lua_tostring(L: *mut lua_State, idx: c_int, tolstring: LuaTolString) -> *const c_char {
    tolstring(L, idx, std::ptr::null_mut())
}

/// 插件类型枚举，用于注册不同类型的 CE 插件回调
#[repr(C)]
pub enum PluginType {
    PtAddressList = 0,
    PtMemoryView = 1,
    PtOnDebugEvent = 2,
    PtProcesswatcherEvent = 3,
    PtFunctionPointerchange = 4,
    PtMainMenu = 5,
    PtDisassemblerContext = 6,
    PtDisassemblerRenderLine = 7,
    PtAutoAssembler = 8,
}

/// 插件版本信息结构体
#[repr(C)]
pub struct PluginVersion {
    /// CE SDK 版本号
    pub version: u32,
    /// 插件名称（C 字符串指针）
    pub pluginname: *mut c_char,
}

// ── 基础函数指针类型 ──

/// 显示消息框
pub type CepShowMessage = unsafe extern "system" fn(message: *const c_char);
/// 注册 CE 插件回调函数
pub type CepRegisterFunction = unsafe extern "system" fn(pluginid: c_int, functiontype: PluginType, init: *mut c_void) -> c_int;
/// 注销 CE 插件回调
pub type CepUnregisterFunction = unsafe extern "system" fn(pluginid: c_int, functionid: c_int) -> BOOL;
/// 获取 CE 主窗口句柄
pub type CepGetMainWindowHandle = unsafe extern "system" fn() -> HANDLE;

/// 主菜单插件初始化结构体
#[repr(C)]
pub struct MainMenuPluginInit {
    /// 菜单项名称
    pub name: *const c_char,
    /// 点击回调函数
    pub callbackroutine: unsafe extern "system" fn(),
    /// 快捷键描述
    pub shortcut: *const c_char,
}

/// CE SDK 导出函数表
///
/// 这是 CE 插件的核心数据结构。当插件被 CE 加载时，
/// 会通过 `CEPlugin_InitializePlugin` 获得该结构体的指针，
/// 其中包含了 CE 提供的所有 API 函数地址。
///
/// 所有字段均为动态加载的函数指针，采用 `PVOID` 类型存储，
/// 使用时需转换为对应的函数类型后调用。
#[repr(C)]
pub struct ExportedFunctions {
    /// 结构体大小（用于版本兼容检测）
    pub sizeof_exported_functions: c_int,
    /// 显示消息框
    pub show_message: Option<CepShowMessage>,
    /// 注册插件回调
    pub register_function: Option<CepRegisterFunction>,
    /// 注销插件回调
    pub unregister_function: Option<CepUnregisterFunction>,
    /// 已打开进程的 PID 指针
    pub opened_process_id: PULONG,
    /// 已打开进程的句柄指针
    pub opened_process_handle: *mut HANDLE,
    
    /// 获取 CE 主窗口句柄
    pub get_main_window_handle: Option<CepGetMainWindowHandle>,
    pub auto_assemble: PVOID, // TODO: Define specific function type
    pub assembler: PVOID,
    pub disassembler: PVOID,
    pub change_registers_at_address: PVOID,
    pub inject_dll: PVOID,
    pub freeze_mem: PVOID,
    pub unfreeze_mem: PVOID,
    pub fix_mem: PVOID,
    pub process_list: PVOID,
    pub reload_settings: PVOID,
    pub get_address_from_pointer: PVOID,
    
    // ── Windows API Hooks（函数指针的指针） ──
    // 这些字段存储的是指向函数指针的指针，CE 内部用于拦截系统调用。
    // 例如 read_process_memory 实际的类型是 `*mut CepReadProcessMemory`。
    pub read_process_memory: PVOID,
    pub write_process_memory: PVOID,
    pub get_thread_context: PVOID,
    pub set_thread_context: PVOID,
    pub suspend_thread: PVOID,
    pub resume_thread: PVOID,
    pub open_process: PVOID,
    pub wait_for_debug_event: PVOID,
    pub continue_debug_event: PVOID,
    pub debug_active_process: PVOID,
    pub stop_debugging: PVOID,
    pub stop_register_change: PVOID,
    pub virtual_protect: PVOID,
    pub virtual_protect_ex: PVOID,
    pub virtual_query_ex: PVOID,
    pub virtual_alloc_ex: PVOID,
    pub create_remote_thread: PVOID,
    pub open_thread: PVOID,
    pub get_pe_process: PVOID,
    pub get_pe_thread: PVOID,
    pub get_threads_process_offset: PVOID,
    pub get_thread_list_entry_offset: PVOID,
    pub get_processname_offset: PVOID,
    pub get_debugport_offset: PVOID,
    pub get_physical_address: PVOID,
    pub protect_me: PVOID,
    pub get_cr4: PVOID,
    pub get_cr3: PVOID,
    pub set_cr3: PVOID,
    pub get_sdt: PVOID,
    pub get_sdt_shadow: PVOID,
    pub set_alternate_debug_method: PVOID,
    pub get_alternate_debug_method: PVOID,
    pub debug_process: PVOID,
    pub change_reg_on_bp: PVOID,
    pub retrieve_debug_data: PVOID,
    pub start_process_watch: PVOID,
    pub wait_for_process_list_data: PVOID,
    pub get_process_name_from_id: PVOID,
    pub get_process_name_from_pe_process: PVOID,
    pub kernel_open_process: PVOID,
    pub kernel_read_process_memory: PVOID,
    pub kernel_write_process_memory: PVOID,
    pub kernel_virtual_alloc_ex: PVOID,
    pub is_valid_handle: PVOID,
    pub get_idt_current_thread: PVOID,
    pub get_idts: PVOID,
    pub make_writable: PVOID,
    pub get_loaded_state: PVOID,
    pub dbk_suspend_thread: PVOID,
    pub dbk_resume_thread: PVOID,
    pub dbk_suspend_process: PVOID,
    pub dbk_resume_process: PVOID,
    pub kernel_alloc: PVOID,
    pub get_k_proc_address: PVOID,
    pub create_toolhelp32_snapshot: PVOID,
    pub process32_first: PVOID,
    pub process32_next: PVOID,
    pub thread32_first: PVOID,
    pub thread32_next: PVOID,
    pub module32_first: PVOID,
    pub module32_next: PVOID,
    pub heap32_list_first: PVOID,
    pub heap32_list_next: PVOID,
    
    // ── 高级：CE 主窗体 ──
    pub mainform: PVOID,
    pub memorybrowser: PVOID,
    
    // ── SDK v2+：符号与 API Hook ──
    pub sym_name_to_address: PVOID,
    pub sym_address_to_name: PVOID,
    pub sym_generate_api_hook_script: PVOID,
    
    // ── SDK v3+：DBVM 与反汇编 ──
    pub load_dbk32: PVOID,
    pub load_dbvm_if_needed: PVOID,
    pub previous_opcode: PVOID,
    pub next_opcode: PVOID,
    pub disassemble_ex: PVOID,
    pub load_module: PVOID,
    pub aa_add_extra_command: PVOID,
    pub aa_remove_extra_command: PVOID,
    
    // ── SDK v4：地址列表（内存表） ──
    pub create_table_entry: PVOID,
    pub get_table_entry: PVOID,
    pub memrec_set_description: PVOID,
    pub memrec_get_description: PVOID,
    pub memrec_get_address: PVOID,
    pub memrec_set_address: PVOID,
    pub memrec_get_type: PVOID,
    pub memrec_set_type: PVOID,
    pub memrec_get_value: PVOID,
    pub memrec_set_value: PVOID,
    pub memrec_get_script: PVOID,
    pub memrec_set_script: PVOID,
    pub memrec_is_frozen: PVOID,
    pub memrec_freeze: PVOID,
    pub memrec_unfreeze: PVOID,
    pub memrec_set_color: PVOID,
    pub memrec_append_to_entry: PVOID,
    pub memrec_delete: PVOID,
    
    // ── SDK v5：进程/UI/调试增强 ──
    pub get_process_id_from_process_name: PVOID,
    pub open_process_ex: PVOID,
    pub debug_process_ex: PVOID,
    pub pause: PVOID,
    pub unpause: PVOID,
    pub debug_set_breakpoint: PVOID,
    pub debug_remove_breakpoint: PVOID,
    pub debug_continue_from_breakpoint: PVOID,
    pub close_ce: PVOID,
    pub hide_all_ce_windows: PVOID,
    pub unhide_main_ce_window: PVOID,
    pub create_form: PVOID,
    pub form_center_screen: PVOID,
    pub form_hide: PVOID,
    pub form_show: PVOID,
    pub form_on_close: PVOID,
    pub create_panel: PVOID,
    pub create_group_box: PVOID,
    pub create_button: PVOID,
    pub create_image: PVOID,
    pub image_load_image_from_file: PVOID,
    pub image_transparent: PVOID,
    pub image_stretch: PVOID,
    pub create_label: PVOID,
    pub create_edit: PVOID,
    pub create_memo: PVOID,
    pub create_timer: PVOID,
    pub timer_set_interval: PVOID,
    pub timer_on_timer: PVOID,
    pub control_set_caption: PVOID,
    pub control_get_caption: PVOID,
    pub control_set_position: PVOID,
    pub control_get_x: PVOID,
    pub control_get_y: PVOID,
    pub control_set_size: PVOID,
    pub control_get_width: PVOID,
    pub control_get_height: PVOID,
    pub control_set_align: PVOID,
    pub control_on_click: PVOID,
    pub object_destroy: PVOID,
    pub message_dialog: PVOID,
    pub speedhack_set_speed: PVOID,
    pub get_lua_state: Option<CepGetLuaState>,
    // ── SDK v5 地址列表补充函数 ──
    pub set_entry_description: PVOID,
    pub get_entry_description: PVOID,
    pub set_entry_address: PVOID,
    pub get_entry_address: PVOID,
    pub set_entry_type: PVOID,
    pub get_entry_type: PVOID,
    pub set_entry_value: PVOID,
    pub get_entry_value: PVOID,
    pub set_entry_script: PVOID,
    pub get_entry_script: PVOID,
    pub freeze_entry: PVOID,
    pub unfreeze_entry: PVOID,
    pub delete_entry: PVOID,
    // Process Management - open_process, get_process_id_from_process_name, pause, unpause, debug_process are already declared above
}
