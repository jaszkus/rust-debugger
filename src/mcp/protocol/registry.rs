use crate::mcp::tools::schemas::*;
use serde_json::{json, Value};

pub type ToolSpec = (&'static str, &'static str, fn() -> Value);

pub const ALL_TOOLS: &[ToolSpec] = &[
    ("search_tools", "Find tools by keywords/category (e.g. 'entropy', 'xor decrypt', category=patching). Empty query lists categories. Returns names, params, required args, async eligibility; include_schema=true attaches full inputSchema.", schema_search_tools),
    ("get_metadata", "Get binary metadata: format, arch, entry point, file path", schema_empty),
    ("get_function_count", "Return total number of detected functions", schema_empty),
    ("get_entry_points", "List binary entry point addresses", schema_empty),
    ("run_analysis", "Run auto-analysis and WAIT for the fresh result (blocking; timeout_ms default 600000, 5000..3600000). Use reanalyze for the old fire-and-forget queue.", schema_timeout),
    ("get_analysis_status", "Get current analysis progress / status", schema_empty),
    ("int_convert", "Convert integer between formats (dec/hex/bin/bytes/ascii)", schema_int_convert),

    ("list_functions", "List functions paginated with optional filter (name or hex address, '0x' optional). limit 1..1000: above is clamped (see 'warnings'), below is rejected", schema_list_functions),
    ("lookup_function", "Lookup a function by address (hex) or name", schema_lookup),
    ("decompile_function", "Get pseudocode for a function at the given address", schema_decompile),
    ("disassemble_function", "Get full disassembly listing for a function", schema_addr),
    ("get_function_callers", "Get functions that call the given address", schema_addr),
    ("get_function_callees", "Get functions called by the given address", schema_addr),
    ("get_function_pcode", "Get PCode IR for a function", schema_addr),
    ("get_stack_frame", "Get stack frame variables (locals/params) for a function", schema_addr),

    ("get_xrefs_to", "Get cross-references targeting an address", schema_addr),
    ("get_xrefs_from", "Get cross-references originating from an address", schema_addr),

    ("get_bytes", "Read raw bytes from a virtual address (hex string output). size 1..4096 per call; larger requests are clamped and flagged with truncated/warnings/next_address", schema_get_bytes),
    ("get_string", "Read a null-terminated string from a virtual address", schema_addr),
    ("get_int", "Read an integer (u8/u16/u32/u64/i*) at a virtual address", schema_get_int),

    ("list_strings", "List extracted strings (paginated, filter, encoding). limit 1..5000 and a response-size budget per page: follow next_offset while has_more is true", schema_list_strings),
    ("list_imports", "List imported symbols (paginated)", schema_list_paginated),
    ("list_exports", "List exported symbols (paginated)", schema_list_paginated),
    ("list_symbols", "List all symbols (paginated)", schema_list_paginated),
    ("list_sections", "List binary sections", schema_empty),
    ("list_relocations", "List base/dynamic relocations (PE BaseReloc, ELF rela, PLT artificial)", schema_list_paginated),

    ("search_functions", "Search functions by name substring or hex address", schema_search),
    ("search_strings", "Search strings by substring", schema_search),
    ("search_bytes", "Search for a hex byte pattern ('??' = any byte) in binary data. Paged: has_more / next_offset tell whether the list is complete; pass offset to continue", schema_search_paged),

    ("set_comment", "Set / update a user comment at an address (kind: eol|pre|post|plate|repeatable)", schema_set_comment),
    ("delete_comment", "Delete the user comment at an address (optional kind)", schema_addr),
    ("list_comments", "List all user comments (all kinds)", schema_empty),
    ("set_bookmark", "Add a bookmark at an address (kind: note|info|error|analysis)", schema_set_bookmark),
    ("set_plan", "Publish the agent plan shown in the AI Live card (steps + in-progress index)", schema_set_plan),
    ("list_bookmarks", "List all bookmarks", schema_empty),
    ("delete_bookmark", "Delete bookmark at an address", schema_addr),
    ("rename_function", "Rename a detected function", schema_rename_function),
    ("undo_annotation", "Undo the last annotation edit (comment/bookmark/label/rename/tag)", schema_empty),
    ("redo_annotation", "Redo the last undone annotation edit", schema_empty),

    ("get_function_at", "Find function containing the given address", schema_addr),
    ("get_section_at", "Find section containing the given address", schema_addr),
    ("address_info", "All info about an address: section, function, basic block, instruction, string, symbol, xrefs, comment", schema_addr),
    ("get_basic_block_at", "Find the basic block containing the given address", schema_addr),
    ("list_basic_blocks", "List all basic blocks of a function with successors/predecessors", schema_addr),
    ("get_function_summary", "Comprehensive one-shot summary of a function: signature, callers/callees, used imports, used strings, preview", schema_addr),
    ("get_annotated_disasm", "Disassembly of a function with inline annotations: comments, call targets, string refs, xrefs", schema_addr),
    ("find_imports_called_by", "List Win32/POSIX imports called by a function (direct or via stub)", schema_addr),
    ("find_strings_referenced_by", "List strings referenced by a function", schema_addr),
    ("find_users_of_import", "List functions that use a given import (by name, e.g. 'CreateFileW' or 'KERNEL32.dll!CreateFileW')", schema_lookup_name),
    ("get_call_tree", "Get call tree (BFS through callees) from a function up to max_depth", schema_addr_depth),
    ("find_callers_chain", "Get layered list of callers up to max_depth", schema_addr_depth),
    ("find_recursive_functions", "List functions that call themselves", schema_empty),
    ("find_leaf_functions", "List functions that don't call any other function", schema_list_paginated),
    ("find_root_functions", "List functions that are never called by any other function", schema_list_paginated),
    ("get_function_hash", "Get dual FNV-1a hashes (full masked + value-sensitive specific) of a function body", schema_addr),
    ("find_similar_functions", "Find groups of functions with identical masked code shape", schema_similar),
    ("fid_ingest_library", "Ingest named functions of the current analysis as a FunctionID library (persists in session, merges into analysis)", schema_fid_ingest),
    ("fid_export_db", "Export the session FunctionID library to a .fidb JSON file", schema_path),
    ("fid_import_db", "Import a .fidb JSON library file into the session FunctionID DB", schema_path),
    ("fid_list", "List session FunctionID signatures (filter by name/library substring)", schema_fid_list),
    ("list_stubs", "List detected import thunks / stub functions", schema_list_paginated),
    ("list_switch_tables", "List detected switch/jump tables", schema_search),
    ("find_format_strings", "List strings containing C printf-style format specifiers (%s, %d, etc.)", schema_search),
    ("search_in_decompiled", "Search substring across all decompiled pseudocode", schema_search),
    ("search_instruction_pattern", "Find sequences of instructions matching a pattern of mnemonics (e.g. 'push;mov;call'). Paged: has_more / next_offset", schema_pattern),

    ("disassemble_range", "Disassemble N instructions starting at an address (or up to end_address). No analysis required.", schema_disasm_range),
    ("disassemble_bytes", "Disassemble a hex byte string at an arbitrary base address. No binary required.", schema_disasm_bytes),
    ("find_immediate_refs", "Scan sections for raw immediate references (32-bit and 64-bit LE) to an address. Useful when xref analysis hasn't run.", schema_find_imm_refs),
    ("cancel_analysis", "Cancel a stuck analysis run and free the progress slot. The background thread silently discards its result.", schema_empty),
    ("find_callsites_to_import", "Ghidra-style: scan the binary for every direct call/jump to an imported function (by name like 'MessageBoxW' or 'USER32.dll!MessageBoxW') and every call to its import thunk", schema_lookup_name),

    ("detect_protections", "Run all detectors at once and return a structured protection report (anti-debug, anti-VM, packers, obfuscation, .NET, crypto)", schema_empty),
    ("detect_anti_debug", "Anti-debug imports, strings, INT 2D / RDTSC / SIDT, PEB reads via fs:[30]/gs:[60]", schema_empty),
    ("detect_anti_vm", "Anti-VM strings (VBox/VMware/QEMU), CPUID, VMware backdoor port 0x5658", schema_empty),
    ("detect_packers", "Known packer section names (UPX/ASPack/VMProtect/Themida/...), entropy, tiny IAT", schema_empty),
    ("detect_obfuscation", "Indirect jumps/calls, jmp $+2 junk, prefix soup, opaque predicates", schema_empty),
    ("detect_crypto", "Common crypto init constants (MD5/SHA1/SHA256/AES Rcon)", schema_empty),

    ("is_dotnet_assembly", "Quick yes/no â€” is the loaded PE a managed .NET assembly?", schema_empty),
    ("dotnet_info", "CLR runtime version, COR20 flags, entry-point token, stream layout, table/type/method counts", schema_empty),
    ("list_dotnet_types", "List TypeDef rows (paginated, optional name filter)", schema_list_paginated),
    ("list_dotnet_methods", "List MethodDef rows with owner type (paginated, optional name filter)", schema_list_paginated),
    ("list_dotnet_member_refs", "List MemberRef rows (external calls like System.Console::WriteLine) with parent scope", schema_list_paginated),
    ("resolve_dotnet_token", "Resolve a metadata token (e.g. 0x0A000003) to Parent::Name", schema_dotnet_token),

    ("get_pe_info", "PE/DLL header info: image_base, is_dll, COFF + DLL characteristics with decoded flag names (CFG, DEP, ASLR, ...)", schema_empty),
    ("list_exports_full", "List exports with ordinal, RVA, address, and forwarder string (paginated, filter, only_forwarders)", schema_list_exports_full),
    ("lookup_export", "Lookup an export by name OR ordinal", schema_lookup_export),
    ("list_imported_libraries", "Group imports by DLL (kernel32.dll, ntdll.dll, etc.)", schema_empty),
    ("dll_export_summary", "Counts of named/ordinal-only/forwarder exports â€” useful for stub-DLL fingerprinting", schema_empty),

    ("section_entropy", "Per-section entropy with verdict (packed_or_encrypted / compressed / code / structured / padding)", schema_empty),
    ("find_pe_headers", "Scan whole binary for embedded PE headers (MZ + PE\\0\\0). Reveals nested loaders / overlays", schema_find_pe_headers),
    ("find_xor_loops", "Heuristic scan for XOR-based decryption stubs: `xor mem, ...` followed by `inc idx; backward branch`", schema_find_xor_loops),
    ("find_aes_rcon_table", "Locate the canonical AES Rcon table (01 02 04 08 10 20 40 80 1B 36) â€” marks AES key expansion", schema_empty),

    ("dump_section", "Dump a section to a file by name", schema_dump_section),
    ("dump_range", "Dump a virtual address range to a file", schema_dump_range),
    ("dump_full_binary", "Dump entire current (possibly patched) binary data to a file", schema_path),
    ("load_binary", "Parse and load a PE/ELF/Mach-O file from disk as the current binary", schema_path),
    ("load_memory_dump", "Load a raw memory dump file as a new binary (replaces current)", schema_load_dump),
    ("load_map_file", "Import symbols from an MSVC .map file into the loaded binary (args: path, optional base_offset hex added to every address)", schema_path_plus_offset),

    ("patch_bytes", "Patch raw bytes at a virtual address (hex string; 'bytes' or alias 'hex'). Records the patch for undo/list. Drops the analysis by default (analysis_invalidated in the response; invalidate_analysis=false keeps it)", schema_patch_bytes_aliased),
    ("nop_range", "Replace a byte range with x86 NOPs (0x90)", schema_nop_range),
    ("fill_bytes", "Fill a virtual address range with a single byte value (e.g. 0xCC for INT3)", schema_fill_bytes),
    ("fill_pattern", "Fill a virtual address range with a repeating hex pattern", schema_fill_pattern),
    ("patch_string", "Write an ASCII/UTF-8 string at a virtual address (optionally null-terminated)", schema_patch_string),
    ("patch_wide_string", "Write a UTF-16LE string at a virtual address (optionally null-terminated)", schema_patch_string),
    ("patch_int", "Write an integer (u8/u16/u32/u64/i*) at a virtual address (LE/BE)", schema_patch_int),
    ("copy_bytes", "Copy `size` bytes from src_address to dst_address within the binary", schema_copy_bytes),
    ("search_and_replace_bytes", "Find a hex pattern across (optionally a single section) and replace each match with a same-length pattern", schema_search_replace),
    ("patch_nop_instruction", "Replace one or more whole instructions starting at address with NOPs (uses disassembly to size them)", schema_patch_nop_instruction),
    ("patch_call_to_nop", "Replace the call instruction at address with NOPs (auto-sized)", schema_addr),
    ("patch_jcc_to_nop", "Replace the conditional jump at address with NOPs (auto-sized)", schema_addr),
    ("patch_jcc_invert", "Invert the condition of a Jcc at address (jeâ†”jne, jlâ†”jge, etc.) â€” short or near", schema_addr),
    ("patch_jcc_to_jmp", "Convert the conditional jump at address into an unconditional jump (preserves target)", schema_addr),
    ("patch_jmp_to_address", "Write `jmp rel32` at address jumping to target (5 bytes; rel must fit in 32 bits)", schema_patch_jmp),
    ("patch_function_to_ret", "Replace function entry with a single 0xC3 (`ret`) so the function does nothing", schema_addr),
    ("patch_return_value", "Rewrite function entry as `xor eax,eax;ret` (value=0) or `mov eax,imm32;ret` (i32 fits)", schema_patch_return_value),
    ("list_patches", "List every patch recorded in this session (offset, vaddr, original, new, description)", schema_empty),
    ("get_patch_diff", "Get all patches as an offset-sorted before/after diff", schema_empty),
    ("undo_last_patch", "Undo (revert) the most recently applied patch", schema_empty),
    ("undo_patch_at", "Undo the most recent patch covering a given virtual address", schema_addr),
    ("revert_all_patches", "Revert all patches and clear the history", schema_empty),
    ("clear_patch_history", "Clear the patch history without reverting (keeps current binary state)", schema_empty),
    ("export_patches", "Export the patch list to a JSON file (replayable via import_patches)", schema_path),
    ("import_patches", "Apply patches from a JSON file produced by export_patches", schema_import_patches),
    ("diff_with_file", "Byte-by-byte compare current binary data with a file on disk", schema_diff_with_file),
    ("save_patched_binary", "Write the (possibly patched) binary data to a new file", schema_path),

    ("get_debugger_status", "Get current debugger status, registers, breakpoint count, recent events", schema_empty),
    ("debugger_start", "Start debugging the currently loaded binary (queues request)", schema_empty),
    ("debugger_step_into", "Single-step into (queues request)", schema_empty),
    ("debugger_step_over", "Step over (queues request)", schema_empty),
    ("debugger_continue", "Continue execution (queues request)", schema_empty),
    ("debugger_pause", "Suspend a running target for inspection (SIGSTOP/DebugBreakProcess); resume with debugger_continue", schema_empty),
    ("debugger_stop", "Terminate debug session (queues request)", schema_empty),
    ("add_breakpoint", "Add a breakpoint at an address", schema_addr),
    ("remove_breakpoint", "Remove a breakpoint at an address", schema_addr),
    ("list_breakpoints", "List all breakpoints", schema_empty),
    ("list_watchpoints", "List hardware watchpoints (read/write/access + hw exec)", schema_empty),
    ("read_process_memory", "Read live process memory (debugger must be attached). Returns hex+ASCII of the requested range.", schema_get_bytes),
    ("write_process_memory", "Write live process memory (debugger must be attached). Hex bytes payload.", schema_patch_bytes),

    ("list_memory_regions", "Walk every committed region in the live process (VirtualQueryEx). Optional only_executable / only_writable filters.", schema_list_mem_regions),
    ("list_modules", "List every loaded module in the target process (DLLs + EXE) with runtime base + size.", schema_empty),
    ("list_threads", "List thread IDs in the target process.", schema_empty),
    ("disassemble_process_memory", "Read N instructions from the live process at a runtime address. Use this to see *decrypted* code on the fly.", schema_disasm_proc),
    ("search_process_memory", "Scan the live process memory for a pattern. Hex bytes (default) or ASCII string with `s:` prefix.", schema_search_proc),
    ("dump_process_region", "Dump [address, address+size] of live process memory to a file.", schema_dump_proc),
    ("set_hardware_breakpoint", "Arm a DR0..DR3 hardware breakpoint (kind: execute|write|rw). Per-thread.", schema_hw_bp_set),
    ("clear_hardware_breakpoint", "Clear a DR0..DR3 hardware breakpoint slot.", schema_hw_bp_clear),
    ("arm_software_breakpoint", "Write 0xCC at the given address in the live process and remember the original byte.", schema_addr),
    ("run_until_address", "Arm an INT3 at address, continue, and poll until the BP is hit. Returns registers at hit.", schema_run_until),
    ("start_trace", "Start single-step trace recording. Subsequent BP/SS hits append to a ring buffer of size `max`.", schema_start_trace),
    ("stop_trace", "Stop trace recording.", schema_empty),
    ("read_trace", "Read the recorded trace (rip/rax/rcx/rdx/rsp/t per entry).", schema_read_trace),
    ("save_trace", "Save the recorded trace to a JSON file (Ghidra SaveTraceTask equivalent)", schema_path),
    ("load_trace", "Load a saved trace file back into the buffer (time-ordered)", schema_path),
    ("set_debug_options", "Toggle forward_exceptions (DBG_EXCEPTION_NOT_HANDLED for SEH/VEH) and auto_continue_after_bp.", schema_debug_options),

    ("set_exception_policy", "Per-exception-code policy override: forward/swallow/pause/clear. Wins over the global forward_exceptions flag.", schema_exception_policy),
    ("scan_rtti", "C++ RTTI scanner (MSVC + Itanium fallback): TypeDescriptors/COLs/vftables/first vfunc per class.", schema_scan_rtti),
    ("emu_run_function", "Concretely execute a function on the p-code emulator (no live process): pass integer args (rdi,rsi,...), get rax, end reason, steps and memory writes", schema_emu_run),
    ("debugger_attach", "Attach the debugger to an already-running process by PID. Non-destructive on detach.", schema_attach),
    ("debugger_detach", "Detach from the target without killing it.", schema_empty),

    ("get_current_program_info", "Get current program info: name, path, language, image base, entry point, counts", schema_empty),
    ("reanalyze", "Trigger full auto-analysis (alias of run_analysis)", schema_empty),
    ("save_program", "Write the (possibly patched) binary to a file", schema_path),
    ("import_file", "Import a binary file from disk and load it (alias of load_binary)", schema_path),
    ("list_data_items", "List defined data: strings in non-executable sections (paginated, filter)", schema_list_paginated),
    ("list_globals", "List global symbols with section + type info (paginated)", schema_list_paginated),
    ("list_namespaces", "List C++ namespaces derived from demangled function names", schema_empty),
    ("list_classes", "List C++ classes derived from demangled function names", schema_empty),
    ("list_calling_conventions", "List known calling conventions", schema_empty),
    ("list_valid_data_types", "List built-in data types", schema_empty),
    ("get_function_labels", "List labels (user + symbol) inside a function", schema_addr),
    ("create_label", "Create an in-memory user label at an address", schema_create_label),
    ("delete_label", "Delete a user label at an address", schema_addr),
    ("list_labels", "List all user-defined labels (with source: user|analysis)", schema_empty),
    ("tag_function", "Tag a function for triage (e.g. crypto, network, reviewed)", schema_tag_function),
    ("untag_function", "Remove a tag from a function", schema_tag_function),
    ("list_function_tags", "List function tags (all, or for one address)", schema_tags_query),
    ("label_strings", "Apply default s_xxx labels to all strings missing a user label", schema_empty),
    ("search_instructions", "Search instructions by mnemonic and/or operand substring", schema_search_insns),
    ("search_functions_enhanced", "Advanced function search: name + size range + caller/callee counts", schema_search_funcs_enh),
    ("search_byte_patterns", "Search for byte patterns (alias of search_bytes)", schema_search),
    ("force_decompile", "Force fresh decompilation of a function", schema_addr),
    ("get_function_xrefs", "All xrefs into and out of a function", schema_addr),
    ("get_bulk_xrefs", "Get xrefs to a list of addresses in one call", schema_bulk_xrefs),
    ("add_memory_reference", "Create a user-defined memory reference (in-memory only)", schema_mem_ref),
    ("remove_reference", "Remove a user-defined memory reference", schema_mem_ref),
    ("list_memory_references", "List user-defined memory references", schema_empty),
    ("batch_set_comments", "Set multiple comments atomically: [{address, kind, text}]", schema_batch_comments),
    ("analyze_call_graph", "Call graph statistics: roots, leaves, indegree/outdegree distribution", schema_empty),
    ("analyze_control_flow", "CFG statistics for a function: blocks, edges, branch points", schema_addr),
    ("find_code_gaps", "Find gaps of undefined bytes between functions in executable sections", schema_find_gaps),
    ("find_next_undefined_function", "Find the first undefined byte region after an address", schema_addr),
    ("create_function", "Define a function at an address (Ghidra createFunction; UserDefined source, persists in .rdb v4)", schema_create_function),
    ("delete_function", "Delete the function starting at an address", schema_addr),
    ("resolve_thunk", "Walk a thunk chain to its ultimate destination (Ghidra getThunkedFunction; import thunks show DLL!Name)", schema_addr),
    ("inspect_memory_content", "Read memory with heuristic type guessing (string/pointer/data)", schema_inspect_mem),
    ("read_memory", "Read raw memory at an address (alias of get_bytes)", schema_get_bytes),
    ("get_assembly_context", "Disassemble N instructions before/after an address", schema_asm_ctx),
    ("diff_functions", "Diff two functions by normalized mnemonic sequence", schema_diff_funcs),
    ("get_function_signature", "Get first N bytes of a function as a signature + FNV-1a hash", schema_func_sig),
    ("check_connection", "Health check: is the MCP server connected and which program is loaded", schema_empty),
    ("health", "Server health: binary/analysis/debugger state", schema_empty),
    ("get_version", "Get server version and feature list", schema_empty),
    ("debugger_stack_trace", "Walk the EBP frame chain of the attached process and resolve return addresses", schema_empty),

    ("list_data_types", "List all data types in the type manager (id, name, size, C decl)", schema_empty),
    ("get_data_type", "Get one data type by name (id, size, C declaration)", schema_type_name),
    ("create_struct", "Create a struct type", schema_type_name),
    ("create_union", "Create a union type", schema_type_name),
    ("create_enum", "Create an enum type (optional underlying type)", schema_create_enum),
    ("create_typedef", "Create a typedef of an existing type", schema_create_typedef),
    ("create_pointer_type", "Create a pointer-to-type (deduped by target)", schema_pointer_type),
    ("create_array_type", "Create an array type [count] of an element type", schema_create_array),
    ("create_function_signature", "Create a function signature type: return_type, params [{name,type}], calling_convention, varargs", schema_create_func_sig),
    ("add_struct_field", "Add a field to a struct/union (auto-offset after the last field, or explicit offset)", schema_add_field),
    ("remove_struct_field", "Remove a field from a struct/union by name", schema_remove_field),
    ("add_enum_variant", "Add a named value to an enum", schema_enum_variant),
    ("rename_data_type", "Rename a data type", schema_rename_type),
    ("delete_data_type", "Delete a user data type (fails if referenced)", schema_type_name),
    ("apply_data_type", "Ghidra setDataType: define data of a type at an address", schema_apply_type),
    ("get_data_type_at", "Get the data type applied at an address", schema_addr),
    ("list_applied_types", "List all address->type definitions", schema_empty),
    ("export_types", "Export the type manager as JSON (reimportable)", schema_empty),
    ("import_types", "Import types from a JSON doc (inline 'types' array) or a file path", schema_import_types),
    ("import_dwarf_types", "Import DWARF types from the loaded ELF's .debug_info into the DataTypeManager (structs/unions/enums/typedefs with members and layouts)", schema_empty),
    ("import_pdb", "Import types from a PDB file (MSVC): path, or default <binary>.pdb next to the loaded PE. Classes/unions/enums with fields, enum values", schema_path),
    ("list_type_archives", "List built-in type archives (win32/crt/libc — Ghidra .gdt equivalent)", schema_empty),
    ("load_type_archive", "Seed well-known OS/CRT types from a built-in archive (idempotent)", schema_type_archive),

    ("assemble", "Assemble a single instruction to bytes (mov/call/jmp/jcc/push/pop/xor/add/sub/cmp/test/lea/nop/ret/int3/...)", schema_assemble),
    ("assemble_snippet", "Assemble multiple lines (one instruction per line) at an address", schema_assemble_snippet),
    ("patch_asm", "Assemble an instruction at an address and patch it into the binary (records patch, invalidates analysis)", schema_assemble),
    ("list_asm_mnemonics", "List mnemonics supported by the built-in assembler", schema_empty),

    ("open_program", "Open a binary from disk as a new program (saves the current one as a slot)", schema_open_program),
    ("close_program", "Close an open program by name (switches away if it's the current one)", schema_program_name),
    ("list_open_programs", "List all open programs (multi-program model)", schema_empty),
    ("switch_program", "Switch the current program to an already-open one (by name)", schema_program_name),

    ("get_binary_overview", "One-shot binary overview: format, arch, entry, sections, import summary, exports, function count, protection report counts. Replaces 5+ separate calls.", schema_empty),
    ("get_call_context", "One-shot call context for an address: containing function + decompilation + callers + callees + imports called + strings referenced.", schema_addr),

    ("run_async", "Run an allowlisted long scan in a background thread (max 4 concurrent, timeout_ms default 120s) and return a job_id. Poll with poll_job. Eligible: detect_*, search_*, find_*, list_strings, section_entropy, get_binary_overview, get_call_context, analyze_call_graph, scan_rtti and more - search_tools marks every eligible tool with async_eligible=true.", schema_run_async),
    ("poll_job", "Poll a background job (timeout_ms enforced). Returns the tool result when done; consumes the job slot.", schema_poll_job),
];

pub fn list_descriptors() -> Vec<Value> {
    ALL_TOOLS.iter().map(|(name, desc, schema_fn)| {
        let mut schema = schema_fn();
        if let Some(props) = schema.as_object_mut()
            .and_then(|o| o.get_mut("properties"))
            .and_then(|p| p.as_object_mut())
        {
            props.insert("_verbose".into(), json!({
                "type": "boolean",
                "default": false,
                "description": "Disable compact mode: keep input echo fields in the response"
            }));
            props.insert("_snapshot".into(), json!({
                "type": "boolean",
                "default": false,
                "description": "Force a state snapshot into a successful result (default: only for program/analysis/debugger-changing tools; errors always include it unless false)"
            }));
        }
        json!({
            "name": name,
            "description": desc,
            "inputSchema": schema
        })
    }).collect()
}

pub(crate) fn tool_category(name: &str) -> &'static str {
    if matches!(
        name,
        "search_tools"
            | "run_async"
            | "poll_job"
            | "check_connection"
            | "health"
            | "get_version"
            | "int_convert"
    ) {
        return "meta";
    }
    if name.starts_with("patch_")
        || matches!(
            name,
            "nop_range"
                | "fill_bytes"
                | "fill_pattern"
                | "copy_bytes"
                | "search_and_replace_bytes"
                | "list_patches"
                | "get_patch_diff"
                | "undo_last_patch"
                | "undo_patch_at"
                | "revert_all_patches"
                | "clear_patch_history"
                | "export_patches"
                | "import_patches"
                | "diff_with_file"
                | "save_patched_binary"
        )
    {
        return "patching";
    }
    if name.starts_with("debugger_")
        || name.contains("breakpoint")
        || name.contains("trace")
        || name.contains("process_")
        || matches!(
            name,
            "get_debugger_status"
                | "list_threads"
                | "list_modules"
                | "list_memory_regions"
                | "set_debug_options"
                | "set_exception_policy"
                | "run_until_address"
                | "list_watchpoints"
        )
    {
        return "debugger";
    }
    if name.starts_with("detect_")
        || matches!(
            name,
            "section_entropy" | "find_pe_headers" | "find_xor_loops" | "find_aes_rcon_table"
        )
    {
        return "detection";
    }
    if name.contains("dotnet") {
        return "dotnet";
    }
    if matches!(
        name,
        "get_pe_info"
            | "list_exports_full"
            | "lookup_export"
            | "list_imported_libraries"
            | "dll_export_summary"
    ) {
        return "pe";
    }
    if name.contains("_type")
        || name.contains("struct")
        || name.contains("enum")
        || name.contains("typedef")
        || matches!(name, "create_function_signature" | "import_pdb")
    {
        return "types";
    }
    if name.starts_with("assemble") || name == "list_asm_mnemonics" {
        return "assembler";
    }
    if matches!(
        name,
        "open_program"
            | "close_program"
            | "list_open_programs"
            | "switch_program"
            | "load_binary"
            | "load_memory_dump"
            | "load_map_file"
            | "import_file"
            | "save_program"
            | "get_current_program_info"
            | "dump_section"
            | "dump_range"
            | "dump_full_binary"
    ) {
        return "programs";
    }
    if name.contains("comment")
        || name.contains("bookmark")
        || name.contains("label")
        || name.contains("tag")
        || name.contains("memory_reference")
        || name == "remove_reference"
        || name == "rename_function"
        || name == "undo_annotation"
        || name == "redo_annotation"
        || name == "set_plan"
    {
        return "annotations";
    }
    if name.contains("xref") || matches!(name, "find_immediate_refs" | "find_callsites_to_import") {
        return "xrefs";
    }
    if name.starts_with("search_") || name.starts_with("find_") {
        return "search";
    }
    if name.contains("function")
        || name.starts_with("get_call_")
        || name.starts_with("decompile")
        || name.starts_with("disassemble")
        || name == "list_basic_blocks"
    {
        return "functions";
    }
    if matches!(
        name,
        "get_bytes"
            | "get_string"
            | "get_int"
            | "read_memory"
            | "inspect_memory_content"
            | "get_assembly_context"
            | "address_info"
            | "list_strings"
            | "list_imports"
            | "list_exports"
            | "list_symbols"
            | "list_sections"
            | "list_relocations"
            | "list_data_items"
            | "list_globals"
            | "get_section_at"
    ) {
        return "data";
    }
    "analysis"
}

pub fn search_tools(args: &Value) -> Result<Value, String> {
    use std::collections::BTreeMap;
    let query = match args.get("query") {
        None | Some(Value::Null) => String::new(),
        Some(v) => v
            .as_str()
            .ok_or("Invalid params: query must be a string")?
            .to_lowercase(),
    };
    let category = args
        .get("category")
        .and_then(|v| v.as_str())
        .map(|c| c.trim().to_lowercase())
        .filter(|c| !c.is_empty() && c != "all");
    let limit = args
        .get("limit")
        .and_then(|v| v.as_i64())
        .unwrap_or(25)
        .clamp(1, 100) as usize;
    let offset = args
        .get("offset")
        .and_then(|v| v.as_i64())
        .unwrap_or(0)
        .max(0) as usize;
    let include_schema = args
        .get("include_schema")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    let tokens: Vec<String> = query
        .split(|c: char| c.is_whitespace() || c == ',' || c == ';')
        .filter(|t| t.len() >= 2)
        .map(|t| t.to_string())
        .collect();

    let mut categories: BTreeMap<&'static str, usize> = BTreeMap::new();
    let mut hits: Vec<(usize, u32, usize)> = Vec::new();
    for (idx, (name, desc, _)) in ALL_TOOLS.iter().enumerate() {
        let cat = tool_category(name);
        *categories.entry(cat).or_insert(0) += 1;
        if let Some(c) = &category
            && cat != c.as_str() {
                continue;
            }
        if tokens.is_empty() {
            hits.push((0, 0, idx));
            continue;
        }
        let name_lc = name.to_lowercase();
        let desc_lc = desc.to_lowercase();
        let mut matched = 0usize;
        let mut score = 0u32;
        for t in &tokens {
            let mut s = 0u32;
            if name_lc == *t {
                s += 50;
            } else if name_lc.contains(t.as_str()) {
                s += 5;
                if name_lc.starts_with(t.as_str()) {
                    s += 2;
                }
            }
            if desc_lc.contains(t.as_str()) {
                s += 1;
            }
            if s > 0 {
                matched += 1;
                score += s;
            }
        }
        if matched > 0 {
            hits.push((matched, score, idx));
        }
    }
    if !tokens.is_empty() {
        hits.sort_by(|a, b| b.0.cmp(&a.0).then(b.1.cmp(&a.1)).then(a.2.cmp(&b.2)));
    }

    let total = hits.len();
    let items: Vec<Value> = hits
        .iter()
        .skip(offset)
        .take(limit)
        .map(|&(_, _, idx)| {
            let (name, desc, schema_fn) = ALL_TOOLS[idx];
            let schema = schema_fn();
            let params: Vec<String> = schema
                .get("properties")
                .and_then(|p| p.as_object())
                .map(|o| o.keys().cloned().collect())
                .unwrap_or_default();
            let mut row = json!({
                "tool_name": name,
                "description": desc,
                "category": tool_category(name),
                "params": params,
                "required": schema.get("required").cloned().unwrap_or_else(|| json!([])),
                "async_eligible": super::envelope::JOB_ALLOWLIST.contains(&name),
            });
            if include_schema {
                row["inputSchema"] = schema;
            }
            row
        })
        .collect();

    let count = items.len();
    let mut out = json!({
        "total": total,
        "count": count,
        "offset": offset,
        "total_tools": ALL_TOOLS.len(),
        "items": items,
    });
    if tokens.is_empty() && category.is_none() {
        out["categories"] = json!(categories);
    }
    if offset + count < total {
        out["next_offset"] = json!(offset + count);
    }
    if total == 0 {
        out["hint"] = json!("No match: try fewer or different keywords, or call search_tools with an empty query to list categories.");
    }
    Ok(out)
}
