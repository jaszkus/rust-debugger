use super::{Category, Finding, Severity, Source};
use crate::disasm::DisasmResult;
use crate::parser::ParsedBinary;

const ANTI_DEBUG_IMPORTS: &[(&str, Severity, &str)] = &[
    (
        "IsDebuggerPresent",
        Severity::Medium,
        "PEB-based debugger check",
    ),
    (
        "CheckRemoteDebuggerPresent",
        Severity::Medium,
        "Remote debugger check via NT API",
    ),
    (
        "NtQueryInformationProcess",
        Severity::High,
        "Direct NT process info query (bypasses Win32)",
    ),
    (
        "ZwQueryInformationProcess",
        Severity::High,
        "Direct NT process info query (Zw alias)",
    ),
    (
        "NtSetInformationThread",
        Severity::High,
        "Possibly hides thread from debugger (HideFromDebugger)",
    ),
    (
        "ZwSetInformationThread",
        Severity::High,
        "Possibly hides thread from debugger (HideFromDebugger)",
    ),
    (
        "OutputDebugStringA",
        Severity::Low,
        "Anti-debug via OutputDebugString side-effect / GetLastError",
    ),
    (
        "OutputDebugStringW",
        Severity::Low,
        "Anti-debug via OutputDebugString side-effect / GetLastError",
    ),
    (
        "DebugActiveProcess",
        Severity::Medium,
        "Self-debug to occupy the debug slot",
    ),
    (
        "CreateToolhelp32Snapshot",
        Severity::Low,
        "Process enumeration; commonly used to scan for debuggers",
    ),
    (
        "Process32First",
        Severity::Low,
        "Process enumeration; commonly used to scan for debuggers",
    ),
    (
        "Process32Next",
        Severity::Low,
        "Process enumeration; commonly used to scan for debuggers",
    ),
    (
        "FindWindowA",
        Severity::Low,
        "Window-name probe (OllyDbg, x64dbg, IDA, etc.)",
    ),
    (
        "FindWindowW",
        Severity::Low,
        "Window-name probe (OllyDbg, x64dbg, IDA, etc.)",
    ),
    (
        "EnumWindows",
        Severity::Low,
        "Window enumeration; sometimes used to spot debugger UIs",
    ),
    (
        "BlockInput",
        Severity::Medium,
        "Blocks user input — commonly used to frustrate debugging",
    ),
    (
        "SuspendThread",
        Severity::Low,
        "Self-suspend may be used as debug evasion",
    ),
    ("GetTickCount", Severity::Info, "Possible timing check"),
    ("GetTickCount64", Severity::Info, "Possible timing check"),
    (
        "QueryPerformanceCounter",
        Severity::Info,
        "Possible high-precision timing check",
    ),
    (
        "RtlAdjustPrivilege",
        Severity::Medium,
        "Privilege escalation often paired with anti-debug",
    ),
    (
        "DbgUiRemoteBreakin",
        Severity::High,
        "Hooks/patches remote breakin",
    ),
    (
        "DbgBreakPoint",
        Severity::Medium,
        "Direct breakpoint primitive",
    ),
    (
        "CsrGetProcessId",
        Severity::Medium,
        "CSRSS PID lookup (Khaled N. Shah anti-attach trick)",
    ),
];

const ANTI_DEBUG_STRINGS: &[(&str, Severity, &str)] = &[
    (
        "BeingDebugged",
        Severity::Medium,
        "Reference to PEB.BeingDebugged",
    ),
    (
        "NtGlobalFlag",
        Severity::High,
        "Reference to PEB.NtGlobalFlag (heap-flags trick)",
    ),
    (
        "HeapFlags",
        Severity::Medium,
        "Reference to PEB.HeapFlags / ForceFlags",
    ),
    (
        "ProcessDebugPort",
        Severity::High,
        "NtQueryInformationProcess class 7",
    ),
    (
        "ProcessDebugFlags",
        Severity::High,
        "NtQueryInformationProcess class 31",
    ),
    (
        "ProcessDebugObjectHandle",
        Severity::High,
        "NtQueryInformationProcess class 30",
    ),
    (
        "ThreadHideFromDebugger",
        Severity::High,
        "NtSetInformationThread class 17",
    ),
    ("OLLYDBG", Severity::Medium, "OllyDbg window name probe"),
    (
        "WinDbgFrameClass",
        Severity::Medium,
        "WinDbg window class probe",
    ),
    (
        "Immunity Debugger",
        Severity::Medium,
        "Immunity Debugger probe",
    ),
    ("x64dbg", Severity::Medium, "x64dbg probe"),
    ("ida.exe", Severity::Medium, "IDA executable probe"),
    ("ida64.exe", Severity::Medium, "IDA64 executable probe"),
    ("\\\\.\\NTICE", Severity::High, "SoftICE driver probe"),
    ("\\\\.\\SICE", Severity::High, "SoftICE driver probe"),
    (
        "\\\\.\\SIWVID",
        Severity::High,
        "SoftICE video driver probe",
    ),
];

pub(crate) fn string_hit_confidence(sev: Severity) -> f64 {
    match sev {
        Severity::High => 0.9,
        Severity::Medium => 0.8,
        Severity::Low => 0.6,
        Severity::Info => 0.5,
    }
}

fn import_severity(sev: Severity) -> Severity {
    match sev {
        Severity::High => Severity::Medium,
        other => other,
    }
}

const PEB_READ_SAMPLE: u32 = 5;

fn demote_weak_signals(out: &mut [Finding], weak: &[&str], strong: &[&str]) {
    if out.iter().any(|f| strong.contains(&f.id)) {
        return;
    }
    for f in out.iter_mut() {
        if weak.contains(&f.id) {
            f.severity = Severity::Info;
            f.confidence = (f.confidence * 0.4).min(0.3);
        }
    }
}

const AD_WEAK: &[&str] = &[
    "rdtsc",
    "rdtsc_many",
    "peb_gs60",
    "peb_fs30",
    "IsDebuggerPresent",
    "QueryPerformanceCounter",
    "GetTickCount",
    "GetTickCount64",
    "OutputDebugStringA",
    "OutputDebugStringW",
];
const AD_STRONG: &[&str] = &[
    "int_2d",
    "NtSetInformationThread",
    "ZwSetInformationThread",
    "NtQueryInformationProcess",
    "ZwQueryInformationProcess",
    "DbgUiRemoteBreakin",
    "NtGlobalFlag",
    "ProcessDebugPort",
    "ProcessDebugFlags",
    "ProcessDebugObjectHandle",
    "ThreadHideFromDebugger",
];

const AV_WEAK: &[&str] = &["cpuid", "cpuid_many", "registry_probe_api"];
const AV_STRONG: &[&str] = &[
    "vmware_backdoor",
    "VBoxService",
    "VBoxTray",
    "VBoxGuest",
    "VirtualBox",
    "VMware",
    "vmtoolsd",
    "vmwaretray",
    "vmwareuser",
    "QEMU",
    "Bochs",
    "Xen",
    "Hyper-V",
];

pub fn detect_anti_debug(bin: &ParsedBinary, disasm: &DisasmResult) -> Vec<Finding> {
    let mut out = detect_anti_debug_raw(bin, disasm);
    demote_weak_signals(&mut out, AD_WEAK, AD_STRONG);
    out
}

pub fn detect_anti_vm(bin: &ParsedBinary, disasm: &DisasmResult) -> Vec<Finding> {
    let mut out = detect_anti_vm_raw(bin, disasm);
    demote_weak_signals(&mut out, AV_WEAK, AV_STRONG);
    out
}

fn detect_anti_debug_raw(bin: &ParsedBinary, disasm: &DisasmResult) -> Vec<Finding> {
    let mut out = Vec::new();

    for imp in &bin.imports {
        for (name, sev, desc) in ANTI_DEBUG_IMPORTS {
            if imp.name == *name {
                out.push(Finding {
                    category: Category::AntiDebug,
                    severity: import_severity(*sev),
                    id: name,
                    description: format!("{} (import-based, low confidence)", desc),
                    address: None,
                    evidence: Some(format!("{}!{}", imp.library, imp.name)),
                    source: Source::Import,
                    confidence: 0.5,
                });
                break;
            }
        }
    }

    for s in &bin.strings {
        for (needle, sev, desc) in ANTI_DEBUG_STRINGS {
            if s.content.contains(needle) {
                out.push(Finding {
                    category: Category::AntiDebug,
                    severity: *sev,
                    id: needle,
                    description: desc.to_string(),
                    address: Some(s.vaddr),
                    evidence: Some(s.content.clone()),
                    source: Source::Heuristic,
                    confidence: string_hit_confidence(*sev),
                });
                break;
            }
        }
    }

    detect_anti_debug_instructions(disasm, &mut out);

    out
}

fn detect_anti_debug_instructions(disasm: &DisasmResult, out: &mut Vec<Finding>) {
    let mut int2d_count = 0u32;
    let mut rdtsc_count = 0u32;
    let mut sidt_count = 0u32;
    let mut peb_fs30_count = 0u32;
    let mut peb_gs60_count = 0u32;

    for insn in disasm.instructions.iter() {
        match insn.mnemonic {
            "int" => {
                let op_owned = insn.ops();
                let op = op_owned.trim();
                if op == "0x2d" || op == "0x2D" || op == "45" {
                    int2d_count += 1;
                    if int2d_count <= 5 {
                        out.push(Finding {
                            category: Category::AntiDebug,
                            severity: Severity::High,
                            id: "int_2d",
                            description:
                                "INT 2D — kernel-debug interrupt; trips most user-mode debuggers"
                                    .into(),
                            address: Some(insn.address),
                            evidence: Some("int 0x2d".into()),
                            source: Source::StaticSignature,
                            confidence: 1.0,
                        });
                    }
                }
            }
            "rdtsc" => {
                rdtsc_count += 1;
                if rdtsc_count <= 4 {
                    out.push(Finding {
                        category: Category::AntiDebug,
                        severity: Severity::Medium,
                        id: "rdtsc",
                        description: "RDTSC timing instruction — often used to detect single-stepping".into(),
                        address: Some(insn.address),
                        evidence: None,
                        source: Source::Heuristic,
                        confidence: 0.7,
                    });
                }
            }
            "sidt" | "sgdt" | "sldt" | "str" => {
                sidt_count += 1;
                if sidt_count <= 4 {
                    out.push(Finding {
                        category: Category::AntiDebug,
                        severity: Severity::High,
                        id: "redpill",
                        description: format!(
                            "{} — Red Pill / VM-detection style descriptor read",
                            insn.mnemonic
                        ),
                        address: Some(insn.address),
                        evidence: None,
                        source: Source::Heuristic,
                        confidence: 0.8,
                    });
                }
            }
            _ => {}
        }
        if insn.bytes.len() >= 6 {
            let b = &insn.bytes;
            if b[0] == 0x64
                && b[1] == 0xA1
                && b[2] == 0x30
                && b[3] == 0x00
                && b[4] == 0x00
                && b[5] == 0x00
            {
                peb_fs30_count += 1;
                if peb_fs30_count <= PEB_READ_SAMPLE {
                    out.push(Finding {
                        category: Category::AntiDebug,
                        severity: Severity::Medium,
                        id: "peb_fs30",
                        description:
                            "Direct PEB read via fs:[0x30] — manual BeingDebugged/NtGlobalFlag check"
                                .into(),
                        address: Some(insn.address),
                        evidence: Some("64 a1 30 00 00 00".into()),
                        source: Source::StaticSignature,
                        confidence: 1.0,
                    });
                }
            }
            if b.len() >= 9
                && b[0] == 0x65
                && b[1] == 0x48
                && b[2] == 0x8B
                && b[3] == 0x04
                && b[4] == 0x25
                && b[5] == 0x60
                && b[6] == 0
                && b[7] == 0
                && b[8] == 0
            {
                peb_gs60_count += 1;
                if peb_gs60_count <= PEB_READ_SAMPLE {
                    out.push(Finding {
                        category: Category::AntiDebug,
                        severity: Severity::Medium,
                        id: "peb_gs60",
                        description: "Direct PEB read via gs:[0x60] (x64) — manual BeingDebugged/NtGlobalFlag check".into(),
                        address: Some(insn.address),
                        evidence: Some("65 48 8b 04 25 60 00 00 00".into()),
                        source: Source::StaticSignature,
                        confidence: 1.0,
                    });
                }
            }
        }
    }

    if peb_fs30_count > PEB_READ_SAMPLE || peb_gs60_count > PEB_READ_SAMPLE {
        out.push(Finding {
            category: Category::AntiDebug,
            severity: Severity::Low,
            id: "peb_reads_many",
            description: format!(
                "{} direct PEB reads in total (fs:[0x30]: {}, gs:[0x60]: {}) — common in ordinary code; inspect the surrounding function before treating as anti-debug",
                peb_fs30_count + peb_gs60_count,
                peb_fs30_count,
                peb_gs60_count
            ),
            address: None,
            evidence: None,
            source: Source::Heuristic,
            confidence: 0.5,
        });
    }

    if rdtsc_count > 4 {
        out.push(Finding {
            category: Category::AntiDebug,
            severity: Severity::Medium,
            id: "rdtsc_many",
            description: format!(
                "{} RDTSC instructions in total — heavy timing-based protection",
                rdtsc_count
            ),
            address: None,
            evidence: None,
            source: Source::Heuristic,
            confidence: 0.75,
        });
    }
}

const ANTI_VM_STRINGS: &[(&str, Severity, &str)] = &[
    ("VBoxService", Severity::High, "VirtualBox service name"),
    ("VBoxTray", Severity::High, "VirtualBox tray name"),
    ("VBoxGuest", Severity::High, "VirtualBox guest driver"),
    ("VBoxMouse", Severity::Medium, "VirtualBox mouse driver"),
    (
        "VBoxSF",
        Severity::Medium,
        "VirtualBox shared folders driver",
    ),
    ("VBoxVideo", Severity::Medium, "VirtualBox video driver"),
    ("VirtualBox", Severity::High, "VirtualBox name reference"),
    ("VMware", Severity::High, "VMware name reference"),
    (
        "vmware",
        Severity::Medium,
        "VMware name reference (lowercase)",
    ),
    ("vmtoolsd", Severity::High, "VMware tools daemon"),
    ("vmwaretray", Severity::High, "VMware tray"),
    ("vmwareuser", Severity::High, "VMware user"),
    ("vmci.sys", Severity::High, "VMware VMCI driver"),
    ("vmusbmouse.sys", Severity::High, "VMware USB mouse driver"),
    ("vmx_svga.sys", Severity::High, "VMware SVGA driver"),
    ("vmxnet.sys", Severity::High, "VMware vmxnet driver"),
    ("QEMU", Severity::High, "QEMU reference"),
    ("Bochs", Severity::High, "Bochs reference"),
    ("Xen", Severity::Medium, "Xen reference"),
    ("Hyper-V", Severity::Medium, "Hyper-V reference"),
    (
        "\\\\.\\VBoxMiniRdrDN",
        Severity::High,
        "VirtualBox shared folders device path",
    ),
    ("\\\\.\\VBoxTrayIPC", Severity::High, "VirtualBox tray IPC"),
    (
        "\\\\.\\VBoxGuest",
        Severity::High,
        "VirtualBox guest device",
    ),
    (
        "\\\\.\\HGFS",
        Severity::High,
        "VMware host-guest filesystem",
    ),
    (
        "HARDWARE\\ACPI\\DSDT\\VBOX__",
        Severity::High,
        "VirtualBox ACPI registry path",
    ),
    (
        "SOFTWARE\\Oracle\\VirtualBox Guest Additions",
        Severity::High,
        "VirtualBox additions registry",
    ),
    (
        "SYSTEM\\ControlSet001\\Services\\VBoxService",
        Severity::High,
        "VirtualBox service registry",
    ),
    (
        "SOFTWARE\\VMware, Inc.\\VMware Tools",
        Severity::High,
        "VMware Tools registry path",
    ),
];

fn detect_anti_vm_raw(bin: &ParsedBinary, disasm: &DisasmResult) -> Vec<Finding> {
    let mut out = Vec::new();

    for imp in &bin.imports {
        let name = &imp.name;
        if matches!(
            name.as_str(),
            "RegOpenKeyExA" | "RegOpenKeyExW" | "RegQueryValueExA" | "RegQueryValueExW"
        ) {
            out.push(Finding {
                category: Category::AntiVm,
                severity: Severity::Info,
                id: "registry_probe_api",
                description: format!("{} — possibly checks VM registry keys", name),
                address: None,
                evidence: Some(format!("{}!{}", imp.library, imp.name)),
                source: Source::Heuristic,
                confidence: 0.5,
            });
            break;
        }
    }

    for s in &bin.strings {
        for (needle, sev, desc) in ANTI_VM_STRINGS {
            if s.content.contains(needle) {
                out.push(Finding {
                    category: Category::AntiVm,
                    severity: *sev,
                    id: needle,
                    description: desc.to_string(),
                    address: Some(s.vaddr),
                    evidence: Some(s.content.clone()),
                    source: Source::Heuristic,
                    confidence: string_hit_confidence(*sev),
                });
                break;
            }
        }
    }

    let mut cpuid_count = 0u32;
    let mut cpuid_in_exec = 0u32;
    let mut cpuid_shown = 0u32;
    for insn in disasm.instructions.iter() {
        if insn.mnem() == "cpuid" {
            cpuid_count += 1;
            let in_exec = bin.sections.iter().any(|s| {
                s.is_executable
                    && insn.address >= s.vaddr
                    && insn.address < s.vaddr.saturating_add(s.size)
            });
            if in_exec {
                cpuid_in_exec += 1;
            }
            if cpuid_shown < 5 {
                cpuid_shown += 1;
                out.push(Finding {
                    category: Category::AntiVm,
                    severity: if in_exec { Severity::Info } else { Severity::Medium },
                    id: "cpuid",
                    description: if in_exec {
                        "CPUID in executable code — usually legit CPU feature detection (SSE/AVX probing)".into()
                    } else {
                        "CPUID in a data region decoded as code — worth a closer look".into()
                    },
                    address: Some(insn.address),
                    evidence: Some(if in_exec { "exec section" } else { "non-exec section" }.into()),
                    source: Source::Heuristic,
                    confidence: if in_exec { 0.7 } else { 0.8 },
                });
            }
        }
        if insn.mnem() == "in" && insn.ops().contains("0x5658") {
            out.push(Finding {
                category: Category::AntiVm,
                severity: Severity::High,
                id: "vmware_backdoor",
                description: "I/O on 0x5658 — VMware backdoor port".into(),
                address: Some(insn.address),
                evidence: None,
                source: Source::StaticSignature,
                confidence: 1.0,
            });
        }
    }
    if cpuid_count > 5 {
        out.push(Finding {
            category: Category::AntiVm,
            severity: Severity::Info,
            id: "cpuid_many",
            description: format!(
                "{} CPUID instructions total ({} in executable code) — mass CPUID usually means feature probing, not VM evasion",
                cpuid_count, cpuid_in_exec
            ),
            address: None,
            evidence: None,
            source: Source::Heuristic,
            confidence: 0.6,
        });
    }

    out
}
