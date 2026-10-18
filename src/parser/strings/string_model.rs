
use std::cell::RefCell;
use std::collections::{HashMap, HashSet};
use std::sync::OnceLock;

const SYMS: usize = 128;

const THRESHOLDS: &[f64] = &[
    10.0, 10.0, 10.0, 10.0, -2.71, -3.26, -3.52, -3.84, -4.23, -4.49,
    -4.55, -4.74, -4.88, -5.03, -5.06, -5.20, -5.24, -5.29, -5.29, -5.42,
    -5.51, -5.52, -5.53, -5.60, -5.60, -5.62, -5.70, -5.70, -5.78, -5.79,
    -5.81, -5.81, -5.84, -5.85, -5.86, -5.88, -5.92, -5.92, -5.93, -5.95,
    -5.99, -6.00, -6.00, -6.00, -6.02, -6.02, -6.02, -6.05, -6.06, -6.07,
    -6.08, -6.10, -6.12, -6.12, -6.13, -6.13, -6.13, -6.13, -6.13, -6.13,
    -6.13, -6.15, -6.15, -6.16, -6.16, -6.16, -6.17, -6.19, -6.19, -6.21,
    -6.21, -6.21, -6.21, -6.21, -6.21, -6.25, -6.25, -6.25, -6.25, -6.25,
    -6.25, -6.25, -6.26, -6.26, -6.26, -6.26, -6.26, -6.26, -6.26, -6.26,
    -6.26, -6.29, -6.29, -6.30, -6.30, -6.30, -6.30, -6.30, -6.30, -6.30,
    -6.30,
];
const MAX_THRESHOLD: f64 = -6.3;

#[inline]
fn thr(n: usize) -> f64 {
    THRESHOLDS.get(n).copied().unwrap_or(MAX_THRESHOLD)
}

const MODEL_SOURCE: &str = include_str!("../../../data/StringModel.sng");

const MAX_ANALYZE: usize = 2048;

const LLR_BIN: &[u8] = include_bytes!("../../../data/StringModelLLR.bin");
const LLR_TRI_LEN: usize = 1 << 21;
const LLR_BI_LEN: usize = 1 << 14;
const LLR_STEP: f64 = 0.05;
const _: () = assert!(LLR_BIN.len() == LLR_TRI_LEN + LLR_BI_LEN);


#[allow(dead_code)]
struct TrigramModel {
    begin: Vec<f32>,
    end: Vec<f32>,
    trigram: Vec<f32>,
    zero_log: f32,
    n_begin: usize,
    n_end: usize,
    n_trigram: usize,
}

#[inline(always)]
fn idx2(a: u8, b: u8) -> usize {
    ((a as usize & 0x7F) << 7) | (b as usize & 0x7F)
}

#[inline(always)]
fn idx3(a: u8, b: u8, c: u8) -> usize {
    ((a as usize & 0x7F) << 14) | ((b as usize & 0x7F) << 7) | (c as usize & 0x7F)
}

fn parse_token(tok: &str) -> Option<u8> {
    match tok {
        "[SP]" => Some(b' '),
        "[HT]" => Some(b'\t'),
        "[NUL]" => Some(0),
        "[SOH]" => Some(1),
        "[STX]" => Some(2),
        "[ETX]" => Some(3),
        "[EOT]" => Some(4),
        "[ENQ]" => Some(5),
        "[ACK]" => Some(6),
        "[BEL]" => Some(7),
        "[BS]" => Some(8),
        "[LF]" => Some(10),
        "[VT]" => Some(11),
        "[FF]" => Some(12),
        "[CR]" => Some(13),
        "[SO]" => Some(14),
        "[SI]" => Some(15),
        "[DLE]" => Some(16),
        "[DC1]" => Some(17),
        "[DC2]" => Some(18),
        "[DC3]" => Some(19),
        "[DC4]" => Some(20),
        "[NAK]" => Some(21),
        "[SYN]" => Some(22),
        "[ETB]" => Some(23),
        "[CAN]" => Some(24),
        "[EM]" => Some(25),
        "[SUB]" => Some(26),
        "[ESC]" => Some(27),
        "[FS]" => Some(28),
        "[GS]" => Some(29),
        "[RS]" => Some(30),
        "[US]" => Some(31),
        "[DEL]" => Some(127),
        s if s.len() == 1 => s.as_bytes().first().copied(),
        _ => None,
    }
}

fn build_model(src: &str) -> TrigramModel {
    let mut begin: HashMap<(u8, u8), u64> = HashMap::new();
    let mut end: HashMap<(u8, u8), u64> = HashMap::new();
    let mut trigram: HashMap<(u8, u8, u8), u64> = HashMap::new();

    for line in src.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let parts: Vec<&str> = line.split('\t').collect();
        if parts.len() != 4 {
            continue;
        }
        let count: u64 = match parts[3].trim().parse() {
            Ok(c) => c,
            Err(_) => continue,
        };
        if count == 0 {
            continue;
        }
        if parts[0] == "[^]" {
            if parts[2] != "[$]" {
                if let (Some(a), Some(b)) = (parse_token(parts[1]), parse_token(parts[2])) {
                    *begin.entry((a, b)).or_insert(0) += count;
                }
            }
        } else if parts[2] == "[$]" {
            if let (Some(a), Some(b)) = (parse_token(parts[0]), parse_token(parts[1])) {
                *end.entry((a, b)).or_insert(0) += count;
            }
        } else if let (Some(a), Some(b), Some(c)) =
            (parse_token(parts[0]), parse_token(parts[1]), parse_token(parts[2]))
        {
            *trigram.entry((a, b, c)).or_insert(0) += count;
        }
    }

    let total = begin.values().sum::<u64>()
        + end.values().sum::<u64>()
        + trigram.values().sum::<u64>()
        + ((128 * 128) as u64 - begin.len() as u64)
        + ((128 * 128) as u64 - end.len() as u64)
        + ((128 * 128 * 128) as u64 - trigram.len() as u64);

    let zero_log = (1.0_f64 / total as f64).log10();
    let log_of = |c: u64| ((c as f64 / total as f64).log10()) as f32;

    let mut m = TrigramModel {
        begin: vec![zero_log as f32; SYMS * SYMS],
        end: vec![zero_log as f32; SYMS * SYMS],
        trigram: vec![zero_log as f32; SYMS * SYMS * SYMS],
        zero_log: zero_log as f32,
        n_begin: begin.len(),
        n_end: end.len(),
        n_trigram: trigram.len(),
    };
    for ((a, b), v) in begin {
        m.begin[idx2(a, b)] = log_of(v);
    }
    for ((a, b), v) in end {
        m.end[idx2(a, b)] = log_of(v);
    }
    for ((a, b, c), v) in trigram {
        m.trigram[idx3(a, b, c)] = log_of(v);
    }
    m
}

fn model() -> &'static TrigramModel {
    static MODEL: OnceLock<TrigramModel> = OnceLock::new();
    MODEL.get_or_init(|| build_model(MODEL_SOURCE))
}


fn score(s: &[u8]) -> Option<(f64, usize)> {
    let m = model();

    let mut pos: usize = 0;
    let mut likelihood: f64 = 0.0;
    let mut first0: u8 = 0;
    let mut prev2: u8 = 0;
    let mut prev1: u8 = 0;
    let mut started = false;
    let mut pending_ws = false;

    macro_rules! emit_byte {
        ($b:expr) => {{
            let b: u8 = $b;
            if pos == 0 {
                first0 = b;
                prev1 = b;
            } else if pos == 1 {
                likelihood += m.begin[idx2(first0, b)] as f64;
                prev2 = prev1;
                prev1 = b;
            } else {
                if pos >= 3 {
                    likelihood += m.trigram[idx3(prev2, prev1, b)] as f64;
                }
                prev2 = prev1;
                prev1 = b;
            }
            pos += 1;
        }};
    }

    for &raw in s {
        let c = if raw < 128 { raw.to_ascii_lowercase() } else { b' ' };
        if c == b' ' || c == b'\t' {
            if started {
                pending_ws = true;
            }
            continue;
        }
        if !started {
            started = true;
            emit_byte!(c);
        } else {
            if pending_ws {
                emit_byte!(b' ');
                pending_ws = false;
            }
            emit_byte!(c);
        }
    }
    if pos < 4 {
        return None;
    }
    likelihood += m.end[idx2(prev2, prev1)] as f64;

    Some((likelihood / pos as f64, pos))
}

#[inline]
pub fn score_probable(s: &[u8]) -> Option<f64> {
    let (sc, len) = score(s)?;
    if sc > thr(len) {
        Some(sc)
    } else {
        None
    }
}

pub fn is_probable_string(s: &str) -> bool {
    is_probable_string_bytes(s.as_bytes())
}

pub fn is_probable_string_bytes(s: &[u8]) -> bool {
    score_probable(s).is_some()
}

pub fn string_score(s: &str) -> f64 {
    score(s.as_bytes()).map(|(sc, _)| sc).unwrap_or(f64::MIN)
}

pub fn is_high_confidence(s: &str) -> bool {
    match score(s.as_bytes()) {
        Some((sc, len)) => sc > thr(len) + 1.0,
        None => false,
    }
}


#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    None,
    Url,
    Guid,
    Ipv4,
    Hash,
    WinPath,
    UnixPath,
    Mangled,
    Java,
    Section,
    Base64,
    Banner,
    Script,
    Diacritic,
}

impl Kind {
    pub fn as_str(self) -> &'static str {
        match self {
            Kind::None => "text",
            Kind::Url => "url",
            Kind::Guid => "guid",
            Kind::Ipv4 => "ipv4",
            Kind::Hash => "hash",
            Kind::WinPath => "winpath",
            Kind::UnixPath => "unixpath",
            Kind::Mangled => "mangled",
            Kind::Java => "java",
            Kind::Section => "section",
            Kind::Base64 => "base64",
            Kind::Banner => "banner",
            Kind::Script => "script",
            Kind::Diacritic => "diacritic",
        }
    }

    fn fixed_conf(self) -> Option<f64> {
        match self {
            Kind::None => None,
            Kind::Url => Some(0.98),
            Kind::Guid => Some(0.97),
            Kind::Ipv4 => Some(0.90),
            Kind::Hash => Some(0.90),
            Kind::WinPath => Some(0.97),
            Kind::UnixPath => Some(0.93),
            Kind::Mangled => Some(0.95),
            Kind::Java => Some(0.93),
            Kind::Section => Some(0.90),
            Kind::Base64 => Some(0.75),
            Kind::Banner => Some(0.90),
            Kind::Script => Some(0.85),
            Kind::Diacritic => Some(0.75),
        }
    }
}

#[derive(Clone, Copy, Debug, Default)]
pub struct Context {
    pub has_xref: bool,
    pub in_code_section: bool,
    pub nul_terminated: bool,
    pub preceded_by_nul: bool,
}

const CTX_XREF: f64 = 3.0;
const CTX_CODE_SECTION: f64 = -1.5;
const CTX_NUL_TERMINATED: f64 = 0.7;
const CTX_PRECEDED_BY_NUL: f64 = 0.3;

#[derive(Clone, Copy, Debug)]
pub struct Verdict {
    pub accepted: bool,
    pub confidence: f32,
    pub kind: Kind,
    pub len: usize,
}

impl Verdict {
    pub fn is_high(&self) -> bool {
        self.confidence >= 0.9
    }
}

pub const HYBRID_FLOOR: f64 = 0.2;

pub fn accept_threshold(n: usize) -> f64 {
    match n {
        0..=3 => 2.0,
        4 => 0.99,
        5 => 0.92,
        6 => 0.66,
        7 | 8 => 0.57,
        _ => 0.50,
    }
}

pub fn analyze(s: &[u8], ctx: Context) -> Option<Verdict> {
    if !s.is_ascii() {
        if let Ok(text) = std::str::from_utf8(s) {
            if kind_script(text) {
                return Some(text_verdict(Kind::Script, text.chars().count()));
            }
            if kind_diacritic(text) {
                return Some(text_verdict(Kind::Diacritic, text.chars().count()));
            }
        }
    }
    SCRATCH.with(|cell| {
        let mut guard = cell.borrow_mut();
        analyze_normalized(s, ctx, &mut guard)
    })
}

pub fn is_string(s: &[u8]) -> bool {
    analyze(s, Context::default()).map_or(false, |v| v.accepted)
}

pub fn confidence(s: &[u8]) -> f32 {
    analyze(s, Context::default()).map_or(0.0, |v| v.confidence)
}

fn text_verdict(kind: Kind, len: usize) -> Verdict {
    Verdict {
        accepted: true,
        confidence: kind.fixed_conf().unwrap_or(0.0) as f32,
        kind,
        len,
    }
}


struct Scratch {
    t: Vec<u8>,
    low: Vec<u8>,
    tv: Vec<f32>,
    tok: Vec<u8>,
}

thread_local! {
    static SCRATCH: RefCell<Scratch> = RefCell::new(Scratch {
        t: Vec::new(),
        low: Vec::new(),
        tv: Vec::new(),
        tok: Vec::new(),
    });
}

const NFEAT: usize = 26;
const WEIGHTS: [f64; NFEAT] = [
    -1.2123814627314344,
    -0.030692910367419453,
    1.8731773162103698,
    -1.3922640857090622,
    -0.41334465657867486,
    -2.608180617979698,
    -1.9306680676198413,
    -0.7141815606448263,
    -0.4236282689070373,
    -0.8187361187369846,
    -1.2061890671273048,
    3.197756296017754,
    -3.4400872366641075,
    3.131099539897461,
    3.4953422367726255,
    0.6371077701692389,
    -2.656996389839299,
    -2.691867375707884,
    -0.48256964914413025,
    1.9707006682860562,
    0.13982309252066838,
    -1.1394630870051463,
    -1.140767192782167,
    0.8395152384484073,
    0.2813391360081116,
    0.6983203916297112,
];
const BIAS: f64 = 8.235813345822425;
const LEXICON: &str = concat!(
    "aad aam aarch abbrev abort about abs absl absolute abstract acc accent accept accesory access ",
    "accessibility accessible account acquire action activate activated activation active activity ",
    "adapter add adding additional addr address adjust admin advanced advapi aero aes affix after ",
    "against age agent aggregator aix algorithm alias align alignment all alloc allocate allocation ",
    "allocator allow allowed alpha already also alternate amount anaheim analysis and animation ",
    "animations anonymous any aom api app append apple applicable application applications apply ",
    "apps aranges arb arc arch archive are area arg argument arguments arm array ars ascii asn ",
    "assert assertion assigned assisted association associations assuan async atk atom atomic atspi ",
    "attempt attempted attempts attr attrib attribute attributes audience audio audit auth ",
    "authentication auto autologon autosave aux available avif avx awareness back backend background ",
    "backup bad band banner base based basic bbwe because been before begin beginning behavior best ",
    "between bfd big bin binary bind bing bio biometrics bit bitmap bitrate bits black blend blob ",
    "block blocked blocking blocks bool boolean boot bottom bounds box boxed branded break broken ",
    "broker browser bss btree budget buf buffer buffers build builder bus but button byte bytes ",
    "cache cairo calculation calendar call callback called caller campaign can cancel cannot cap ",
    "capable caps capture case category cblas cbor cdm cell center cert certificate cfg cfl chain ",
    "change changed changes channel channels char character characters chars charset check checked ",
    "child choice choices chroma chunk cipher class clean cleanup clear click client clip clipboard ",
    "clock clone close cloud code codec codex coding col collation collator collection collections ",
    "color colorfiltering colormap colors column columns com command commdlg comment commercial ",
    "commit common compare compile compiler complete completed completion component compound ",
    "compress compressed compression computation compute condition config configs configuration ",
    "configure configured connect connected connection connectivity consent const constant ",
    "constructors consumer container contains content context contrast control controller controls ",
    "conventional conversation conversion convert converter convolve cookie coord coordinator ",
    "copilot copy copying copyright cord core correct correlation corrupt cortana could couldn count ",
    "cpi cpp cpu crc create created creating creation credential credentials critera criteria ",
    "critical crl crt crypto css ctor ctors ctx cuda cudt cups currency current cursor curve custom ",
    "cvt cxx data database date day days dbus deadline debian debug debugging dec decimal decklink ",
    "decode decoder decrypt deep def default deferred define defined definition deinit del delay ",
    "delete delivered delivery delta demo demux denied deployment depth desc description descriptor ",
    "desk deskbandsite desktop dest destination destroy detail detected detection determine dev ",
    "device diagnostics dialog dict different digest dir direct direction directory disable disabled ",
    "discard disconnect discoverer disown dispatcher display distribution div dll dls document does ",
    "doesn domain don done dos dot double download dpb dpi draw driver drm drop dsp dst dtls dtors ",
    "duk dump dup duplicate duration durations dvb dvi dwarf dyn dynamic dynstr dynsym each early ",
    "edata edge edition edu education eee effect egl eii element elements elf eligibility eligible ",
    "email embedded emit empty enable enabled enablement enc encode encoder encoding encountered ",
    "encrypt encryption end ended enduser engine enhanced enough ens ensure enter enterprise entity ",
    "entries entry enum enumeration env environment eol eos epk epkns epns epoll epoxy eps equal erk ",
    "erkn erkns erks erns err errno error ers escape ess etc even event events ex exceeded excel ",
    "except exception excl exclude excluded exe executable execution exist existing exists exit ",
    "exited exp expected expedited experience explorer export expression exr ext extended extension ",
    "extensions extents external extra extract exts face factory fail failed failure fallback false ",
    "family fast fatal favicon fdisk feature features fec feedback field fields fifo file filename ",
    "files filesyncpolicy filesystem fill filter final find fini finish finished finite first fixed ",
    "flac flag flags flat flip float flow fluid flush folder font for force form format formats ",
    "formattable formatted formatter found foundation fragment frame framebuffer frames framework ",
    "free from frx fsck fsia full fullscreen func funcnames funcs function functions future fwlink ",
    "gcc gcm gdi gdk gen generate generated generator generic geographic geometry get git glib glibc ",
    "global glx glyph glyphs gnu gnutls got gpgme gpgrt gradient graph graphene graphics group gst ",
    "guid handle handled handler handling handshake hang harness has hash have hdr head header ",
    "headers health heap heif height help helper helpers here hide high highbd highlight history ",
    "hkcu hklm hmac holographic hook host hotkey html http https hub hvsi hwasan hwnd ibm ice icon ",
    "icu identifier identity idle idx iface ignore ignored ignoring illegal image images imf imm ",
    "immersive impl import inbox inc include inclusive incomplete incorrect index ineligible info ",
    "information init initial initialization initialize initialized initially inline inode input ins ",
    "insert inst install installation installed instance instantiated instead int integer ",
    "integration intent interaction interactive interface internal internet interval into intra ",
    "invalid ioctl ipatch ipc ipp irisservice islamic iso item iter iterator itm jack java jcr ",
    "journal joystick jpeg json keep kernel kernel32 kernelbase key keyboard keys khr kind kmod ",
    "known label landing lang language larch large last latency latest latin launch launched ",
    "launcher layer layout ldr learn left len length less level lib libinstpatch library librdf ",
    "librevenge libs license light limit line lines link linked linker linkid linux list listen ",
    "listener listening literal load loaded loader loc local locale localized located location ",
    "locations lock lockdown locked loclists log logging logon logontasks long look lookup loop low ",
    "lsan lto lucene lzma mac machine macinfo macro magic magick mai main make malloc managed ",
    "management manager many map mapping margin mark marked marker mask match matcher matrix max ",
    "maximum may mbedtls mdm means measure media medium mem member memory menu merge message met ",
    "meta metacall metadata method mfx microsoft midi migration mime min minimum mips misc mismatch ",
    "missing mmap mobility mockable mod modal mode model modification modifier module monitor month ",
    "more motion mouse move mpeg mpi msa msg msix mul multi multiple must mutex mux name named names ",
    "namespace narrator native nds ndup need needed needs negative net nettle network new next node ",
    "non none normal not note notepad notice notification notifications notify now nt ntdll nth null ",
    "num number numeric numparse obj object objects obtained odp ods oem oes off offers office ",
    "offset offsets oid old ole onboarding once one onecore onecoreuap onedrive onetime oni only ",
    "oobe opcode open opening openpgp opensource operation option optional options opus orcus order ",
    "org orientation origin original osshell other out outlook output over overflow overlay pack ",
    "package packages packet packets pad page pager pages paint painter palette pam panel pango ",
    "panic param parameter parameterfv parameteriv parameters params parent parental parisc parse ",
    "parsed parser parsing part partition pass passed passport password path pattern payload pci pcm ",
    "pcre pcrel pcshell pct pdf pearl peb peek peer pending per performance period periodic perl ",
    "permitted personal personalized phase phone pic picture pid pin pinned pinning pipe pipeline ",
    "pixbuf pixel pixels pixmap pkcs placement plane platform play please plt plugin plugins plural ",
    "png pns point pointer points policies policy poll poly pool pop port pos position posix post ",
    "power ppc pre precision prefix preinstall prelaunch prepare present presented preserved preset ",
    "prev preview previous primary print priority priv privacy private privilege privkey proc ",
    "process processing product profile prog program progress promotion prompt prop properties ",
    "property props protection protocol provide provided provider provisioning proxy psa pthread ptr ",
    "pts pubkey public pubnames pubtypes push pushing put pwa qio qtdemux quality quantity query ",
    "queue raise ramp random range ranges raptor raster rate raw rcv reactivated read reader ",
    "readiness reading ready real realloc reason rebar rec recall receive received recent reclaim ",
    "reclaimed recog record rect rectangle rects recv ref reference refresh reg regex region ",
    "register registered registration registry regkey regular rel rela relative release remove ",
    "render renderer rep replace reply report reported req request requested required requirements ",
    "requires res reserved reset resize resolution resolve resolver resource resources response ",
    "restart restore restored restriction result resume ret retail retry return returned rfc rgb ",
    "right ring rist rkns rnglists rns roaming rodata root routine row rows royalty rsa rtcp rtl ",
    "rtmp rtp rule rules run running runonce runtime rvng same sample samples sanitizer save saved ",
    "saver sax scale scaled scan scenario scoobe scope screen screentint script sdk sdl search ",
    "searchbutton searchcontrol sec second secondary section sections secure security see seek ",
    "segment segoe select selected selection selector self send sender sending sensitivity separate ",
    "separation seq sequence serialize serks server service services session set setting settings ",
    "setup sframe sgi sha shader shadow shake shape shared sheet shell shellcommon shells shift shm ",
    "short shortcut should show shown shutdown sid sig sign signal signature signed silent simple ",
    "since single sink site size sizeof skeleton skip skipped skipping sku sleep sli slice slot ",
    "small snapshot snd socket soft software solid soon sort sorted sound soundtouch source space ",
    "span sparc sparse spec special specified spi split spotlight spp spreadsheet src srt srtp ssd ",
    "sse ssl ssrc stab stable stabstr stack staged staging standard start started starting startup ",
    "stat state static statics stats status std steady stop storage store str stream streams string ",
    "strings stroke struct structure stub style sub subscribed subscription substitution success ",
    "successful suggestions sun sup support supported sure surface svg swap switch symbol symbolizer ",
    "symbols sync synth sys syscall system systray table tablet tag tags tail target targeted task ",
    "taskband taskbar tasklist tasks taskview tdata tdb teb telemetry template temporary term ",
    "terminate tesseract test tex text texture than that the them theme themes themeui there these ",
    "this thread threadpool threshold through ticks tid tile tilegx tilepro tiles time timed timeout ",
    "timer timestamp tint tip title tls token too toolbar top total touch tprel trace track traits ",
    "trans transaction transform transition transliterator transparency transport tray tree trie ",
    "trigger triggered true try trying turn twinui two txt txyewy type typenames types uac ubsan udk ",
    "uid uint uiv unable unattend unchecked under underflow undocked unelevated unexpected unicode ",
    "unified uniform uninitialized unique unit units unix unknown unlocalized unlock unmap ",
    "unrecognized unref unregister unsigned unsupported until update upgrade upgraded upgrading uprv ",
    "uri url urls usage use used user user32 uses using usr utf util utils uuid uwp val valid ",
    "validate value values var variable variant varnames vbi vec vector ven verify version vertex ",
    "video view virtual visible visio voice void volume vorbis vulkan wait waiting wallpaper want ",
    "warn warning was wasc watermark weaknames web website wekyb welcome were when which while why ",
    "widget width wil wildcard will win window windows winlogon winrt with within without wlan wnf ",
    "woah won workflow workstation wow wrap wrapper write writer writing wrong wsb wsx xaml xaw xcb ",
    "xkb xml xmlns yaml year yet you your zero zip znk zone zti ztin zts ztsn ztv ztvn zw ",
);

fn lexicon() -> &'static HashSet<&'static str> {
    static LEX: OnceLock<HashSet<&'static str>> = OnceLock::new();
    LEX.get_or_init(|| LEXICON.split_whitespace().collect())
}


fn fold_char(ch: char) -> Option<u8> {
    let r = match ch {
        'ą' | 'á' | 'à' | 'â' | 'ä' | 'ã' | 'å' | 'ā' => b'a',
        'Ą' | 'Á' | 'À' | 'Â' | 'Ä' | 'Ã' | 'Å' | 'Ā' => b'A',
        'ć' | 'č' | 'ç' | 'ĉ' => b'c',
        'Ć' | 'Č' | 'Ç' | 'Ĉ' => b'C',
        'ď' | 'đ' => b'd',
        'Ď' | 'Đ' => b'D',
        'ę' | 'é' | 'è' | 'ê' | 'ë' | 'ě' | 'ē' => b'e',
        'Ę' | 'É' | 'È' | 'Ê' | 'Ë' | 'Ě' | 'Ē' => b'E',
        'í' | 'ì' | 'î' | 'ï' | 'ī' => b'i',
        'Í' | 'Ì' | 'Î' | 'Ï' | 'Ī' => b'I',
        'ł' | 'ľ' | 'ĺ' => b'l',
        'Ł' | 'Ľ' | 'Ĺ' => b'L',
        'ń' | 'ň' | 'ñ' => b'n',
        'Ń' | 'Ň' | 'Ñ' => b'N',
        'ó' | 'ò' | 'ô' | 'ö' | 'õ' | 'ø' | 'ō' => b'o',
        'Ó' | 'Ò' | 'Ô' | 'Ö' | 'Õ' | 'Ø' | 'Ō' => b'O',
        'ř' | 'ŕ' => b'r',
        'Ř' | 'Ŕ' => b'R',
        'ś' | 'š' | 'ş' | 'ß' => b's',
        'Ś' | 'Š' | 'Ş' => b'S',
        'ť' | 'ţ' => b't',
        'Ť' | 'Ţ' => b'T',
        'ú' | 'ù' | 'û' | 'ü' | 'ů' | 'ū' => b'u',
        'Ú' | 'Ù' | 'Û' | 'Ü' | 'Ů' | 'Ū' => b'U',
        'ý' | 'ÿ' => b'y',
        'Ý' | 'Ÿ' => b'Y',
        'ź' | 'ż' | 'ž' => b'z',
        'Ź' | 'Ż' | 'Ž' => b'Z',
        _ => return None,
    };
    Some(r)
}

struct Norm<'a> {
    out: &'a mut Vec<u8>,
    pending: bool,
    started: bool,
}

impl<'a> Norm<'a> {
    fn feed(&mut self, b: u8) {
        if b == b' ' || b == b'\t' {
            if self.started {
                self.pending = true;
            }
            return;
        }
        self.started = true;
        if self.pending {
            self.out.push(b' ');
            self.pending = false;
        }
        self.out.push(b);
    }
}

fn normalize_into(s: &[u8], out: &mut Vec<u8>) {
    out.clear();
    let mut norm = Norm { out, pending: false, started: false };
    if s.is_ascii() {
        for &b in s {
            norm.feed(b);
        }
    } else if let Ok(text) = std::str::from_utf8(s) {
        for ch in text.chars() {
            if (ch as u32) < 128 {
                norm.feed(ch as u8);
            } else {
                norm.feed(fold_char(ch).unwrap_or(b' '));
            }
        }
    } else {
        for &b in s {
            norm.feed(if b < 128 { b } else { b' ' });
        }
    }
}


#[inline]
fn is_alpha(b: u8) -> bool {
    b.is_ascii_alphabetic()
}
#[inline]
fn is_digit(b: u8) -> bool {
    b.is_ascii_digit()
}
#[inline]
fn is_alnum(b: u8) -> bool {
    b.is_ascii_alphanumeric()
}
#[inline]
fn in_set(set: &[u8], b: u8) -> bool {
    set.contains(&b)
}
#[inline]
fn is_hex(b: u8) -> bool {
    b.is_ascii_hexdigit()
}

fn starts_with(t: &[u8], p: &[u8]) -> bool {
    t.len() >= p.len() && &t[..p.len()] == p
}

fn find_sub(h: &[u8], n: &[u8]) -> Option<usize> {
    if n.is_empty() || h.len() < n.len() {
        return None;
    }
    (0..=h.len() - n.len()).find(|&i| &h[i..i + n.len()] == n)
}


fn kind_url(t: &[u8]) -> bool {
    let k = match find_sub(t, b"://") {
        Some(k) => k,
        None => return false,
    };
    if k < 1 || k > 10 || !is_alpha(t[0]) {
        return false;
    }
    if !t[..k].iter().all(|&b| is_alnum(b) || in_set(b"+.-", b)) {
        return false;
    }
    let rest = &t[k + 3..];
    rest.len() >= 3 && !rest.iter().any(|&b| b == b' ' || b == b'\t' || b == b'\n')
}

fn kind_guid(t: &[u8]) -> bool {
    let mut g = t;
    if g.len() == 38 && g[0] == b'{' && g[37] == b'}' {
        g = &g[1..37];
    }
    if g.len() != 36 {
        return false;
    }
    for (i, &b) in g.iter().enumerate() {
        if i == 8 || i == 13 || i == 18 || i == 23 {
            if b != b'-' {
                return false;
            }
        } else if !is_hex(b) {
            return false;
        }
    }
    true
}

fn kind_ipv4(t: &[u8]) -> bool {
    let mut p = t;
    if let Some(ci) = t.iter().rposition(|&b| b == b':') {
        let port = &t[ci + 1..];
        if port.is_empty() || port.len() > 5 || !port.iter().all(|&b| is_digit(b)) {
            return false;
        }
        p = &t[..ci];
    }
    if p.len() < 7 {
        return false;
    }
    let mut parts = 0;
    for part in p.split(|&b| b == b'.') {
        parts += 1;
        if part.is_empty() || part.len() > 3 || !part.iter().all(|&b| is_digit(b)) {
            return false;
        }
        let v: u32 = part.iter().fold(0u32, |a, &b| a * 10 + (b - b'0') as u32);
        if v > 255 {
            return false;
        }
    }
    parts == 4
}

fn kind_hash(t: &[u8]) -> bool {
    let n = t.len();
    if !(n == 32 || n == 40 || n == 56 || n == 64 || n == 96 || n == 128) {
        return false;
    }
    if !t.iter().all(|&b| is_hex(b)) {
        return false;
    }
    let mut seen = [false; 128];
    let mut distinct = 0;
    for &b in t {
        let l = b.to_ascii_lowercase() as usize;
        if !seen[l] {
            seen[l] = true;
            distinct += 1;
        }
    }
    distinct >= 4
}

fn winpath_char_ok(b: u8) -> bool {
    is_alnum(b) || in_set(b" ._-{}()", b)
}

fn kind_winpath(t: &[u8]) -> bool {
    let n = t.len();
    if n >= 4 && is_alpha(t[0]) && t[1] == b':' && (t[2] == b'\\' || t[2] == b'/') {
        return true;
    }
    if starts_with(t, b"\\\\") && n >= 5 && is_alpha(t[2]) {
        return true;
    }
    if starts_with(t, b"\\??\\") || starts_with(t, b"\\Device\\") || starts_with(t, b"\\Registry\\") {
        return true;
    }
    if is_alpha(t[0]) && t.contains(&b'\\') {
        let segs: Vec<&[u8]> = t.split(|&b| b == b'\\').collect();
        if segs.len() >= 3
            && segs.iter().all(|s| !s.is_empty() && s.iter().all(|&b| winpath_char_ok(b)))
        {
            return true;
        }
    }
    false
}

fn kind_unixpath(t: &[u8]) -> bool {
    let n = t.len();
    if n < 5 {
        return false;
    }
    let body: &[u8] = if t[0] == b'/' {
        &t[1..]
    } else if starts_with(t, b"./") {
        &t[2..]
    } else if starts_with(t, b"../") {
        &t[3..]
    } else if starts_with(t, b"~/") {
        &t[2..]
    } else {
        return false;
    };
    let mut segs: Vec<&[u8]> = body.split(|&b| b == b'/').collect();
    if segs.last().map_or(false, |s| s.is_empty()) {
        segs.pop();
    }
    if segs.len() < 2 || segs.iter().any(|s| s.is_empty()) {
        return false;
    }
    if !segs.iter().all(|s| s.iter().all(|&b| is_alnum(b) || in_set(b"._+%@:~-", b))) {
        return false;
    }
    let alnum = t.iter().filter(|&&b| is_alnum(b)).count();
    alnum * 10 >= n * 6 && segs.iter().any(|s| s.len() >= 3)
}

fn kind_mangled(t: &[u8]) -> bool {
    let n = t.len();
    if n >= 6 && starts_with(t, b"_Z") && in_set(b"NLSKTv0123456789", t[2]) {
        return t.iter().all(|&b| is_alnum(b) || in_set(b"_$.", b));
    }
    if n >= 6 && t[0] == b'?' && find_sub(t, b"@@").is_some() {
        return t.iter().all(|&b| is_alnum(b) || in_set(b"_?@$", b));
    }
    false
}

fn kind_java(t: &[u8]) -> bool {
    let n = t.len();
    if n < 6 || !t.contains(&b'/') {
        return false;
    }
    if !t.iter().all(|&b| is_alnum(b) || in_set(b"_$/;()[<>", b)) {
        return false;
    }
    if t[0] == b'L' && t[n - 1] == b';' {
        return true;
    }
    const PREFIXES: [&[u8]; 6] = [b"java/", b"javax/", b"android/", b"kotlin/", b"org/", b"com/"];
    PREFIXES.iter().any(|p| starts_with(t, p))
}

fn kind_section(t: &[u8]) -> bool {
    let n = t.len();
    if n < 4 || n > 32 || t[0] != b'.' || !is_alpha(t[1]) {
        return false;
    }
    let ok = t[1..]
        .iter()
        .all(|&b| b.is_ascii_lowercase() || is_digit(b) || in_set(b"_.$-", b));
    ok && find_sub(t, b"..").is_none()
}

fn kind_base64(t: &[u8], lex_frac: f64) -> bool {
    let n = t.len();
    if n < 24 || n % 4 != 0 || lex_frac >= 0.3 {
        return false;
    }
    let mut body_len = n;
    while body_len > 0 && t[body_len - 1] == b'=' {
        body_len -= 1;
    }
    if n - body_len > 2 {
        return false;
    }
    let body = &t[..body_len];
    if !body.iter().all(|&b| is_alnum(b) || b == b'+' || b == b'/') {
        return false;
    }
    let has_upper = body.iter().any(|b| b.is_ascii_uppercase());
    let has_lower = body.iter().any(|b| b.is_ascii_lowercase());
    let has_digit = body.iter().any(|&b| is_digit(b));
    let mut seen = [false; 128];
    let mut distinct = 0;
    for &b in body {
        if !seen[b as usize] {
            seen[b as usize] = true;
            distinct += 1;
        }
    }
    has_upper && has_lower && has_digit && distinct >= 12
}

fn kind_banner(t: &[u8]) -> bool {
    starts_with(t, b"GCC: (")
        || find_sub(t, b" clang version ").is_some()
        || starts_with(t, b"clang version ")
        || starts_with(t, b"rustc version ")
}

fn classify_kind(t: &[u8], lex_frac: f64) -> Kind {
    if kind_url(t) {
        Kind::Url
    } else if kind_guid(t) {
        Kind::Guid
    } else if kind_ipv4(t) {
        Kind::Ipv4
    } else if kind_hash(t) {
        Kind::Hash
    } else if kind_winpath(t) {
        Kind::WinPath
    } else if kind_unixpath(t) {
        Kind::UnixPath
    } else if kind_mangled(t) {
        Kind::Mangled
    } else if kind_java(t) {
        Kind::Java
    } else if kind_section(t) {
        Kind::Section
    } else if kind_base64(t, lex_frac) {
        Kind::Base64
    } else if kind_banner(t) {
        Kind::Banner
    } else {
        Kind::None
    }
}


const SCRIPTS: [(u32, u32); 9] = [
    (0x0370, 0x03FF),
    (0x0400, 0x04FF),
    (0x0590, 0x05FF),
    (0x0600, 0x06FF),
    (0x0E00, 0x0E7F),
    (0x3040, 0x309F),
    (0x30A0, 0x30FF),
    (0x4E00, 0x9FFF),
    (0xAC00, 0xD7AF),
];

fn script_idx(ch: char) -> Option<usize> {
    let o = ch as u32;
    SCRIPTS.iter().position(|&(lo, hi)| lo <= o && o <= hi)
}

fn kind_script(text: &str) -> bool {
    let mut non_space = 0usize;
    let mut letters = 0usize;
    let mut seen: u32 = 0;
    let mut any_non_ascii = false;
    for ch in text.chars() {
        if (ch as u32) >= 128 {
            any_non_ascii = true;
        }
        if ch == ' ' || ch == '\t' || ch == '\r' || ch == '\n' {
            continue;
        }
        non_space += 1;
        if let Some(i) = script_idx(ch) {
            letters += 1;
            seen |= 1 << i;
        }
    }
    any_non_ascii && non_space >= 4 && letters * 10 >= non_space * 7 && seen.count_ones() <= 2
}

fn kind_diacritic(text: &str) -> bool {
    let mut non_space = 0usize;
    let mut letters = 0usize;
    let mut dia = 0usize;
    let mut any_non_ascii = false;
    for ch in text.chars() {
        if ch == ' ' || ch == '\t' || ch == '\r' || ch == '\n' {
            continue;
        }
        non_space += 1;
        if (ch as u32) >= 128 {
            any_non_ascii = true;
            if fold_char(ch).is_some() {
                dia += 1;
                letters += 1;
            } else {
                return false;
            }
        } else if ch.is_ascii_alphabetic() {
            letters += 1;
        }
    }
    any_non_ascii && non_space >= 4 && dia >= 2 && letters * 10 >= non_space * 7
}


fn fmt_count(t: &[u8]) -> usize {
    let n = t.len();
    let mut i = 0;
    let mut cnt = 0;
    while i < n {
        if t[i] != b'%' {
            i += 1;
            continue;
        }
        i += 1;
        if i < n && t[i] == b'%' {
            i += 1;
            continue;
        }
        while i < n && in_set(b"-+ #0", t[i]) {
            i += 1;
        }
        if i < n && t[i] == b'*' {
            i += 1;
        } else {
            while i < n && is_digit(t[i]) {
                i += 1;
            }
        }
        if i < n && t[i] == b'.' {
            i += 1;
            if i < n && t[i] == b'*' {
                i += 1;
            } else {
                while i < n && is_digit(t[i]) {
                    i += 1;
                }
            }
        }
        while i < n && in_set(b"hlLqjzt", t[i]) {
            i += 1;
        }
        if i < n && in_set(b"diouxXeEfFgGaAcsSpn", t[i]) {
            cnt += 1;
            i += 1;
        }
    }
    cnt
}


fn opcode_noise(t: &[u8]) -> bool {
    if t.len() > 24 || t.contains(&b' ') {
        return false;
    }
    if t.iter().any(|b| b.is_ascii_lowercase()) {
        return false;
    }
    let mut pairs = 0;
    for i in 0..t.len() - 1 {
        if t[i] == b'A' && in_set(b"TUVW\\]^_", t[i + 1]) {
            pairs += 1;
        }
    }
    pairs >= 2
}

fn seq_noise(low: &[u8]) -> bool {
    let n = low.len();
    if n < 6 || n >= 40 {
        return false;
    }
    let (mut asc, mut desc) = (0usize, 0usize);
    for i in 1..n {
        let a = low[i - 1] as i32;
        let b = low[i] as i32;
        if b - a == 1 {
            asc += 1;
        }
        if a - b == 1 {
            desc += 1;
        }
    }
    if asc.max(desc) * 5 >= 4 * (n - 1) {
        return true;
    }
    const KB: &[u8] = b"qwertyuiopasdfghjklzxcvbnm";
    const KB_REV: &[u8] = b"mnbvcxzlkjhgfdsapoiuytrewq";
    find_sub(KB, low).is_some() || find_sub(KB_REV, low).is_some()
}


fn legacy_parts(m: &TrigramModel, c: &[u8], mut tv: Option<&mut Vec<f32>>) -> f64 {
    let n = c.len();
    let mut like = m.begin[idx2(c[0], c[1])] as f64;
    if let Some(v) = tv.as_mut() {
        v.clear();
    }
    for i in 3..n {
        let x = m.trigram[idx3(c[i - 2], c[i - 1], c[i])];
        like += x as f64;
        if let Some(v) = tv.as_mut() {
            v.push(x);
        }
    }
    like += m.end[idx2(c[n - 2], c[n - 1])] as f64;
    like / n as f64
}

struct TokAcc {
    tot: usize,
    lexl: usize,
    ws: f64,
    wl: usize,
    ntok: usize,
    nshort: usize,
    pass: usize,
}

fn tok_flush(
    m: &TrigramModel,
    lex: &HashSet<&'static str>,
    t: &[u8],
    start: usize,
    end: usize,
    tok: &mut Vec<u8>,
    acc: &mut TokAcc,
) {
    if end <= start {
        return;
    }
    let len = end - start;
    tok.clear();
    tok.extend(t[start..end].iter().map(|b| b.to_ascii_lowercase()));
    acc.tot += len;
    acc.ntok += 1;
    if len <= 2 {
        acc.nshort += 1;
    }
    let in_lex = match std::str::from_utf8(&tok[..]) {
        Ok(w) => lex.contains(w),
        Err(_) => false,
    };
    if in_lex {
        acc.lexl += len;
    }
    if len >= 4 {
        let avg = legacy_parts(m, &tok[..], None);
        acc.ws += len as f64 * avg;
        acc.wl += len;
        if in_lex || avg > thr(len) - 1.0 {
            acc.pass += len;
        }
    } else if in_lex {
        acc.pass += len;
    }
}

fn scan_tokens(
    m: &TrigramModel,
    lex: &HashSet<&'static str>,
    t: &[u8],
    tok: &mut Vec<u8>,
) -> TokAcc {
    let mut acc = TokAcc { tot: 0, lexl: 0, ws: 0.0, wl: 0, ntok: 0, nshort: 0, pass: 0 };
    let mut start = 0usize;
    let mut end = 0usize;
    for i in 0..t.len() {
        let ch = t[i];
        if !is_alpha(ch) {
            tok_flush(m, lex, t, start, end, tok, &mut acc);
            start = i + 1;
            end = i + 1;
            continue;
        }
        if end > start {
            let p = t[i - 1];
            if p.is_ascii_lowercase() && ch.is_ascii_uppercase() {
                tok_flush(m, lex, t, start, end, tok, &mut acc);
                start = i;
            } else if p.is_ascii_uppercase()
                && ch.is_ascii_lowercase()
                && end - start >= 2
                && t[i - 2].is_ascii_uppercase()
            {
                tok_flush(m, lex, t, start, i - 1, tok, &mut acc);
                start = i - 1;
            }
        } else {
            start = i;
        }
        end = i + 1;
    }
    tok_flush(m, lex, t, start, end, tok, &mut acc);
    acc
}


fn llr_features(low: &[u8]) -> (f64, f64, f64) {
    let n = low.len();
    let tri_tab = &LLR_BIN[..LLR_TRI_LEN];
    let bi_tab = &LLR_BIN[LLR_TRI_LEN..];
    let nt = n - 2;
    let q = |i: usize| -> i64 { tri_tab[idx3(low[i - 2], low[i - 1], low[i])] as i8 as i64 };
    let mut sum: i64 = 0;
    for i in 2..n {
        sum += q(i);
    }
    let tri_avg = sum as f64 * LLR_STEP / nt as f64;
    let w = 6usize;
    let win = if nt <= w {
        tri_avg
    } else {
        let mut s: i64 = 0;
        for i in 2..(2 + w) {
            s += q(i);
        }
        let mut best = s;
        for i in (2 + w)..n {
            s += q(i) - q(i - w);
            if s < best {
                best = s;
            }
        }
        best as f64 * LLR_STEP / w as f64
    };
    let mut bs: i64 = 0;
    for i in 1..n {
        bs += bi_tab[idx2(low[i - 1], low[i])] as i8 as i64;
    }
    let bi_avg = bs as f64 * LLR_STEP / (n - 1) as f64;
    (clamp(tri_avg, -4.0, 4.0), clamp(win, -6.0, 6.0), clamp(bi_avg, -3.0, 3.0))
}


#[inline]
fn clamp(x: f64, lo: f64, hi: f64) -> f64 {
    if x < lo {
        lo
    } else if x > hi {
        hi
    } else {
        x
    }
}

#[inline]
fn sigmoid(x: f64) -> f64 {
    if x >= 0.0 {
        1.0 / (1.0 + (-x).exp())
    } else {
        let e = x.exp();
        e / (1.0 + e)
    }
}

fn analyze_normalized(s: &[u8], ctx: Context, sc: &mut Scratch) -> Option<Verdict> {
    normalize_into(s, &mut sc.t);
    if sc.t.len() > MAX_ANALYZE {
        sc.t.truncate(MAX_ANALYZE);
    }
    let n = sc.t.len();
    if n < 4 {
        return None;
    }
    let m = model();
    let lex = lexicon();
    let Scratch { t, low, tv, tok } = sc;
    let t: &[u8] = &t[..];

    low.clear();
    low.extend(t.iter().map(|b| b.to_ascii_lowercase()));
    let avg = legacy_parts(m, &low[..], Some(&mut *tv));
    let tvs: &[f32] = &tv[..];
    let margin = avg - thr(n);

    let win_min = if tvs.len() <= 8 {
        let s: f64 = tvs.iter().map(|&x| x as f64).sum();
        s / tvs.len() as f64
    } else {
        let mut s: f64 = tvs[..8].iter().map(|&x| x as f64).sum();
        let mut best = s;
        for j in 8..tvs.len() {
            s += tvs[j] as f64 - tvs[j - 8] as f64;
            if s < best {
                best = s;
            }
        }
        best / 8.0
    };
    let unseen = tvs.iter().filter(|&&x| x == m.zero_log).count() as f64 / tvs.len() as f64;

    let mut seen = [false; 128];
    let mut distinct = 0usize;
    for &b in low.iter() {
        if !seen[b as usize] {
            seen[b as usize] = true;
            distinct += 1;
        }
    }
    let dist = distinct as f64 / n as f64;

    let mut run = 1usize;
    let mut mx = 1usize;
    for i in 1..n {
        if t[i] == t[i - 1] {
            run += 1;
            if run > mx {
                mx = run;
            }
        } else {
            run = 1;
        }
    }
    let mut periodic = 0.0f64;
    for p in 1..=4usize {
        if n > p {
            let k = (p..n).filter(|&i| t[i] == t[i - p]).count();
            let frac = k as f64 / (n - p) as f64;
            if frac > periodic {
                periodic = frac;
            }
        }
    }

    let (mut alpha_c, mut digit_c, mut upper_c, mut space_c, mut punct_c) =
        (0usize, 0usize, 0usize, 0usize, 0usize);
    for &b in t {
        if is_alpha(b) {
            alpha_c += 1;
            if b.is_ascii_uppercase() {
                upper_c += 1;
            }
        } else if is_digit(b) {
            digit_c += 1;
        } else if b == b' ' {
            space_c += 1;
        } else if b != b'\n' && b != b'\r' && b != b'\t' {
            punct_c += 1;
        }
    }
    let nf = n as f64;

    let (mut letters, mut vowels) = (0usize, 0usize);
    for &b in low.iter() {
        if b.is_ascii_lowercase() {
            letters += 1;
            if in_set(b"aeiou", b) {
                vowels += 1;
            }
        }
    }
    let vowel_dev = if letters >= 3 {
        (vowels as f64 / letters as f64 - 0.38).abs()
    } else {
        0.0
    };

    let acc = scan_tokens(m, lex, t, tok);
    let lex_frac = if acc.tot > 0 { acc.lexl as f64 / acc.tot as f64 } else { 0.0 };
    let tok_score = if acc.wl > 0 { acc.ws / acc.wl as f64 } else { -5.0 };

    let (mut flips, mut pairs) = (0usize, 0usize);
    for i in 1..n {
        if is_alpha(t[i]) && is_alpha(t[i - 1]) {
            pairs += 1;
            if (t[i] < b'a') != (t[i - 1] < b'a') {
                flips += 1;
            }
        }
    }
    let case_flips = if pairs > 0 { flips as f64 / pairs as f64 } else { 0.0 };

    let f0 = t[0];
    let l0 = t[n - 1];
    let bad_start = !(is_alpha(f0) || is_digit(f0) || in_set(b"\"'([{/%<._-~\\$@#:", f0));
    let bad_end = !(is_alpha(l0) || is_digit(l0) || in_set(b"\"')]}>.:;!?\n\r/%", l0));

    let tok_len = if acc.ntok > 0 { clamp(acc.tot as f64 / acc.ntok as f64, 0.0, 12.0) } else { 0.0 };
    let tok_short = if acc.ntok > 0 { acc.nshort as f64 / acc.ntok as f64 } else { 0.0 };
    let tok_pass = if acc.tot > 0 { acc.pass as f64 / acc.tot as f64 } else { 0.0 };
    let (llr_tri, llr_win6, llr_bi) = llr_features(&low[..]);

    let feats: [f64; NFEAT] = [
        (n.min(200) as f64).ln(),
        clamp(margin, -6.0, 6.0),
        clamp(avg, -9.0, -1.0),
        clamp(win_min, -9.0, -1.0),
        unseen,
        dist,
        mx as f64 / nf,
        periodic,
        alpha_c as f64 / nf,
        digit_c as f64 / nf,
        upper_c as f64 / nf,
        punct_c as f64 / nf,
        space_c as f64 / nf,
        vowel_dev,
        lex_frac,
        clamp(tok_score, -9.0, -1.0),
        if opcode_noise(t) { 1.0 } else { 0.0 },
        case_flips,
        (bad_start as u8 + bad_end as u8) as f64,
        if fmt_count(t) > 0 { 1.0 } else { 0.0 },
        tok_len,
        tok_short,
        tok_pass,
        llr_tri,
        llr_win6,
        llr_bi,
    ];

    let kind = classify_kind(t, lex_frac);
    let conf = if let Some(c) = kind.fixed_conf() {
        c
    } else if (n >= 8 && feats[7] >= 0.85) || seq_noise(&low[..]) {
        0.05
    } else {
        let mut z = BIAS;
        for i in 0..NFEAT {
            z += WEIGHTS[i] * feats[i];
        }
        if ctx.has_xref {
            z += CTX_XREF;
        }
        if ctx.in_code_section {
            z += CTX_CODE_SECTION;
        }
        if ctx.nul_terminated {
            z += CTX_NUL_TERMINATED;
        }
        if ctx.preceded_by_nul {
            z += CTX_PRECEDED_BY_NUL;
        }
        sigmoid(z)
    };

    Some(Verdict {
        accepted: kind != Kind::None
            || conf >= accept_threshold(n)
            || (margin > 0.0 && conf >= HYBRID_FLOOR),
        confidence: conf as f32,
        kind,
        len: n,
    })
}


#[cfg(test)]
const GOLDEN: &[(&str, bool, f32)] = &[
    ("kernel32.dll", true, 0.9951),
    ("GetProcAddress", true, 0.9900),
    ("VirtualAllocEx", true, 0.8867),
    ("/usr/lib/libc.so.6", true, 0.9300),
    ("%s: error %d\n", true, 0.9986),
    ("std::vector<int>", true, 0.9950),
    ("C:\\Windows\\System32\\cmd.exe", true, 0.9700),
    ("SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run", true, 0.9700),
    ("https://example.com/api/v1/users", true, 0.9800),
    ("Content-Type: application/json", true, 0.9967),
    ("__libc_start_main", true, 0.9965),
    ("_ZN3foo3barEv", true, 0.9500),
    (".text", true, 0.9000),
    (".rdata", true, 0.9000),
    ("<init>", true, 0.9986),
    ("printf", true, 0.9740),
    ("0x%08x", true, 0.9931),
    ("%-20s %10d", true, 0.7626),
    ("java/lang/String", true, 0.9300),
    ("Ljava/lang/Object;", true, 0.9300),
    ("GCC: (Ubuntu 11.4.0-1ubuntu1~22.04) 11.4.0", true, 0.9000),
    ("192.168.1.1", true, 0.9000),
    ("admin123", true, 0.9969),
    ("wsprintfA", true, 0.3502),
    ("Za\u{17c}\u{f3}\u{142}\u{107} g\u{119}\u{15b}l\u{105} ja\u{17a}\u{144}", true, 0.7500),
    ("{8E3F2A1B-4C5D-6E7F-8091-A2B3C4D5E6F7}", true, 0.9700),
    ("d41d8cd98f00b204e9800998ecf8427e", true, 0.9000),
    ("Error: cannot open file", true, 0.9959),
    ("hello world", true, 0.6464),
    ("Loading configuration file", true, 0.9964),
    ("NtAllocateVirtualMemory", true, 0.9802),
    ("ERROR: connection refused", true, 0.9910),
    ("password", true, 0.9978),
    ("error", true, 0.9997),
    ("UAWAVAUATSH", false, 0.0002),
    ("AWAVAUATUSH", false, 0.0012),
    ("[]A\\A]A^A_", false, 0.0000),
    ("ABCDEFGHIJKLMNOPQRSTUVWXYZ", false, 0.0500),
    ("abcdefghijklmnopqrstuvwxyz0123456789", false, 0.0500),
    ("AAAAAAAAAAAA", false, 0.0500),
    ("inininininin", false, 0.0500),
    ("rererererere", false, 0.0500),
    ("qwertyuiop", false, 0.0500),
    ("l$0H", false, 0.0004),
    ("D$@H", false, 0.0006),
    ("xk7Qp9", false, 0.2516),
    ("aZ9&xQ2%k#", false, 0.0001),
    ("##########", false, 0.0500),
    ("tttttttttt", false, 0.0500),
    ("ing ing ing ing", false, 0.0500),
    ("xzqx", false, 0.1046),
    ("H9\\$", false, 0.0004),
    ("t$ H", false, 0.0002),
    ("UVWATAUAVAWH", false, 0.0001),
    ("cmu_us_awb_single_mcep_y_195_cart", true, 0.9233),
    ("FAKE_SHELL", true, 0.9591),
    ("Downstream supports %lu profiles", true, 0.9714),
    ("visual_audio_sample_format_is_signed", true, 0.9944),
    ("NTLM single-sign-on using %s failed", true, 0.9954),
    ("Vorbis: Granule position is nonsensical! (Missing end-of-stream marker?)\n", true, 0.9565),
    ("GSS_C_NT_STRING_UID_NAME", true, 0.9868),
    ("MFXVideoDECODE::Init returned warning %d (%s)", true, 0.9976),
    ("s2i_ASN1_INTEGER", true, 0.9767),
    ("  Requested %u bytes.\n", true, 0.9995),
    ("show filtered stream data", true, 0.9737),
    ("NormalizeCounts(counts.data(), &omit_pos, alphabet_size, ANS_LOG_TAB_SIZE, shift, &num_symbols, symbols)", true, 0.9827),
    ("0123456789ab", false, 0.0500),
    (": control character in string (missing \"?)", true, 0.9978),
    (" master=%lld ", true, 0.9946),
    ("index < props_to_use.size()", true, 0.9900),
    ("group-check", true, 0.9979),
    ("SOUP_GSSAPI_BLOCKLISTED_URIS", true, 0.6859),
    ("HINTversion", true, 0.9152),
    ("visual_timer_reset", true, 0.9913),
    ("\tspecify HW counter profiling for up to %u HW counters\n", true, 0.9435),
    ("CompareHuffmanTrees", true, 0.7932),
    ("EVP_DigestSignInit", true, 0.9810),
    ("\nMessage Digest commands (see the `dgst' command for more details)\n", true, 0.9705),
    ("qpdf_force_pdf_version_and_extension", true, 0.9978),
    (" ignore_corruption", true, 0.9897),
    ("vorbis_version_string", true, 0.9994),
    ("Taking EVENT lock from thread %p", true, 0.9949),
    ("mnt_table_parse_file", true, 0.9987),
    ("Is Options Ping", true, 0.9601),
    ("E9w\\", false, 0.0003),
    ("K,AU", false, 0.0258),
    (";N |", false, 0.0006),
    ("emdlt", false, 0.6077),
    ("ASARAVAWV", false, 0.0019),
    ("AVWAQI", false, 0.0043),
    ("L$$%", false, 0.0051),
    ("Pd 4", false, 0.0037),
    ("o5g?", false, 0.0065),
    ("L$ME", false, 0.0170),
    ("\rKu\n", false, 0.0002),
    ("%Vc\n", false, 0.0066),
    ("~\tMc", false, 0.0000),
    ("tp9X8~", false, 0.0016),
    ("o\r(e", false, 0.0021),
    ("u_H;", false, 0.0483),
    ("<0A;>t H", false, 0.0003),
    ("x0H9u8", false, 0.0000),
    ("uO[A\\A]A^]", false, 0.0000),
    ("GLib.LisI9U", false, 0.0297),
    ("|H(H", false, 0.0005),
    ("|H(\rlG$", false, 0.0000),
    ("H;8~)fH", false, 0.0002),
    ("XoJ3", false, 0.0020),
    ("tXHc}", false, 0.0002),
    ("\rg9p", false, 0.0049),
    ("}\rE)", false, 0.0093),
    ("~[U1", false, 0.0331),
    ("A;\\$4r", false, 0.0004),
    ("L;l0", false, 0.0031),
];

#[cfg(test)]
mod tests {
    use super::*;


    #[test]
    fn model_loads() {
        let m = model();
        assert!(m.n_trigram > 0);
        assert!(m.n_begin > 100);
        assert!(m.n_end > 100);
        assert!(m.zero_log < 0.0);
    }

    #[test]
    fn real_words_pass() {
        assert!(is_probable_string("This is a test string"));
        assert!(is_probable_string("hello world"));
        assert!(is_probable_string("Loading configuration file"));
        assert!(is_probable_string("The quick brown fox jumps over the lazy dog"));
    }

    #[test]
    fn garbage_fails() {
        assert!(!is_probable_string("l$0H"));
        assert!(!is_probable_string("fff"));
        assert!(!is_probable_string("aZ9&xQ2%k#"));
        assert!(!is_probable_string("##########"));
        assert!(!is_probable_string("0x1F3A9B2C"));
    }

    #[test]
    fn score_probable_agrees_with_gate() {
        for s in ["hello world", "l$0H", "Loading configuration file", "##########", "xzqx"] {
            assert_eq!(score_probable(s.as_bytes()).is_some(), is_probable_string(s), "{s}");
            if let Some(sc) = score_probable(s.as_bytes()) {
                assert_eq!(sc, string_score(s));
            }
        }
    }

    #[test]
    fn short_strings_are_strict() {
        assert!(is_probable_string("hello"));
        assert!(is_probable_string("happy"));
        assert!(!is_probable_string("xzqx"));
        assert!(!is_probable_string("l$0H"));
    }


    #[test]
    fn llr_table_has_expected_size_and_sign() {
        assert_eq!(LLR_BIN.len(), LLR_TRI_LEN + LLR_BI_LEN);
        let good = LLR_BIN[idx3(b't', b'h', b'e')] as i8;
        let junk = LLR_BIN[idx3(b'$', b'0', b'h')] as i8;
        assert!(good > junk, "llr(the)={good} should exceed llr($0h)={junk}");
    }

    #[test]
    fn golden_vectors_match_reference() {
        assert!(!GOLDEN.is_empty(), "run tools/gen_rust.py to generate the golden vectors");
        for &(s, accepted, conf) in GOLDEN {
            let v = analyze(s.as_bytes(), Context::default())
                .unwrap_or_else(|| panic!("no verdict for {s:?}"));
            assert_eq!(v.accepted, accepted, "accepted mismatch for {s:?}: {v:?}");
            assert!(
                (v.confidence - conf).abs() < 0.02,
                "confidence mismatch for {s:?}: got {} expected {conf}",
                v.confidence
            );
        }
    }

    #[test]
    fn structured_strings_are_recognised() {
        let cases: [(&str, Kind); 11] = [
            ("https://example.com/api/v1/users", Kind::Url),
            ("{8E3F2A1B-4C5D-6E7F-8091-A2B3C4D5E6F7}", Kind::Guid),
            ("192.168.1.1", Kind::Ipv4),
            ("d41d8cd98f00b204e9800998ecf8427e", Kind::Hash),
            ("C:\\Windows\\System32\\cmd.exe", Kind::WinPath),
            ("/usr/lib/libc.so.6", Kind::UnixPath),
            ("_ZN3foo3barEv", Kind::Mangled),
            ("Ljava/lang/Object;", Kind::Java),
            (".eh_frame", Kind::Section),
            ("GCC: (Ubuntu 11.4.0-1ubuntu1~22.04) 11.4.0", Kind::Banner),
            ("Файл не найден", Kind::Script),
        ];
        for &(s, kind) in cases.iter() {
            let v = analyze(s.as_bytes(), Context::default()).unwrap();
            assert_eq!(v.kind, kind, "{s}");
            assert!(v.accepted, "{s}");
        }
    }

    #[test]
    fn opcode_alphabet_and_repetition_junk_is_rejected() {
        for s in [
            "UAWAVAUATSH",
            "AWAVAUATUSH",
            "[]A\\A]A^A_",
            "ABCDEFGHIJKLMNOPQRSTUVWXYZ",
            "abcdefghijklmnopqrstuvwxyz0123456789",
            "AAAAAAAAAAAA",
            "inininininin",
            "ing ing ing ing",
            "qwertyuiop",
            "l$0H",
        ] {
            assert!(!is_string(s.as_bytes()), "{s} should be rejected");
        }
    }

    #[test]
    fn binary_flavoured_strings_pass() {
        for s in ["0x%08x", "%-20s %10d", "<init>", "wsprintfA", "GetProcAddress", "__libc_start_main"] {
            assert!(is_string(s.as_bytes()), "{s} should be accepted");
        }
    }

    #[test]
    fn diacritics_are_folded_not_blanked() {
        let v = analyze("Zażółć gęślą jaźń".as_bytes(), Context::default()).unwrap();
        assert!(v.accepted);
        assert_eq!(v.kind, Kind::Diacritic);
    }

    #[test]
    fn context_moves_confidence_the_right_way() {
        let s = b"wsprintfA";
        let base = analyze(s, Context::default()).unwrap().confidence;
        let xref = analyze(s, Context { has_xref: true, ..Context::default() }).unwrap().confidence;
        let code = analyze(s, Context { in_code_section: true, ..Context::default() })
            .unwrap()
            .confidence;
        assert!(xref > base, "xref {xref} should exceed base {base}");
        assert!(code < base, "code-section {code} should be below base {base}");
    }

    #[test]
    fn too_short_has_no_verdict() {
        assert!(analyze(b"abc", Context::default()).is_none());
        assert!(analyze(b"  a  ", Context::default()).is_none());
    }
}