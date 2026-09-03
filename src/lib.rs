use clap::{Parser, Subcommand, ValueEnum};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::env;
use std::ffi::{OsStr, OsString};
use std::fs;
use std::io::{self, Read};
use std::path::{Path, PathBuf};
use std::process::Command;

const SCHEMA_VERSION: u8 = 1;
const MAX_PATH_ENTRIES: usize = 256;
const MAX_SCAN_RECORDS: usize = 512;
const MAX_DIRECTORY_ENTRIES: usize = 2048;
const MAX_FILE_BYTES: u64 = 8 * 1024 * 1024;
const MAX_MODULE_DEPTH: usize = 32;
const MAX_SYMLINK_DEPTH: usize = 16;

#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum)]
pub enum OutputFormat {
    Text,
    Json,
    Jsonl,
}

#[derive(Debug, Parser)]
#[command(
    name = "agent-env",
    version,
    about = "Inspect local binaries, packages, modules, and source origins"
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Debug, Subcommand)]
enum Commands {
    Which {
        program: String,
        #[arg(long, value_enum, default_value = "text")]
        format: OutputFormat,
    },
    Owner {
        path: PathBuf,
        #[arg(long)]
        manifest_path: Option<PathBuf>,
        #[arg(long, value_enum, default_value = "text")]
        format: OutputFormat,
    },
    Module {
        module: String,
        #[arg(long)]
        manifest_path: Option<PathBuf>,
        #[arg(long, value_enum, default_value = "text")]
        format: OutputFormat,
    },
    Scan {
        #[arg(long, value_enum, default_value = "jsonl")]
        format: OutputFormat,
        #[arg(long)]
        manifest_path: Option<PathBuf>,
        #[arg(long)]
        output: Option<PathBuf>,
    },
    Version,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Fact {
    pub schema_version: u8,
    pub kind: String,
    pub key: String,
    pub state: String,
    pub details: BTreeMap<String, String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct WhichCandidate {
    pub path: String,
    pub state: String,
    pub executable: bool,
    pub symlink_target: Option<String>,
    pub error: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct WhichReport {
    pub schema_version: u8,
    pub tool: String,
    pub program: String,
    pub selected: Option<String>,
    pub candidates: Vec<WhichCandidate>,
    pub state: String,
    pub reason: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct OwnerReport {
    pub schema_version: u8,
    pub tool: String,
    pub path: String,
    pub owner: Option<String>,
    pub manifest: Option<String>,
    pub source: Option<String>,
    pub inside_project_boundary: Option<bool>,
    pub state: String,
    pub reason: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ModuleReport {
    pub schema_version: u8,
    pub tool: String,
    pub module: String,
    pub package: Option<String>,
    pub source_file: Option<String>,
    pub origin: Option<String>,
    pub state: String,
    pub reason: String,
}

#[derive(Debug, Deserialize)]
struct CargoMetadata {
    #[serde(default)]
    packages: Vec<CargoPackage>,
    workspace_root: String,
}

#[derive(Debug, Deserialize)]
struct CargoPackage {
    name: String,
    version: String,
    manifest_path: String,
    source: Option<String>,
    #[serde(default)]
    dependencies: Vec<CargoDependency>,
    #[serde(default)]
    targets: Vec<CargoTarget>,
}

#[derive(Debug, Deserialize)]
struct CargoDependency {
    name: String,
    req: String,
    source: Option<String>,
    kind: Option<String>,
    target: Option<String>,
}

#[derive(Debug, Deserialize)]
struct CargoTarget {
    name: String,
    #[serde(default)]
    kind: Vec<String>,
    src_path: String,
}

#[derive(Debug)]
struct CandidateInspection {
    candidate: WhichCandidate,
}

pub fn entry<I, T>(args: I) -> i32
where
    I: IntoIterator<Item = T>,
    T: Into<OsString> + Clone,
{
    let cli = match Cli::try_parse_from(args) {
        Ok(cli) => cli,
        Err(error) => {
            let code = error.exit_code();
            let _ = error.print();
            return code;
        }
    };

    match run(cli) {
        Ok(()) => 0,
        Err(error) => {
            eprintln!("agent-env: {error}");
            2
        }
    }
}

fn run(cli: Cli) -> Result<(), String> {
    match cli.command {
        Commands::Which { program, format } => {
            let report = resolve_program(&program, None);
            emit_serialized(&report, format)
        }
        Commands::Owner {
            path,
            manifest_path,
            format,
        } => {
            let report = inspect_owner_path(&path, manifest_path.as_deref());
            emit_serialized(&report, format)
        }
        Commands::Module {
            module,
            manifest_path,
            format,
        } => {
            let report = inspect_module_path(&module, manifest_path.as_deref());
            emit_serialized(&report, format)
        }
        Commands::Scan {
            format,
            manifest_path,
            output,
        } => {
            let records = scan_project(manifest_path.as_deref());
            let rendered = render_facts(&records, format)?;
            if let Some(output) = output {
                write_verified(&output, &rendered)
            } else {
                print!("{rendered}");
                Ok(())
            }
        }
        Commands::Version => {
            println!("agent-env {}", env!("CARGO_PKG_VERSION"));
            Ok(())
        }
    }
}

fn emit_serialized<T: Serialize>(value: &T, format: OutputFormat) -> Result<(), String> {
    match format {
        OutputFormat::Json | OutputFormat::Jsonl => {
            println!(
                "{}",
                serde_json::to_string(value).map_err(|error| error.to_string())?
            );
        }
        OutputFormat::Text => {
            if let Ok(report) = serde_json::to_value(value) {
                print_text_value(&report);
            }
        }
    }
    Ok(())
}

fn print_text_value(value: &serde_json::Value) {
    if let Some(object) = value.as_object() {
        for (key, value) in object {
            if let Some(array) = value.as_array() {
                println!("{key}:");
                for item in array {
                    println!("- {item}");
                }
            } else if value.is_null() {
                println!("{key}: unresolved");
            } else {
                println!("{key}: {value}");
            }
        }
    } else {
        println!("{value}");
    }
}

pub fn redact_url_credentials(value: &str) -> String {
    let Some(separator) = value.find("://") else {
        return value.to_owned();
    };
    let authority_start = separator + 3;
    let authority_end = value[authority_start..]
        .find(['/', '?', '#'])
        .map(|offset| authority_start + offset)
        .unwrap_or(value.len());
    let authority = &value[authority_start..authority_end];
    let Some(at) = authority.rfind('@') else {
        return value.to_owned();
    };
    let suffix = &value[authority_start + at + 1..authority_end];
    format!(
        "{}<redacted>@{}{}",
        &value[..authority_start],
        suffix,
        &value[authority_end..]
    )
}

pub fn redact_value(key: &str, value: &str) -> String {
    let normalized = key.to_ascii_lowercase();
    let secret = [
        "token",
        "password",
        "secret",
        "credential",
        "api_key",
        "private_key",
        "authorization",
    ]
    .iter()
    .any(|part| normalized.contains(part));
    if secret {
        "<redacted>".to_owned()
    } else {
        redact_url_credentials(value)
    }
}

pub fn resolve_program(program: &str, path_override: Option<&OsStr>) -> WhichReport {
    if program.trim().is_empty() {
        return WhichReport {
            schema_version: SCHEMA_VERSION,
            tool: "agent-env".to_owned(),
            program: program.to_owned(),
            selected: None,
            candidates: Vec::new(),
            state: "unresolved".to_owned(),
            reason: "program name is empty".to_owned(),
        };
    }

    let direct =
        Path::new(program).is_absolute() || program.contains('/') || program.contains('\\');
    let paths = if direct {
        vec![PathBuf::from(program)]
    } else {
        let environment_path = if path_override.is_none() {
            env::var_os("PATH")
        } else {
            None
        };
        let path_value = path_override.or(environment_path.as_deref());
        path_value
            .map(|value| {
                env::split_paths(value)
                    .take(MAX_PATH_ENTRIES)
                    .collect::<Vec<PathBuf>>()
            })
            .unwrap_or_default()
            .into_iter()
            .map(|directory| directory.join(program))
            .collect()
    };

    let mut candidates = Vec::new();
    for path in paths {
        if let Some(inspection) = inspect_candidate(&path) {
            candidates.push(inspection.candidate);
        }
    }
    let selected = candidates
        .iter()
        .find(|candidate| candidate.executable)
        .map(|candidate| candidate.path.clone());
    let state = if selected.is_some() {
        "observed"
    } else {
        "unresolved"
    };
    let reason = if selected.is_some() {
        "first executable candidate wins PATH resolution".to_owned()
    } else if candidates.is_empty() {
        "no candidate was found in PATH".to_owned()
    } else {
        "candidates exist but none is executable".to_owned()
    };
    WhichReport {
        schema_version: SCHEMA_VERSION,
        tool: "agent-env".to_owned(),
        program: program.to_owned(),
        selected,
        candidates,
        state: state.to_owned(),
        reason,
    }
}

fn inspect_candidate(path: &Path) -> Option<CandidateInspection> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return None,
        Err(error) => {
            return Some(CandidateInspection {
                candidate: WhichCandidate {
                    path: path.to_string_lossy().into_owned(),
                    state: "unresolved".to_owned(),
                    executable: false,
                    symlink_target: None,
                    error: Some(classify_io_error(&error)),
                },
            });
        }
    };
    let symlink_target = symlink_chain(path);
    let target_metadata = match fs::metadata(path) {
        Ok(metadata) => metadata,
        Err(error) => {
            return Some(CandidateInspection {
                candidate: WhichCandidate {
                    path: path.to_string_lossy().into_owned(),
                    state: "unresolved".to_owned(),
                    executable: false,
                    symlink_target,
                    error: Some(classify_io_error(&error)),
                },
            });
        }
    };
    let executable = target_metadata.is_file() && is_executable(&target_metadata);
    let state = if metadata.file_type().is_symlink() || target_metadata.is_file() {
        "observed"
    } else {
        "unresolved"
    };
    Some(CandidateInspection {
        candidate: WhichCandidate {
            path: path.to_string_lossy().into_owned(),
            state: state.to_owned(),
            executable,
            symlink_target,
            error: None,
        },
    })
}

fn symlink_chain(path: &Path) -> Option<String> {
    let mut current = path.to_path_buf();
    let mut links = Vec::new();
    for _ in 0..MAX_SYMLINK_DEPTH {
        let metadata = fs::symlink_metadata(&current).ok()?;
        if !metadata.file_type().is_symlink() {
            break;
        }
        let target = fs::read_link(&current).ok()?;
        links.push(target.to_string_lossy().into_owned());
        current = if target.is_absolute() {
            target
        } else {
            current
                .parent()
                .unwrap_or_else(|| Path::new("."))
                .join(target)
        };
    }
    (!links.is_empty()).then(|| links.join(" -> "))
}

pub fn inspect_owner_path(path: &Path, manifest_path: Option<&Path>) -> OwnerReport {
    let absolute = absolute_path(path);
    let path_label = redacted_path(&absolute, None);
    match fs::symlink_metadata(&absolute) {
        Ok(_) => {}
        Err(error) => {
            return owner_unresolved(
                path_label,
                &format!("path is unresolved: {}", classify_io_error(&error)),
            );
        }
    }
    let Some(manifest) = find_manifest(manifest_path, Some(&absolute)) else {
        return owner_unresolved(path_label, "nearest Cargo.toml was not found");
    };
    if is_known_unreadable(&manifest) {
        return OwnerReport {
            schema_version: SCHEMA_VERSION,
            tool: "agent-env".to_owned(),
            path: path_label,
            owner: None,
            manifest: Some(manifest.to_string_lossy().into_owned()),
            source: None,
            inside_project_boundary: None,
            state: "unresolved".to_owned(),
            reason: "permission denied while reading manifest".to_owned(),
        };
    }
    let metadata = match cargo_metadata(&manifest) {
        Ok(metadata) => metadata,
        Err(error) => {
            return OwnerReport {
                schema_version: SCHEMA_VERSION,
                tool: "agent-env".to_owned(),
                path: path_label,
                owner: None,
                manifest: Some(manifest.to_string_lossy().into_owned()),
                source: None,
                inside_project_boundary: None,
                state: "unresolved".to_owned(),
                reason: error,
            };
        }
    };
    let workspace_root = absolute_path(Path::new(&metadata.workspace_root));
    let observed_path = canonicalish(&absolute);
    let inside = observed_path.starts_with(&workspace_root);
    let package = select_package(&metadata, &observed_path);
    let Some(package) = package else {
        return OwnerReport {
            schema_version: SCHEMA_VERSION,
            tool: "agent-env".to_owned(),
            path: redacted_path(&observed_path, Some(&workspace_root)),
            owner: None,
            manifest: Some(redacted_path(&manifest, Some(&workspace_root))),
            source: Some(infer_path_origin(&observed_path)),
            inside_project_boundary: Some(inside),
            state: "unresolved".to_owned(),
            reason: "path is not inside a known Cargo package boundary".to_owned(),
        };
    };
    OwnerReport {
        schema_version: SCHEMA_VERSION,
        tool: "agent-env".to_owned(),
        path: redacted_path(&observed_path, Some(&workspace_root)),
        owner: Some(format!("{}@{}", package.name, package.version)),
        manifest: Some(redacted_path(
            Path::new(&package.manifest_path),
            Some(&workspace_root),
        )),
        source: Some(package_source(package, &observed_path)),
        inside_project_boundary: Some(inside),
        state: "observed".to_owned(),
        reason: "nearest package manifest owns the path".to_owned(),
    }
}

fn owner_unresolved(path: String, reason: &str) -> OwnerReport {
    OwnerReport {
        schema_version: SCHEMA_VERSION,
        tool: "agent-env".to_owned(),
        path,
        owner: None,
        manifest: None,
        source: None,
        inside_project_boundary: None,
        state: "unresolved".to_owned(),
        reason: reason.to_owned(),
    }
}

pub fn inspect_module_path(module: &str, manifest_path: Option<&Path>) -> ModuleReport {
    let segments = module_segments(module);
    let empty = ModuleReport {
        schema_version: SCHEMA_VERSION,
        tool: "agent-env".to_owned(),
        module: module.to_owned(),
        package: None,
        source_file: None,
        origin: None,
        state: "unresolved".to_owned(),
        reason: "module path is empty or contains an unsafe segment".to_owned(),
    };
    if segments.is_empty() || segments.len() > MAX_MODULE_DEPTH {
        return empty;
    }
    let Some(manifest) = find_manifest(manifest_path, None) else {
        return ModuleReport {
            reason: "nearest Cargo.toml was not found".to_owned(),
            ..empty
        };
    };
    let metadata = match cargo_metadata(&manifest) {
        Ok(metadata) => metadata,
        Err(error) => {
            return ModuleReport {
                reason: error,
                ..empty
            };
        }
    };
    let package = metadata
        .packages
        .iter()
        .find(|package| absolute_path(Path::new(&package.manifest_path)) == manifest)
        .or_else(|| select_package(&metadata, &absolute_path(&manifest)));
    let Some(package) = package else {
        return ModuleReport {
            reason: "manifest is not a workspace package".to_owned(),
            ..empty
        };
    };
    let Some(root) = package
        .targets
        .iter()
        .find(|target| target.kind.iter().any(|kind| kind == "lib"))
        .or_else(|| {
            package
                .targets
                .iter()
                .find(|target| target.kind.iter().any(|kind| kind == "bin"))
        })
        .map(|target| absolute_path(Path::new(&target.src_path)))
    else {
        return ModuleReport {
            package: Some(format!("{}@{}", package.name, package.version)),
            reason: "package has no library or binary target".to_owned(),
            ..empty
        };
    };
    let resolved = match resolve_module_source(&root, &segments) {
        Ok(path) => path,
        Err(reason) => {
            return ModuleReport {
                package: Some(format!("{}@{}", package.name, package.version)),
                origin: Some("workspace".to_owned()),
                reason,
                ..empty
            };
        }
    };
    let workspace_root = absolute_path(Path::new(&metadata.workspace_root));
    ModuleReport {
        schema_version: SCHEMA_VERSION,
        tool: "agent-env".to_owned(),
        module: module.to_owned(),
        package: Some(format!("{}@{}", package.name, package.version)),
        source_file: Some(redacted_path(&resolved, Some(&workspace_root))),
        origin: Some("workspace".to_owned()),
        state: "observed".to_owned(),
        reason: "module declaration resolves to a source file".to_owned(),
    }
}

fn module_segments(module: &str) -> Vec<String> {
    module
        .replace("::", ".")
        .split('.')
        .filter(|segment| !segment.is_empty() && *segment != "crate" && *segment != "self")
        .map(str::trim)
        .map(str::to_owned)
        .filter(|segment| {
            !segment.is_empty()
                && segment
                    .chars()
                    .all(|character| character == '_' || character.is_ascii_alphanumeric())
        })
        .collect()
}

fn resolve_module_source(root: &Path, segments: &[String]) -> Result<PathBuf, String> {
    let mut current = root.to_path_buf();
    for (index, segment) in segments.iter().enumerate() {
        let source = read_limited_text(&current).map_err(|error| error.to_owned())?;
        let declaration = find_module_declaration(&source, segment)
            .ok_or_else(|| format!("module {segment} is not declared in {}", current.display()))?;
        if declaration.inline {
            if index + 1 == segments.len() {
                return Ok(current);
            }
            continue;
        }
        let parent = current.parent().unwrap_or_else(|| Path::new("."));
        let sibling = parent.join(format!("{segment}.rs"));
        let nested = parent.join(segment).join("mod.rs");
        current = if sibling.is_file() {
            sibling
        } else if nested.is_file() {
            nested
        } else {
            return Err(format!("module {segment} has no source file"));
        };
    }
    Ok(current)
}

#[derive(Debug)]
struct ModuleDeclaration {
    inline: bool,
}

fn find_module_declaration(source: &str, wanted: &str) -> Option<ModuleDeclaration> {
    for line in source.lines() {
        let code = line.split("//").next().unwrap_or_default();
        let words: Vec<&str> = code.split_whitespace().collect();
        let Some(index) = words.iter().position(|word| *word == "mod") else {
            continue;
        };
        let Some(raw_name) = words.get(index + 1) else {
            continue;
        };
        let name = raw_name
            .trim_matches(|character: char| !character.is_ascii_alphanumeric() && character != '_');
        if name != wanted {
            continue;
        }
        let inline = code
            .find("mod")
            .map(|offset| code[offset + 3..].contains('{') && !code[offset + 3..].contains(';'))
            .unwrap_or(false);
        return Some(ModuleDeclaration { inline });
    }
    None
}

pub fn scan_project(manifest_path: Option<&Path>) -> Vec<Fact> {
    let Some(manifest) = find_manifest(manifest_path, None) else {
        return vec![fact(
            "workspace",
            "<workspace>",
            "unresolved",
            [("reason", "nearest Cargo.toml was not found")],
        )];
    };
    let metadata = match cargo_metadata(&manifest) {
        Ok(metadata) => metadata,
        Err(error) => {
            let manifest_string = manifest.to_string_lossy().into_owned();
            return vec![fact(
                "workspace",
                "<workspace>",
                "unresolved",
                [
                    ("manifest", manifest_string.as_str()),
                    ("reason", error.as_str()),
                ],
            )];
        }
    };
    let workspace_root = absolute_path(Path::new(&metadata.workspace_root));
    let mut facts = Vec::new();
    let package_count = metadata.packages.len().to_string();
    let manifest_label = redacted_path(&manifest, Some(&workspace_root));
    push_fact(
        &mut facts,
        fact(
            "workspace",
            "<workspace>",
            "observed",
            [
                ("manifest", manifest_label.as_str()),
                ("package_count", package_count.as_str()),
            ],
        ),
    );
    add_file_fact(&mut facts, "manifest", &manifest, &workspace_root);
    let lockfile = workspace_root.join("Cargo.lock");
    if lockfile.is_file() {
        let digest = file_digest(&lockfile).unwrap_or_else(|_| "unresolved".to_owned());
        push_fact(
            &mut facts,
            fact(
                "lockfile",
                &redacted_path(&lockfile, Some(&workspace_root)),
                "observed",
                [("sha256_prefix", digest.as_str())],
            ),
        );
        add_file_fact(&mut facts, "lockfile", &lockfile, &workspace_root);
    } else {
        push_fact(
            &mut facts,
            fact(
                "lockfile",
                &redacted_path(&lockfile, Some(&workspace_root)),
                "unresolved",
                [("reason", "Cargo.lock is absent")],
            ),
        );
    }
    add_runtime_facts(&mut facts);
    add_cache_facts(&mut facts, &workspace_root);
    for package in &metadata.packages {
        let package_key = format!("{}@{}", package.name, package.version);
        let origin = package_source(package, Path::new(&package.manifest_path));
        let package_source_value = package
            .source
            .as_deref()
            .map(redact_url_credentials)
            .unwrap_or_else(|| "workspace".to_owned());
        let package_manifest =
            redacted_path(Path::new(&package.manifest_path), Some(&workspace_root));
        push_fact(
            &mut facts,
            fact(
                "package",
                &package_key,
                "observed",
                [
                    ("manifest", package_manifest.as_str()),
                    ("origin", origin.as_str()),
                    ("source", package_source_value.as_str()),
                ],
            ),
        );
        for dependency in &package.dependencies {
            let key = format!("{}:{}:{}", package_key, dependency.name, dependency.req);
            let source = dependency
                .source
                .as_deref()
                .map(redact_url_credentials)
                .unwrap_or_else(|| "path-or-workspace".to_owned());
            push_fact(
                &mut facts,
                fact(
                    "dependency",
                    &key,
                    "observed",
                    [
                        ("kind", dependency.kind.as_deref().unwrap_or("normal")),
                        ("source", source.as_str()),
                        ("target", dependency.target.as_deref().unwrap_or("all")),
                    ],
                ),
            );
        }
        add_file_fact(
            &mut facts,
            "file",
            Path::new(&package.manifest_path),
            &workspace_root,
        );
        for target in &package.targets {
            let source_path = absolute_path(Path::new(&target.src_path));
            let target_key = format!("{}:{}", package_key, target.name);
            let source_label = redacted_path(&source_path, Some(&workspace_root));
            let target_kind = target.kind.join(",");
            push_fact(
                &mut facts,
                fact(
                    "module",
                    &target_key,
                    if source_path.is_file() {
                        "observed"
                    } else {
                        "unresolved"
                    },
                    [
                        ("kind", target_kind.as_str()),
                        ("source_file", source_label.as_str()),
                    ],
                ),
            );
            add_file_fact(&mut facts, "file", &source_path, &workspace_root);
        }
    }
    add_path_binary_facts(&mut facts, &workspace_root);
    facts.sort_by(|left, right| {
        (&left.kind, &left.key, &left.state, &left.details).cmp(&(
            &right.kind,
            &right.key,
            &right.state,
            &right.details,
        ))
    });
    facts.dedup();
    facts
}

fn add_runtime_facts(facts: &mut Vec<Fact>) {
    for (name, command, args) in [
        ("cargo", "cargo", vec!["--version"]),
        ("rustc", "rustc", vec!["--version"]),
    ] {
        let version = Command::new(command)
            .args(args)
            .output()
            .ok()
            .filter(|output| output.status.success())
            .and_then(|output| String::from_utf8(output.stdout).ok())
            .and_then(|output| output.lines().next().map(str::to_owned));
        let state = if version.is_some() {
            "observed"
        } else {
            "unresolved"
        };
        let detail = version.as_deref().unwrap_or("command unavailable");
        push_fact(facts, fact("binary", name, state, [("identity", detail)]));
    }
}

fn add_cache_facts(facts: &mut Vec<Fact>, workspace_root: &Path) {
    let cargo_home = env::var_os("CARGO_HOME")
        .map(PathBuf::from)
        .or_else(|| env::var_os("HOME").map(|home| PathBuf::from(home).join(".cargo")));
    let Some(cargo_home) = cargo_home else {
        push_fact(
            facts,
            fact(
                "cache",
                "cargo-home",
                "unresolved",
                [("reason", "CARGO_HOME and HOME are absent")],
            ),
        );
        return;
    };
    let home_label = redacted_path(&cargo_home, Some(workspace_root));
    push_fact(
        facts,
        fact(
            "origin",
            "cargo-home",
            if cargo_home.is_dir() {
                "observed"
            } else {
                "unresolved"
            },
            [("path", home_label.as_str())],
        ),
    );
    for directory in ["registry", "git", "bin"] {
        let path = cargo_home.join(directory);
        let path_label = redacted_path(&path, Some(workspace_root));
        let reason = if path.exists() {
            "directory exists"
        } else {
            "directory is absent"
        };
        push_fact(
            facts,
            fact(
                "cache",
                &format!("cargo-home/{directory}"),
                if path.exists() {
                    "observed"
                } else {
                    "unresolved"
                },
                [("path", path_label.as_str()), ("reason", reason)],
            ),
        );
    }
}

fn add_path_binary_facts(facts: &mut Vec<Fact>, workspace_root: &Path) {
    let mut seen = BTreeSet::new();
    let Some(path) = env::var_os("PATH") else {
        push_fact(
            facts,
            fact(
                "binary",
                "PATH",
                "unresolved",
                [("reason", "PATH is absent")],
            ),
        );
        return;
    };
    let mut truncated = false;
    for directory in env::split_paths(&path).take(MAX_PATH_ENTRIES) {
        let entries = match fs::read_dir(&directory) {
            Ok(entries) => entries,
            Err(_) => continue,
        };
        for entry in entries.take(MAX_DIRECTORY_ENTRIES) {
            let Ok(entry) = entry else {
                continue;
            };
            let path = entry.path();
            let Ok(metadata) = fs::metadata(&path) else {
                continue;
            };
            if !metadata.is_file() || !is_executable(&metadata) {
                continue;
            }
            let key = redacted_path(&path, Some(workspace_root));
            if seen.insert(key.clone()) {
                if facts.len() >= MAX_SCAN_RECORDS.saturating_sub(1) {
                    truncated = true;
                    break;
                }
                let name = entry.file_name().to_string_lossy().into_owned();
                push_fact(
                    facts,
                    fact("binary", &key, "observed", [("name", name.as_str())]),
                );
            }
        }
        if truncated {
            break;
        }
    }
    if truncated {
        push_fact(
            facts,
            fact(
                "warning",
                "scan:bounded",
                "unresolved",
                [("reason", "PATH inventory reached the record bound")],
            ),
        );
    }
}

fn add_file_fact(facts: &mut Vec<Fact>, kind: &str, path: &Path, workspace_root: &Path) {
    let state = if path.is_file() {
        "observed"
    } else {
        "unresolved"
    };
    let digest = if path.is_file() {
        file_digest(path).unwrap_or_else(|_| "unresolved".to_owned())
    } else {
        "unresolved".to_owned()
    };
    let path_label = redacted_path(path, Some(workspace_root));
    push_fact(
        facts,
        fact(
            kind,
            path_label.as_str(),
            state,
            [("sha256_prefix", digest.as_str())],
        ),
    );
}

fn push_fact(facts: &mut Vec<Fact>, value: Fact) {
    if facts.len() < MAX_SCAN_RECORDS {
        facts.push(value);
    }
}

fn fact<'a, I>(kind: &str, key: &str, state: &str, details: I) -> Fact
where
    I: IntoIterator<Item = (&'a str, &'a str)>,
{
    Fact {
        schema_version: SCHEMA_VERSION,
        kind: kind.to_owned(),
        key: key.to_owned(),
        state: state.to_owned(),
        details: details
            .into_iter()
            .map(|(key, value)| (key.to_owned(), value.to_owned()))
            .collect(),
    }
}

pub fn render_facts(facts: &[Fact], format: OutputFormat) -> Result<String, String> {
    match format {
        OutputFormat::Jsonl | OutputFormat::Text => {
            let mut output = String::new();
            for item in facts {
                if format == OutputFormat::Jsonl {
                    output
                        .push_str(&serde_json::to_string(item).map_err(|error| error.to_string())?);
                    output.push('\n');
                } else {
                    output.push_str(&format!(
                        "{} {} {} {}\n",
                        item.kind,
                        item.key,
                        item.state,
                        item.details
                            .iter()
                            .map(|(key, value)| format!("{key}={value}"))
                            .collect::<Vec<_>>()
                            .join(",")
                    ));
                }
            }
            Ok(output)
        }
        OutputFormat::Json => {
            serde_json::to_string_pretty(facts).map_err(|error| error.to_string())
        }
    }
}

fn write_verified(path: &Path, content: &str) -> Result<(), String> {
    fs::write(path, content)
        .map_err(|error| format!("cannot write {}: {error}", path.display()))?;
    let read_back = fs::read_to_string(path)
        .map_err(|error| format!("cannot read back {}: {error}", path.display()))?;
    if read_back != content {
        return Err(format!(
            "read-back verification failed for {}",
            path.display()
        ));
    }
    Ok(())
}

fn find_manifest(explicit: Option<&Path>, path_hint: Option<&Path>) -> Option<PathBuf> {
    if let Some(explicit) = explicit {
        let path = absolute_path(explicit);
        return path.is_file().then_some(path);
    }
    let starting = path_hint
        .map(Path::to_path_buf)
        .or_else(|| env::current_dir().ok())?;
    let starting = absolute_path(&starting);
    let directory = if starting.is_dir() {
        starting
    } else {
        starting.parent()?.to_path_buf()
    };
    for ancestor in directory.ancestors() {
        let candidate = ancestor.join("Cargo.toml");
        if candidate.is_file() {
            return Some(candidate);
        }
    }
    None
}

fn cargo_metadata(manifest: &Path) -> Result<CargoMetadata, String> {
    let output = Command::new("cargo")
        .args([
            "metadata",
            "--format-version=1",
            "--no-deps",
            "--offline",
            "--quiet",
            "--manifest-path",
        ])
        .arg(manifest)
        .output()
        .map_err(|error| format!("could not invoke cargo metadata: {error}"))?;
    if !output.status.success() {
        return Err("malformed or unavailable Cargo metadata".to_owned());
    }
    serde_json::from_slice(&output.stdout).map_err(|_| "malformed Cargo metadata JSON".to_owned())
}

fn select_package<'a>(metadata: &'a CargoMetadata, path: &Path) -> Option<&'a CargoPackage> {
    metadata
        .packages
        .iter()
        .filter(|package| {
            let root = Path::new(&package.manifest_path)
                .parent()
                .map(absolute_path);
            root.is_some_and(|root| path.starts_with(root))
        })
        .max_by_key(|package| {
            Path::new(&package.manifest_path)
                .parent()
                .map(|path| path.components().count())
                .unwrap_or_default()
        })
}

fn package_source(package: &CargoPackage, path: &Path) -> String {
    if path.to_string_lossy().contains("/.cargo/registry/src/") {
        return "registry-cache".to_owned();
    }
    package
        .source
        .as_deref()
        .map(source_kind)
        .unwrap_or_else(|| "workspace".to_owned())
}

fn source_kind(source: &str) -> String {
    let lower = source.to_ascii_lowercase();
    if lower.starts_with("registry+") || lower.starts_with("sparse+") {
        "registry".to_owned()
    } else if lower.starts_with("git+") {
        "git".to_owned()
    } else if lower.starts_with("file:") || lower.starts_with("path:") {
        "path".to_owned()
    } else {
        redact_url_credentials(source)
    }
}

fn infer_path_origin(path: &Path) -> String {
    let value = path.to_string_lossy();
    if value.contains("/.cargo/registry/src/") {
        "registry-cache".to_owned()
    } else if value.contains("/.cargo/git/") {
        "git-cache".to_owned()
    } else {
        "unresolved".to_owned()
    }
}

fn absolute_path(path: &Path) -> PathBuf {
    if path.is_absolute() {
        path.to_path_buf()
    } else {
        env::current_dir()
            .unwrap_or_else(|_| PathBuf::from("."))
            .join(path)
    }
}

fn canonicalish(path: &Path) -> PathBuf {
    fs::canonicalize(path).unwrap_or_else(|_| absolute_path(path))
}

fn redacted_path(path: &Path, workspace_root: Option<&Path>) -> String {
    let absolute = absolute_path(path);
    if let Some(root) = workspace_root {
        if let Ok(relative) = absolute.strip_prefix(root) {
            if relative.as_os_str().is_empty() {
                return "<workspace>".to_owned();
            }
            return format!("<workspace>/{}", relative.to_string_lossy());
        }
    }
    format!(
        "<external:{}>",
        short_digest(absolute.to_string_lossy().as_bytes())
    )
}

fn short_digest(value: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(value);
    let digest = hasher.finalize();
    digest[..8]
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn file_digest(path: &Path) -> Result<String, String> {
    let mut file = fs::File::open(path).map_err(|error| error.to_string())?;
    let mut limited = Vec::new();
    file.by_ref()
        .take(MAX_FILE_BYTES)
        .read_to_end(&mut limited)
        .map_err(|error| error.to_string())?;
    Ok(short_digest(&limited))
}

fn read_limited_text(path: &Path) -> Result<String, &'static str> {
    let metadata = fs::metadata(path).map_err(|_| "source file metadata is unavailable")?;
    if metadata.len() > MAX_FILE_BYTES {
        return Err("source file exceeds the inspection bound");
    }
    fs::read_to_string(path).map_err(|_| "source file is unreadable or not UTF-8")
}

fn is_known_unreadable(path: &Path) -> bool {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::metadata(path)
            .map(|metadata| metadata.permissions().mode() & 0o444 == 0)
            .unwrap_or(false)
    }
    #[cfg(not(unix))]
    {
        let _ = path;
        false
    }
}

fn is_executable(metadata: &fs::Metadata) -> bool {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        metadata.permissions().mode() & 0o111 != 0
    }
    #[cfg(not(unix))]
    {
        metadata.is_file()
    }
}

fn classify_io_error(error: &io::Error) -> String {
    match error.kind() {
        io::ErrorKind::PermissionDenied => "permission-denied".to_owned(),
        io::ErrorKind::NotFound => "not-found".to_owned(),
        _ => error.kind().to_string(),
    }
}

#[cfg(test)]
mod unit_tests {
    use super::*;

    #[test]
    fn redacts_secret_names_and_url_credentials() {
        assert_eq!(redact_value("API_TOKEN", "secret"), "<redacted>");
        assert_eq!(
            redact_url_credentials("https://user:pass@example.test/path"),
            "https://<redacted>@example.test/path"
        );
    }

    #[test]
    fn module_segments_reject_unsafe_values() {
        assert_eq!(
            module_segments("crate::path.to.module"),
            vec!["path", "to", "module"]
        );
        assert!(module_segments("../secret").is_empty());
    }

    #[test]
    fn path_labels_hide_external_paths() {
        let root = Path::new("/tmp/workspace");
        assert_eq!(
            redacted_path(Path::new("/tmp/workspace/src/lib.rs"), Some(root)),
            "<workspace>/src/lib.rs"
        );
        assert!(redacted_path(Path::new("/opt/private/file"), Some(root)).starts_with("<external:"));
    }

    #[test]
    fn facts_render_as_stable_json_lines() {
        let records = vec![fact(
            "package",
            "demo@1.0.0",
            "observed",
            [("origin", "workspace")],
        )];
        let first = render_facts(&records, OutputFormat::Jsonl).unwrap();
        let second = render_facts(&records, OutputFormat::Jsonl).unwrap();
        assert_eq!(first, second);
        assert!(first.ends_with('\n'));
    }
}
