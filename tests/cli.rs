use agent_env::{
    inspect_module_path, inspect_owner_path, resolve_program, scan_project, ModuleReport,
    OutputFormat, OwnerReport,
};
use serde_json::Value;
use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use tempfile::TempDir;

fn binary() -> PathBuf {
    PathBuf::from(
        env::var_os("CARGO_BIN_EXE_agent-env").expect("Cargo must provide the binary path"),
    )
}

fn run<I, S>(args: I, current_dir: &Path) -> Output
where
    I: IntoIterator<Item = S>,
    S: AsRef<std::ffi::OsStr>,
{
    Command::new(binary())
        .args(args)
        .current_dir(current_dir)
        .output()
        .expect("agent-env process should start")
}

fn write_project(root: &Path, name: &str) -> PathBuf {
    fs::create_dir_all(root.join("src")).unwrap();
    let manifest = root.join("Cargo.toml");
    fs::write(
        &manifest,
        format!("[package]\nname = \"{name}\"\nversion = \"0.1.0\"\nedition = \"2021\"\n"),
    )
    .unwrap();
    fs::write(root.join("src/lib.rs"), "pub mod nested;\n").unwrap();
    fs::write(root.join("src/nested.rs"), "pub fn fixture() {}\n").unwrap();
    manifest
}

#[test]
fn path_shadowing_and_symlinked_executable_are_reported() {
    let temp = TempDir::new().unwrap();
    let first = temp.path().join("first");
    let second = temp.path().join("second");
    fs::create_dir_all(&first).unwrap();
    fs::create_dir_all(&second).unwrap();
    let first_tool = first.join("shadow-tool");
    let second_tool = second.join("shadow-tool");
    write_executable(&first_tool);
    write_executable(&second_tool);
    let path = env::join_paths([&first, &second]).unwrap();
    let report = resolve_program("shadow-tool", Some(path.as_os_str()));
    assert_eq!(
        report.selected.as_deref(),
        Some(first_tool.to_str().unwrap())
    );
    assert_eq!(report.candidates.len(), 2);

    #[cfg(unix)]
    {
        use std::os::unix::fs::symlink;
        let link = temp.path().join("linked-tool");
        symlink(&first_tool, &link).unwrap();
        let link_path = env::join_paths([temp.path()]).unwrap();
        let linked = resolve_program("linked-tool", Some(link_path.as_os_str()));
        assert_eq!(linked.selected.as_deref(), Some(link.to_str().unwrap()));
        assert!(linked.candidates[0].symlink_target.is_some());
    }
}

#[test]
fn missing_owner_and_path_forms_are_unresolved_or_owned() {
    let temp = TempDir::new().unwrap();
    let manifest = write_project(temp.path(), "path-fixture");
    let missing = inspect_owner_path(&temp.path().join("missing.txt"), Some(&manifest));
    assert_eq!(missing.state, "unresolved");
    assert!(missing.owner.is_none());

    let owner = inspect_owner_path(&temp.path().join("src/lib.rs"), Some(&manifest));
    assert_eq!(owner.state, "observed");
    assert_eq!(owner.owner.as_deref(), Some("path-fixture@0.1.0"));
    assert_eq!(owner.inside_project_boundary, Some(true));
}

#[test]
fn package_cache_fixture_has_a_registry_origin() {
    let temp = TempDir::new().unwrap();
    let package_root = temp
        .path()
        .join(".cargo/registry/src/index.example/cached-0.1.0");
    let manifest = write_project(&package_root, "cached");
    let report = inspect_owner_path(&package_root.join("src/lib.rs"), Some(&manifest));
    assert_eq!(report.state, "observed");
    assert_eq!(report.owner.as_deref(), Some("cached@0.1.0"));
    assert_eq!(report.source.as_deref(), Some("registry-cache"));
}

#[test]
fn module_fixture_resolves_external_module_source() {
    let temp = TempDir::new().unwrap();
    let manifest = write_project(temp.path(), "module-fixture");
    let report: ModuleReport = inspect_module_path("crate::nested", Some(&manifest));
    assert_eq!(report.state, "observed");
    assert_eq!(report.package.as_deref(), Some("module-fixture@0.1.0"));
    assert!(report
        .source_file
        .as_deref()
        .unwrap()
        .ends_with("src/nested.rs"));
}

#[test]
fn malformed_metadata_is_explicit() {
    let temp = TempDir::new().unwrap();
    fs::create_dir_all(temp.path().join("src")).unwrap();
    let manifest = temp.path().join("Cargo.toml");
    fs::write(&manifest, "[package\nname = \"broken\"\n").unwrap();
    fs::write(temp.path().join("src/lib.rs"), "").unwrap();
    let report = inspect_owner_path(&temp.path().join("src/lib.rs"), Some(&manifest));
    assert_eq!(report.state, "unresolved");
    assert!(report.reason.contains("malformed"));
}

#[cfg(unix)]
#[test]
fn permission_denial_is_not_silently_reported_as_missing() {
    use std::os::unix::fs::PermissionsExt;
    let temp = TempDir::new().unwrap();
    let manifest = write_project(temp.path(), "permission-fixture");
    let original = fs::metadata(&manifest).unwrap().permissions().mode();
    let mut permissions = fs::metadata(&manifest).unwrap().permissions();
    permissions.set_mode(0o0);
    fs::set_permissions(&manifest, permissions).unwrap();
    let report = inspect_owner_path(&temp.path().join("src/lib.rs"), Some(&manifest));
    let mut restore = fs::metadata(&manifest).unwrap().permissions();
    restore.set_mode(original);
    fs::set_permissions(&manifest, restore).unwrap();
    assert_eq!(report.state, "unresolved");
    assert!(report.reason.contains("permission"));
}

#[test]
fn cli_contract_and_jsonl_output_are_stable() {
    let temp = TempDir::new().unwrap();
    let manifest = write_project(temp.path(), "cli-fixture");

    let version = run(["version"], temp.path());
    assert!(version.status.success());
    assert_eq!(
        String::from_utf8_lossy(&version.stdout).trim(),
        "agent-env 0.1.0"
    );

    let help = run(["--help"], temp.path());
    assert!(help.status.success());
    assert!(String::from_utf8_lossy(&help.stdout).contains("scan"));

    let args = [
        "scan",
        "--format",
        "jsonl",
        "--manifest-path",
        manifest.to_str().unwrap(),
    ];
    let first = run(args, temp.path());
    let second = run(args, temp.path());
    assert!(first.status.success());
    assert_eq!(first.stdout, second.stdout);
    let lines: Vec<Value> = String::from_utf8(first.stdout)
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect();
    assert!(lines.iter().any(|line| line["kind"] == "package"));
    assert!(lines.iter().any(|line| line["kind"] == "module"));
    assert!(lines
        .iter()
        .all(|line| !line.to_string().contains(temp.path().to_str().unwrap())));

    let owner = run(["owner", "src/lib.rs", "--format", "json"], temp.path());
    assert!(owner.status.success());
    let owner: OwnerReport = serde_json::from_slice(&owner.stdout).unwrap();
    assert_eq!(owner.owner.as_deref(), Some("cli-fixture@0.1.0"));

    let records = scan_project(Some(&manifest));
    let rendered = agent_env::render_facts(&records, OutputFormat::Jsonl).unwrap();
    assert!(!rendered.is_empty());
}

fn write_executable(path: &Path) {
    fs::write(path, "#!/bin/sh\nexit 0\n").unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut permissions = fs::metadata(path).unwrap().permissions();
        permissions.set_mode(0o755);
        fs::set_permissions(path, permissions).unwrap();
    }
}
