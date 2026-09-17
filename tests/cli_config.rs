//! Phase 1: command line, configuration file, precedence, and validation.
//!
//! Environment access is injected, so these tests never mutate the process
//! environment and can run in parallel.

use std::{
    ffi::OsString,
    fs,
    path::PathBuf,
    process::Command,
    sync::atomic::{AtomicU32, Ordering},
};
use tunlet::{
    cli::{self, Command as CliCommand, Mode},
    config::{self, MapEnv, RawConfig},
    logging::Level,
};

static COUNTER: AtomicU32 = AtomicU32::new(0);

/// A unique temporary directory per call, so parallel tests never share files.
fn temp_dir() -> PathBuf {
    let unique = COUNTER.fetch_add(1, Ordering::Relaxed);
    let path = std::env::temp_dir().join(format!(
        "tunlet-test-{}-{}-{unique}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    fs::create_dir_all(&path).expect("create temp dir");
    path
}

fn write_config(contents: &[u8]) -> PathBuf {
    let path = temp_dir().join("tunlet.cfg");
    fs::write(&path, contents).expect("write config");
    path
}

fn args(list: &[&str]) -> Vec<OsString> {
    std::iter::once(OsString::from("tunlet"))
        .chain(list.iter().map(OsString::from))
        .collect()
}

fn parse(list: &[&str]) -> CliCommand {
    cli::parse(args(list)).expect("parse should succeed")
}

fn cli_values(command: &CliCommand) -> RawConfig {
    match command {
        CliCommand::Run { cli, .. } => cli.clone(),
        _ => panic!("expected a run command"),
    }
}

fn no_env() -> MapEnv {
    MapEnv::new(Vec::<(String, String)>::new())
}

// ----------------------------------------------------------- command line --

#[test]
fn the_documented_examples_parse() {
    let command = parse(&[
        "server",
        "--listen",
        ":4000",
        "--data-bind",
        "0.0.0.0",
        "--allowed-ports",
        "4500-4599",
        "--key",
        "lauda-lasoon",
        "--config",
        "/etc/tunlet/tunlet.cfg",
    ]);
    let CliCommand::Run {
        mode,
        config,
        config_explicit,
        cli,
    } = command
    else {
        panic!("expected a run command");
    };
    assert_eq!(mode, Mode::Server);
    assert_eq!(config, PathBuf::from("/etc/tunlet/tunlet.cfg"));
    assert!(config_explicit);
    let resolved = config::server(&cli).expect("server config");
    assert_eq!(resolved.listen.to_string(), "0.0.0.0:4000");
    assert_eq!(resolved.allowed_ports, (4500, 4599));
    assert_eq!(resolved.key, "lauda-lasoon");

    let command = parse(&[
        "expose",
        "--server",
        "tunnel.example.com:4000",
        "--remote-port",
        "4555",
        "--target",
        "localhost:4556",
        "--key",
        "lauda-lasoon",
    ]);
    let resolved = config::expose(&cli_values(&command)).expect("expose config");
    assert_eq!(resolved.server.to_string(), "tunnel.example.com:4000");
    assert_eq!(resolved.remote_port, Some(4555));
    assert_eq!(resolved.target.to_string(), "localhost:4556");

    // Omitting --remote-port requests automatic allocation.
    let command = parse(&[
        "expose",
        "--server",
        "tunnel.example.com:4000",
        "--target",
        "127.0.0.1:4556",
        "--key",
        "k",
    ]);
    let resolved = config::expose(&cli_values(&command)).expect("expose config");
    assert_eq!(resolved.remote_port, None);
}

#[test]
fn both_flag_forms_are_accepted_and_the_last_duplicate_wins() {
    let command = parse(&[
        "expose",
        "--server=a.example:4000",
        "--server",
        "b.example:4001",
        "--target=:4556",
        "--key=k",
    ]);
    let resolved = config::expose(&cli_values(&command)).expect("expose config");
    assert_eq!(resolved.server.to_string(), "b.example:4001");
    // `:PORT` is shorthand for the IPv4 loopback target.
    assert_eq!(resolved.target.to_string(), "127.0.0.1:4556");
}

#[test]
fn config_may_appear_before_or_after_the_subcommand() {
    for list in [
        vec!["--config", "/tmp/x.cfg", "server", "--key", "k"],
        vec!["server", "--config", "/tmp/x.cfg", "--key", "k"],
        vec!["--config=/tmp/x.cfg", "server", "--key", "k"],
    ] {
        let CliCommand::Run { config, .. } = parse(&list) else {
            panic!("expected a run command");
        };
        assert_eq!(config, PathBuf::from("/tmp/x.cfg"));
    }
}

#[test]
fn unknown_options_and_positional_arguments_fail() {
    for list in [
        vec!["server", "--nope"],
        vec!["server", "--nope=1"],
        vec!["server", "extra"],
        vec!["serve"],
        vec!["server", "--key"],
        vec!["expose", "--remote-port"],
        vec!["--key", "k", "server"],
        vec!["server", "expose"],
    ] {
        assert!(
            cli::parse(args(&list)).is_err(),
            "expected failure for {list:?}"
        );
    }
}

#[test]
fn help_and_version_need_no_key_or_configuration() {
    for flag in ["-h", "--help"] {
        assert!(matches!(parse(&[flag]), CliCommand::Help));
        assert!(matches!(parse(&["server", flag]), CliCommand::Help));
    }
    for flag in ["-V", "--version"] {
        assert!(matches!(parse(&[flag]), CliCommand::Version));
        assert!(matches!(parse(&["expose", flag]), CliCommand::Version));
    }
    let help = cli::help();
    assert!(help.contains("tunlet server"));
    assert!(help.contains("--allowed-ports"));
    assert!(
        help.contains("automatic allocation only"),
        "help must explain what --allowed-ports controls"
    );
}

#[test]
fn quiet_accepts_only_its_documented_forms() {
    let command = parse(&["server", "--quiet", "--key", "k"]);
    assert_eq!(cli_values(&command).values.get("QUIET").unwrap(), "true");
    let command = parse(&["server", "--quiet=false", "--key", "k"]);
    assert_eq!(cli_values(&command).values.get("QUIET").unwrap(), "false");
    assert!(cli::parse(args(&["server", "--quiet=maybe"])).is_err());
    // `--quiet` never swallows the next argument.
    let command = parse(&["server", "--quiet", "--key", "k"]);
    assert_eq!(cli_values(&command).values.get("KEY").unwrap(), "k");
}

// ------------------------------------------------------ configuration file --

#[test]
fn quotes_comments_crlf_bom_and_duplicates_are_handled() {
    let path = write_config(
        b"\xef\xbb\xbf# leading comment\r\n\r\nKEY=\"a=b # c\"\r\n  LISTEN = :4100 \r\n\
          TARGET=':4556'\r\nMAX_CONNECTIONS=8\r\nMAX_CONNECTIONS=9\r\n# trailing\r\n",
    );
    let raw = config::parse_file(&path, true).expect("parse");
    // Interior bytes are literal: no comment stripping, no escapes.
    assert_eq!(raw.values.get("KEY").unwrap(), "a=b # c");
    assert_eq!(raw.values.get("LISTEN").unwrap(), ":4100");
    assert_eq!(raw.values.get("TARGET").unwrap(), ":4556");
    // Last duplicate wins.
    assert_eq!(raw.values.get("MAX_CONNECTIONS").unwrap(), "9");
}

#[test]
fn shipped_examples_parse_and_validate() {
    let server = config::parse_file(&PathBuf::from("examples/server.cfg"), true).expect("server");
    let resolved = config::server(&server).expect("server config");
    assert_eq!(resolved.listen.port(), 4000);
    assert_eq!(resolved.allowed_ports, (10000, 65535));

    let expose = config::parse_file(&PathBuf::from("examples/expose.cfg"), true).expect("expose");
    let resolved = config::expose(&expose).expect("expose config");
    assert_eq!(resolved.remote_port, Some(4555));
    assert_eq!(resolved.target.to_string(), "127.0.0.1:4556");
}

#[test]
fn malformed_lines_report_path_and_line_without_echoing_values() {
    let path = write_config(b"KEY=good\nthis-line-has-no-equals-sign\n");
    let error = config::parse_file(&path, true).unwrap_err().to_string();
    assert!(error.contains(&format!("{}:2", path.display())), "{error}");
    assert!(error.contains("expected NAME=value"), "{error}");
    assert!(!error.contains("this-line-has-no-equals-sign"), "{error}");

    let path = write_config(b"KEY=\"unterminated\n");
    let error = config::parse_file(&path, true).unwrap_err().to_string();
    assert!(error.contains("unterminated quoted value"), "{error}");
    assert!(!error.contains("unterminated\""), "{error}");
}

#[test]
fn unknown_and_prefixed_names_fail_but_other_mode_names_are_ignored() {
    let path = write_config(b"KEY=k\nLSITEN=:4000\n");
    let error = config::parse_file(&path, true).unwrap_err().to_string();
    assert!(error.contains("unknown setting name"), "{error}");

    // Names in files never carry the environment prefix.
    let path = write_config(b"TUNLET_KEY=k\n");
    assert!(config::parse_file(&path, true).is_err());

    // A server file may contain expose names; they are ignored after merging.
    let path = write_config(b"KEY=k\nLISTEN=:4100\nSERVER=example:4000\nTARGET=:22\n");
    let raw = config::parse_file(&path, true).expect("parse");
    let resolved = config::server(&raw).expect("server config");
    assert_eq!(resolved.listen.port(), 4100);
}

#[test]
fn a_missing_default_file_is_fine_but_a_missing_selected_file_is_an_error() {
    let missing = temp_dir().join("absent.cfg");
    assert!(
        config::parse_file(&missing, false)
            .expect("optional")
            .values
            .is_empty()
    );
    let error = config::parse_file(&missing, true).unwrap_err().to_string();
    assert!(error.contains("cannot read configuration file"), "{error}");

    // A directory in place of a file is an unreadable existing path.
    let directory = temp_dir();
    assert!(config::parse_file(&directory, false).is_err());
}

// ------------------------------------------------------------- precedence --

#[test]
fn flags_beat_environment_which_beats_file_which_beats_defaults() {
    let path = write_config(b"KEY=from-file\nLISTEN=:4100\nMAX_CONNECTIONS=10\nLOG_LEVEL=debug\n");
    let env = MapEnv::new([
        ("TUNLET_KEY", "from-env"),
        ("TUNLET_MAX_CONNECTIONS", "20"),
        ("TUNLET_IGNORED", "nothing"),
    ]);
    let cli = RawConfig::from_pairs([("KEY", "from-flag")]);
    let merged = config::resolve(&path, true, cli, &env).expect("resolve");
    let resolved = config::server(&merged).expect("server config");

    assert_eq!(resolved.key, "from-flag", "flags win");
    assert_eq!(resolved.max_connections, 20, "environment beats the file");
    assert_eq!(resolved.listen.port(), 4100, "file beats the default");
    assert_eq!(resolved.data_bind.to_string(), "0.0.0.0", "default applies");
    assert_eq!(resolved.log_level, Level::Debug);
}

#[test]
fn a_higher_layer_overrides_a_malformed_lower_value() {
    let path = write_config(b"KEY=k\nMAX_CONNECTIONS=not-a-number\nALLOWED_PORTS=nonsense\n");
    let env = MapEnv::new([("TUNLET_ALLOWED_PORTS", "20000-20100")]);
    let cli = RawConfig::from_pairs([("MAX_CONNECTIONS", "12")]);
    let merged = config::resolve(&path, true, cli, &env).expect("resolve");
    let resolved = config::server(&merged).expect("server config");
    assert_eq!(resolved.max_connections, 12);
    assert_eq!(resolved.allowed_ports, (20000, 20100));
}

#[test]
fn a_file_syntax_error_fails_even_when_every_value_is_overridden() {
    let path = write_config(b"KEY=k\nUNKNOWN_NAME=1\n");
    let cli = RawConfig::from_pairs([("KEY", "override")]);
    assert!(config::resolve(&path, true, cli, &no_env()).is_err());
}

#[test]
fn an_explicitly_empty_value_overrides_and_is_validated() {
    let path = write_config(b"KEY=from-file\n");
    let env = MapEnv::new([("TUNLET_KEY", "")]);
    let merged = config::resolve(&path, true, RawConfig::default(), &env).expect("resolve");
    let error = config::server(&merged).unwrap_err().to_string();
    assert!(error.contains("KEY must not be empty"), "{error}");

    let cli = RawConfig::from_pairs([("KEY", "")]);
    let merged = config::resolve(&path, true, cli, &no_env()).expect("resolve");
    assert!(config::server(&merged).is_err());
}

#[test]
fn quiet_false_undoes_an_inherited_quiet_setting() {
    let path = write_config(b"KEY=k\nQUIET=true\n");
    let merged = config::resolve(&path, true, RawConfig::default(), &no_env()).expect("resolve");
    assert!(config::server(&merged).expect("server config").quiet);

    let env = MapEnv::new([("TUNLET_QUIET", "true")]);
    let cli = RawConfig::from_pairs([("QUIET", "false")]);
    let merged = config::resolve(&path, true, cli, &env).expect("resolve");
    assert!(!config::server(&merged).expect("server config").quiet);

    // QUIET and LOG_LEVEL resolve independently.
    let path = write_config(b"KEY=k\nQUIET=true\nLOG_LEVEL=debug\n");
    let merged = config::resolve(&path, true, RawConfig::default(), &no_env()).expect("resolve");
    let resolved = config::server(&merged).expect("server config");
    assert!(resolved.quiet && resolved.log_level == Level::Debug);

    let path = write_config(b"KEY=k\nQUIET=yes\n");
    let merged = config::resolve(&path, true, RawConfig::default(), &no_env()).expect("resolve");
    assert!(config::server(&merged).is_err());
}

#[test]
fn only_known_environment_names_are_read() {
    let env = MapEnv::new([
        ("TUNLET_KEY", "k"),
        ("TUNLET_KEYS", "ignored"),
        ("KEY", "ignored"),
        ("PATH", "ignored"),
    ]);
    let raw = config::env_config(&env);
    assert_eq!(raw.values.len(), 1);
    assert_eq!(raw.values.get("KEY").unwrap(), "k");
}

// ------------------------------------------------------------ validation --

#[test]
fn addresses_ports_and_ranges_are_validated() {
    let ok = |pairs: Vec<(&str, &str)>| config::server(&RawConfig::from_pairs(pairs));
    assert!(ok(vec![("KEY", "k"), ("LISTEN", ":4000")]).is_ok());
    assert!(ok(vec![("KEY", "k"), ("LISTEN", "[::1]:4000")]).is_ok());
    assert!(ok(vec![("KEY", "k"), ("LISTEN", "127.0.0.1:4000")]).is_ok());
    // Privileged and zero listener ports are refused before any bind attempt.
    assert!(ok(vec![("KEY", "k"), ("LISTEN", ":80")]).is_err());
    assert!(ok(vec![("KEY", "k"), ("LISTEN", ":0")]).is_err());
    assert!(ok(vec![("KEY", "k"), ("LISTEN", "example.com:4000")]).is_err());
    assert!(ok(vec![("KEY", "k"), ("LISTEN", "4000")]).is_err());
    assert!(ok(vec![("KEY", "k"), ("DATA_BIND", "0.0.0.0:1")]).is_err());
    assert!(ok(vec![("KEY", "k"), ("DATA_BIND", "::")]).is_ok());
    assert!(ok(vec![("KEY", "k"), ("ALLOWED_PORTS", "1000-2000")]).is_err());
    assert!(ok(vec![("KEY", "k"), ("ALLOWED_PORTS", "3000-2000")]).is_err());
    assert!(ok(vec![("KEY", "k"), ("ALLOWED_PORTS", "2000")]).is_err());
    assert!(ok(vec![("KEY", "k"), ("ALLOWED_PORTS", "2000-70000")]).is_err());
    assert!(ok(vec![("KEY", "k"), ("MAX_CONNECTIONS", "0")]).is_err());
    assert!(ok(vec![("KEY", "k"), ("MAX_CONNECTIONS", "65536")]).is_err());
    assert!(ok(vec![("KEY", "k"), ("MAX_CONNECTIONS", "65535")]).is_ok());
    assert!(ok(vec![("LISTEN", ":4000")]).is_err(), "KEY is required");
}

#[test]
fn expose_requires_a_server_and_target_and_validates_ports() {
    let ok = |pairs: Vec<(&str, &str)>| config::expose(&RawConfig::from_pairs(pairs));
    let base = vec![
        ("KEY", "k"),
        ("SERVER", "example:4000"),
        ("TARGET", ":4556"),
    ];
    assert!(ok(base.clone()).is_ok());
    assert!(ok(vec![("KEY", "k"), ("SERVER", "example:4000")]).is_err());
    assert!(ok(vec![("KEY", "k"), ("TARGET", ":4556")]).is_err());

    let with = |name: &'static str, value: &'static str| {
        let mut pairs = base.clone();
        pairs.push((name, value));
        ok(pairs)
    };
    assert!(with("REMOTE_PORT", "0").is_err());
    assert!(with("REMOTE_PORT", "80").is_err());
    assert!(with("REMOTE_PORT", "70000").is_err());
    assert!(with("REMOTE_PORT", "1024").is_ok());
    assert!(with("LOG_LEVEL", "trace").is_err());
    // A local target may use a privileged port: the client dials it.
    let resolved = ok(vec![
        ("KEY", "k"),
        ("SERVER", "example:4000"),
        ("TARGET", "localhost:22"),
    ])
    .expect("privileged target port is allowed");
    assert_eq!(resolved.target.port, 22);
    // IPv6 endpoints are bracketed.
    let resolved = ok(vec![
        ("KEY", "k"),
        ("SERVER", "[2001:db8::1]:4000"),
        ("TARGET", "[::1]:4556"),
    ])
    .expect("IPv6 endpoints");
    assert_eq!(resolved.server.to_string(), "[2001:db8::1]:4000");
    assert_eq!(resolved.target.to_string(), "[::1]:4556");
    assert!(
        ok(vec![
            ("KEY", "k"),
            ("SERVER", "example:80"),
            ("TARGET", ":1")
        ])
        .is_err()
    );
    assert!(
        ok(vec![
            ("KEY", "k"),
            ("SERVER", "example:4000"),
            ("TARGET", ":0")
        ])
        .is_err()
    );
}

#[test]
fn the_key_never_appears_in_an_error_message() {
    let secret = "super-secret-key-value";
    let raw = RawConfig::from_pairs([("KEY", secret), ("LISTEN", ":80")]);
    let error = config::server(&raw).unwrap_err().to_string();
    assert!(!error.contains(secret), "{error}");

    let raw = RawConfig::from_pairs([("KEY", secret), ("MAX_CONNECTIONS", "zero")]);
    let error = config::server(&raw).unwrap_err().to_string();
    assert!(!error.contains(secret), "{error}");

    // A debug rendering of the typed configuration is never logged, but make
    // sure a file parse error cannot leak a quoted key either.
    let path = write_config(format!("KEY=\"{secret}\nLISTEN=:4000\n").as_bytes());
    let error = config::parse_file(&path, true).unwrap_err().to_string();
    assert!(!error.contains(secret), "{error}");
}

// ------------------------------------------------------- process behavior --

fn binary() -> Command {
    Command::new(env!("CARGO_BIN_EXE_tunlet"))
}

#[test]
fn help_and_version_exit_zero_without_configuration() {
    for flag in ["--help", "-h"] {
        let output = binary().arg(flag).output().expect("run");
        assert_eq!(output.status.code(), Some(0));
        let text = String::from_utf8_lossy(&output.stdout);
        assert!(text.contains("tunlet server"), "{text}");
    }
    let output = binary().arg("--version").output().expect("run");
    assert_eq!(output.status.code(), Some(0));
    assert!(String::from_utf8_lossy(&output.stdout).starts_with("tunlet "));
}

#[test]
fn usage_and_configuration_errors_exit_with_status_two() {
    let output = binary().arg("--nope").output().expect("run");
    assert_eq!(output.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&output.stderr).contains("tunlet:"));

    let output = binary()
        .args(["server", "--listen", ":80"])
        .output()
        .expect("run");
    assert_eq!(output.status.code(), Some(2));

    let output = binary()
        .args([
            "server",
            "--config",
            "/nonexistent/tunlet.cfg",
            "--key",
            "k",
        ])
        .output()
        .expect("run");
    assert_eq!(output.status.code(), Some(2));
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("cannot read configuration file"),
        "explicit missing config must fail"
    );
}

#[test]
fn a_missing_key_is_a_configuration_error() {
    let directory = temp_dir();
    let output = binary()
        .current_dir(&directory)
        .args(["server", "--listen", ":4000"])
        .env_remove("TUNLET_KEY")
        .output()
        .expect("run");
    assert_eq!(output.status.code(), Some(2));
    let text = String::from_utf8_lossy(&output.stderr);
    assert!(text.contains("KEY is required"), "{text}");
}
