use anyhow::Result;
use clap::CommandFactory;
use std::{
    env, fs, io,
    path::{Path, PathBuf},
    process::{Command, Stdio},
};

fn cli() -> clap::Command {
    clap::Command::new("xtasks")
        .about("iroh automation tasks")
        .subcommand_required(true)
        .arg_required_else_help(true)
        .allow_external_subcommands(true)
        .subcommand(clap::Command::new("dist").about("build application and man pages"))
        .subcommand(clap::Command::new("man").about("build man pages"))
}

fn main() {
    let matches = cli().get_matches();
    if let Err(e) = run_subcommand(matches) {
        eprintln!("{}", e);
        std::process::exit(-1);
    }
}

fn run_subcommand(matches: clap::ArgMatches) -> Result<()> {
    match matches.subcommand() {
        Some(("dist", _)) => dist()?,
        Some(("man", _)) => dist_manpage()?,
        _ => unreachable!(), // If all subcommands are defined above, anything else is unreachabe!()
    }
    Ok(())
}

fn dist() -> Result<()> {
    let _ = fs::remove_dir_all(&dist_dir());
    fs::create_dir_all(&dist_dir())?;

    dist_binary()?;
    dist_manpage()?;

    Ok(())
}

fn dist_binary() -> Result<()> {
    let cargo = env::var("CARGO").unwrap_or_else(|_| "cargo".to_string());
    let status = Command::new(cargo)
        .current_dir(project_root())
        .args(&["build", "--release"])
        .status()?;

    if !status.success() {
        Err(anyhow::anyhow!("cargo build failed"))?;
    }

    let dst = project_root().join("target/release/iroh");

    fs::copy(&dst, dist_dir().join("iroh"))?;

    if Command::new("strip")
        .arg("--version")
        .stdout(Stdio::null())
        .status()
        .is_ok()
    {
        eprintln!("stripping the binary");
        let status = Command::new("strip").arg(&dst).status()?;
        if !status.success() {
            Err(anyhow::anyhow!("strip failed"))?;
        }
    } else {
        eprintln!("no `strip` utility found")
    }

    Ok(())
}

fn dist_manpage() -> Result<()> {
    let outdir = dist_dir();
    let f = fs::File::create(outdir.join("iroh.1"))?;
    let mut buf = io::BufWriter::new(f);
    let cmd = iroh::run::Cli::command();
    let man = clap_mangen::Man::new(cmd.clone());
    man.render(&mut buf)?;

    write_subcommand_man_files("iroh", &cmd, &outdir)
}

fn write_subcommand_man_files(prefix: &str, cmd: &clap::Command, outdir: &PathBuf) -> Result<()> {
    for subcommand in cmd.get_subcommands() {
        let subcommand_name = format!("iroh{}", subcommand.get_name());
        let f = fs::File::create(outdir.join(format!("{}{}", &subcommand_name, ".1")))?;
        let mut buf = io::BufWriter::new(f);
        let man = clap_mangen::Man::new(subcommand.clone());
        man.render(&mut buf)?;

        write_subcommand_man_files(
            format!("{prefix}{subcommand_name}").as_str(),
            subcommand,
            outdir,
        )?;
    }

    Ok(())
}

fn project_root() -> PathBuf {
    Path::new(&env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(1)
        .unwrap()
        .to_path_buf()
}

fn dist_dir() -> PathBuf {
    project_root().join("target/dist")
}
