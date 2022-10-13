use anyhow::Result;
use clap::{CommandFactory, Parser, Subcommand};
use std::{
    env, fs, io,
    path::{Path, PathBuf},
    process::{Command, Stdio},
};

#[derive(Debug, Parser)]
#[command(name = "xtasks")]
#[command(about = "iroh automation tasks", long_about = None)]
#[command(arg_required_else_help = true)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Debug, Subcommand)]
enum Commands {
    #[command(about = "build application and man pages", long_about = None)]
    Dist {},
    #[command(about = "build man pages")]
    Man {},
}

fn main() {
    let args = Cli::parse();
    if let Err(e) = run_subcommand(args) {
        eprintln!("{}", e);
        std::process::exit(-1);
    }
}

fn run_subcommand(args: Cli) -> Result<()> {
    match args.command {
        Commands::Dist {} => dist()?,
        Commands::Man {} => dist_manpage()?,
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
