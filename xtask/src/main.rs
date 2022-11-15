use anyhow::{bail, Result};
use clap::{CommandFactory, Parser, Subcommand};
use std::{
    env, fs, io,
    path::{Path, PathBuf},
    process::Command,
    str,
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
    #[command(about = "copy release binaries to $HOME/.cargo/bin")]
    DevInstall {
        #[clap(short, long)]
        build: bool,
    },
    #[command(about = "build docker images")]
    Docker {
        #[clap(short, long)]
        all: bool,
        /// Set type of progress output (auto, plain, tty). Use plain to show container output (default "auto")
        #[clap(long)]
        progress: String,
        images: Vec<String>,
    },
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
        Commands::DevInstall { build } => dev_install(build)?,
        Commands::Docker {
            all,
            images,
            progress,
        } => build_docker(all, images, progress)?,
    }
    Ok(())
}

fn dist() -> Result<()> {
    let _ = fs::remove_dir_all(&dist_dir());
    fs::create_dir_all(&dist_dir())?;

    dist_binaries()?;
    dist_manpage()?;

    Ok(())
}

fn dev_install(build: bool) -> Result<()> {
    if build {
        dist().unwrap();
    }
    let bins = ["iroh", "iroh-one", "iroh-gateway", "iroh-p2p", "iroh-store"];
    let home = dirs_next::home_dir().unwrap();
    for bin in bins {
        let from = project_root().join(format!("target/release/{}", bin));
        if !from.try_exists()? {
            bail!(
                "{} not found, did you run `cargo build --release`?",
                from.display()
            );
        }
        let to = home.join(format!(".cargo/bin/{}", bin));
        println!("copying {} to {}", bin, to.display());
        fs::copy(from, to)?;
    }
    Ok(())
}

fn dist_binaries() -> Result<()> {
    let cargo = env::var("CARGO").unwrap_or_else(|_| "cargo".to_string());
    let status = Command::new(cargo)
        .current_dir(project_root())
        .args(["build", "--release"])
        .status()?;

    if !status.success() {
        Err(anyhow::anyhow!("cargo build failed"))?;
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

fn build_docker(all: bool, build_images: Vec<String>, progress: String) -> Result<()> {
    let mut images = build_images;
    if all {
        images = vec![String::from("iroh-one"), String::from("iroh-p2p")];
    }

    let commit = current_git_commit()?;

    for image in images {
        println!("building {}:{}", image, commit);
        let status = Command::new("docker")
            .current_dir(project_root())
            .args([
                "build",
                "-t",
                format!("{}:{}", image, commit).as_str(),
                "-t",
                format!("{}:latest", image).as_str(),
                "-f",
                format!("docker/Dockerfile.{}", image).as_str(),
                format!("--progress={}", progress).as_str(),
                ".",
            ])
            .status()?;

        if !status.success() {
            Err(anyhow::anyhow!("cargo build failed"))?;
        }
    }

    Ok(())
}

fn current_git_commit() -> Result<String> {
    let output = Command::new("git")
        .current_dir(project_root())
        .args(["log", "-1", "--pretty=%h"])
        .output()?;
    let commitish = str::from_utf8(&output.stdout)?.trim_end();
    Ok(String::from(commitish))
}
