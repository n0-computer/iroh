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
    #[command(about = "generate code coverage report", long_about = None)]
    Coverage {},
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
        #[clap(short, long, default_value_t = String::from("auto"))]
        progress: String,
        images: Vec<String>,
    },
    #[command(about = "push docker images. requires image push credentials.")]
    DockerPush {
        /// Publish all images, overrides images args
        #[clap(short, long)]
        all: bool,
        /// Set of services to publish. Any of {iroh-store,iroh-p2p,iroh-gateway,iroh-one}
        images: Vec<String>,
    },
    #[command(
        about = "build & push multi-platform docker images. requires image push credentials."
    )]
    DockerBuildx {
        /// Publish all images, overrides images args
        #[clap(short, long)]
        all: bool,
        /// Set of services to publish. Any of {iroh-store,iroh-p2p,iroh-gateway,iroh-one}
        images: Vec<String>,
        #[clap(short, long, default_value_t = String::from("linux/arm64/v8,linux/amd64"))]
        platforms: String,
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
        Commands::Coverage {} => coverage()?,
        Commands::Dist {} => dist()?,
        Commands::Man {} => dist_manpage()?,
        Commands::DevInstall { build } => dev_install(build)?,
        Commands::Docker {
            all,
            images,
            progress,
        } => build_docker(all, images, progress)?,
        Commands::DockerPush { all, images } => push_docker(all, images)?,
        Commands::DockerBuildx {
            all,
            images,
            platforms,
        } => buildx_docker(all, images, platforms)?,
    }
    Ok(())
}

fn coverage() -> Result<()> {
    xtaskops::tasks::coverage(false)?;
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

fn docker_images(all: bool, build_images: Vec<String>) -> Vec<String> {
    if all {
        return vec![
            String::from("iroh-one"),
            String::from("iroh-store"),
            String::from("iroh-p2p"),
            String::from("iroh-gateway"),
        ];
    }
    build_images
}

fn build_docker(all: bool, build_images: Vec<String>, progress: String) -> Result<()> {
    let images = docker_images(all, build_images);
    let commit = current_git_commit()?;

    for image in images {
        println!("building {}:{}", image, commit);
        let status = Command::new("docker")
            .current_dir(project_root())
            .args([
                "build",
                "-t",
                format!("n0computer/{}:{}", image, commit).as_str(),
                "-t",
                format!("n0computer/{}:latest", image).as_str(),
                "-f",
                format!("docker/Dockerfile.{}", image).as_str(),
                format!("--progress={}", progress).as_str(),
                ".",
            ])
            .status()?;

        if !status.success() {
            Err(anyhow::anyhow!("docker build failed"))?;
        }
    }

    Ok(())
}

fn buildx_docker(all: bool, build_images: Vec<String>, platforms: String) -> Result<()> {
    let images = docker_images(all, build_images);
    let commit = current_git_commit()?;

    // TODO(b5) - it'd be great if this command managed the buildx instance
    // but doing this in a naive way invalidates caching across multiple calls
    // to this task
    // let output = Command::new("docker")
    //         .current_dir(project_root())
    //         .args([
    //             "buildx",
    //             "create",
    //             "--use",
    //         ])
    //         .output()?;

    // let buildx_instance = str::from_utf8(&output.stdout)?.trim_end();
    // println!("created buildx instance: {}", buildx_instance);

    for image in images {
        println!("building {}:{}", image, commit);
        let status = Command::new("docker")
            .current_dir(project_root())
            .args([
                "buildx",
                "build",
                "--push",
                format!("--platform={}", platforms).as_str(),
                "--tag",
                format!("n0computer/{}:{}", image, commit).as_str(),
                "--tag",
                format!("n0computer/{}:latest", image).as_str(),
                "-f",
                format!("docker/Dockerfile.{}", image).as_str(),
                ".",
            ])
            .status()?;

        if !status.success() {
            Err(anyhow::anyhow!("docker buildx failed"))?;
        }
    }

    // let status = Command::new("docker")
    // .current_dir(project_root())
    // .args([
    //     "buildx",
    //     "stop",
    //     buildx_instance,
    // ])
    // .status()?;

    // if !status.success() {
    //     return Err(anyhow::anyhow!("docker buildx failed"))?;
    // }

    Ok(())
}

fn push_docker(all: bool, images: Vec<String>) -> Result<()> {
    let images = docker_images(all, images);
    let commit = current_git_commit()?;
    let mut success_count = 0;
    let count = images.len() * 2;

    for image in images {
        println!("pushing {}:{}", image, commit);
        Command::new("docker")
            .current_dir(project_root())
            .args(["push", format!("n0computer/{}:{}", image, commit).as_str()])
            .status()?
            .success()
            .then(|| {
                success_count += 1;
            });

        println!("pushing {}:{}", image, commit);
        Command::new("docker")
            .current_dir(project_root())
            .args(["push", format!("n0computer/{}:latest", image).as_str()])
            .status()?
            .success()
            .then(|| {
                success_count += 1;
            });

        println!();
    }

    println!("{}/{} tags pushed.", success_count, count);
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
