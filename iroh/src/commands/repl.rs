use anyhow::Result;
use clap::{Parser, Subcommand};
use colored::Colorize;
use iroh::client::quic::Iroh;
use rustyline::{error::ReadlineError, Config, DefaultEditor};
use tokio::sync::{mpsc, oneshot};

use crate::{
    commands::{sync::fmt_short, RpcCommands},
    config::{ConsoleEnv, ConsolePaths},
};

pub async fn run(iroh: &Iroh, env: &ConsoleEnv) -> Result<()> {
    println!("{}", "Welcome to the Iroh console!".purple().bold());
    println!("Type `{}` for a list of commands.", "help".bold());
    let mut from_repl = Repl::spawn(env.clone());
    while let Some((cmd, reply)) = from_repl.recv().await {
        // allow to abort a running command with Ctrl-C
        tokio::select! {
            biased;
            _ = tokio::signal::ctrl_c() => {},
            res = cmd.run(iroh, env) => {
                if let Err(err) = res {
                    println!("{} {:?}", "Error:".red().bold(), err)
                }
            }
        }
        reply.send(()).ok();
    }
    Ok(())
}

pub struct Repl {
    env: ConsoleEnv,
    cmd_tx: mpsc::Sender<(RpcCommands, oneshot::Sender<()>)>,
}
impl Repl {
    pub fn spawn(env: ConsoleEnv) -> mpsc::Receiver<(RpcCommands, oneshot::Sender<()>)> {
        let (cmd_tx, cmd_rx) = mpsc::channel(1);
        let repl = Repl { env, cmd_tx };
        std::thread::spawn(move || {
            if let Err(err) = repl.run() {
                println!("> repl crashed: {err}");
            }
        });
        cmd_rx
    }
    pub fn run(self) -> anyhow::Result<()> {
        let mut rl =
            DefaultEditor::with_config(Config::builder().check_cursor_position(true).build())?;
        let history_path = ConsolePaths::History.with_env()?;
        rl.load_history(&history_path).ok();
        loop {
            // prepare a channel to receive a signal from the main thread when a command completed
            let (reply_tx, reply_rx) = oneshot::channel();
            let readline = rl.readline(&self.prompt());
            match readline {
                Ok(line) if line.is_empty() => continue,
                Ok(line) => {
                    rl.add_history_entry(line.as_str())?;
                    let cmd = parse_cmd::<ReplCmd>(&line);
                    match cmd {
                        None => continue,
                        Some(ReplCmd::Exit) => break,
                        Some(ReplCmd::Rpc(cmd)) => self.cmd_tx.blocking_send((cmd, reply_tx))?,
                    }
                }
                Err(ReadlineError::Eof) => break,
                Err(ReadlineError::Interrupted | ReadlineError::WindowResized) => continue,
                Err(err) => return Err(err.into()),
            }
            // wait for reply from main thread
            reply_rx.blocking_recv()?;
        }
        rl.save_history(&history_path).ok();
        Ok(())
    }

    pub fn prompt(&self) -> String {
        let mut pwd = String::new();
        if let Some(author) = &self.env.author(None).ok() {
            pwd.push_str(&format!(
                "{}{} ",
                "author:".blue(),
                fmt_short(author.as_bytes()).blue().bold(),
            ));
        }
        if let Some(doc) = &self.env.doc(None).ok() {
            pwd.push_str(&format!(
                "{}{} ",
                "doc:".blue(),
                fmt_short(doc.as_bytes()).blue().bold(),
            ));
        }
        if !pwd.is_empty() {
            pwd.push('\n');
        }
        format!("\n{pwd}{}", "> ".blue())
    }
}

#[derive(Debug, Parser)]
pub enum ReplCmd {
    #[clap(flatten)]
    Rpc(#[clap(subcommand)] RpcCommands),
    /// Quit the Iroh console
    #[clap(alias = "quit")]
    Exit,
}

fn try_parse_cmd<C: Subcommand>(s: &str) -> anyhow::Result<C> {
    let args = shell_words::split(s)?;
    let cmd = clap::Command::new("repl");
    let cmd = C::augment_subcommands(cmd);
    let matches = cmd
        .multicall(true)
        .subcommand_required(true)
        .try_get_matches_from(args)?;
    let cmd = C::from_arg_matches(&matches)?;
    Ok(cmd)
}

fn parse_cmd<C: Subcommand>(s: &str) -> Option<C> {
    match try_parse_cmd::<C>(s) {
        Ok(cmd) => Some(cmd),
        Err(err) => {
            println!("{err}");
            None
        }
    }
}
