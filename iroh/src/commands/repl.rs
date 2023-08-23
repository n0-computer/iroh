use anyhow::Result;
use clap::{Parser, Subcommand};
use colored::Colorize;
use iroh::client::quic::RpcClient;
use iroh_gossip::proto::util::base32;
use rustyline::{error::ReadlineError, Config, DefaultEditor};
use tokio::sync::{mpsc, oneshot};

use crate::{
    commands::sync,
    config::{ConsoleEnv, ConsolePaths},
};

pub async fn run(client: RpcClient, mut env: ConsoleEnv) -> Result<()> {
    println!("{}", "Welcome to the Iroh console!".purple().bold());
    println!("Type `{}` for a list of commands.", "help".bold());
    let mut repl_rx = Repl::spawn(env.clone());
    while let Some((event, reply)) = repl_rx.recv().await {
        let (next, res) = match event {
            ReplCmd::Rpc(super::RpcCommands::Sync(sync::Commands::Doc {
                command: sync::DocCommands::Switch { id },
            })) => {
                env.set_doc(id);
                (ToRepl::UpdateEnv(env.clone()), Ok(()))
            }
            ReplCmd::Rpc(super::RpcCommands::Sync(sync::Commands::Author {
                command: sync::AuthorCommands::Switch { id },
            })) => {
                let res = env.save_author(id);
                (ToRepl::UpdateEnv(env.clone()), res)
            }
            ReplCmd::Rpc(cmd) => {
                let res = cmd.run(client.clone(), env.clone()).await;
                (ToRepl::Continue, res)
            }
            ReplCmd::Exit => (ToRepl::Exit, Ok(())),
        };

        if let Err(err) = res {
            println!("{} {:?}", "Error:".red().bold(), err)
        }

        reply.send(next).ok();
    }
    Ok(())
}

/// Reply to the repl after a command completed
#[derive(Debug)]
pub enum ToRepl {
    /// Continue execution by reading the next command
    Continue,
    /// Continue execution by reading the next command, and update the repl state
    UpdateEnv(ConsoleEnv),
    /// Exit the repl
    Exit,
}

pub struct Repl {
    env: ConsoleEnv,
    cmd_tx: mpsc::Sender<(ReplCmd, oneshot::Sender<ToRepl>)>,
}
impl Repl {
    pub fn spawn(env: ConsoleEnv) -> mpsc::Receiver<(ReplCmd, oneshot::Sender<ToRepl>)> {
        let (cmd_tx, cmd_rx) = mpsc::channel(1);
        let repl = Repl { env, cmd_tx };
        std::thread::spawn(move || {
            if let Err(err) = repl.run() {
                println!("> repl crashed: {err}");
            }
        });
        cmd_rx
    }
    pub fn run(mut self) -> anyhow::Result<()> {
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
                    if let Some(cmd) = cmd {
                        self.cmd_tx.blocking_send((cmd, reply_tx))?;
                    } else {
                        continue;
                    }
                }
                Err(ReadlineError::Interrupted | ReadlineError::Eof) => {
                    self.cmd_tx.blocking_send((ReplCmd::Exit, reply_tx))?;
                }
                Err(ReadlineError::WindowResized) => continue,
                Err(err) => return Err(err.into()),
            }
            // wait for reply from main thread
            match reply_rx.blocking_recv()? {
                ToRepl::UpdateEnv(env) => {
                    self.env = env;
                }
                ToRepl::Continue => {}
                ToRepl::Exit => break,
            }
        }
        rl.save_history(&history_path).ok();
        Ok(())
    }

    pub fn prompt(&self) -> String {
        let mut pwd = String::new();
        if let Some(author) = &self.env.author {
            pwd.push_str(&format!(
                "{}{} ",
                "author:".blue(),
                fmt_short(author.as_bytes()).blue().bold(),
            ));
        }
        if let Some(doc) = &self.env.doc {
            pwd.push_str(&format!(
                "{}{} ",
                "doc:".blue(),
                fmt_short(doc.as_bytes()).blue().bold(),
            ));
        }
        if !pwd.is_empty() {
            pwd.push_str("\n");
        }
        format!("\n{pwd}{}", "> ".blue())
    }
}

#[derive(Debug, Parser)]
pub enum ReplCmd {
    #[clap(flatten)]
    Rpc(#[clap(subcommand)] super::RpcCommands),
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

fn fmt_short(bytes: impl AsRef<[u8]>) -> String {
    let bytes = bytes.as_ref();
    // we use 5 bytes because this always results in 8 character string in base32
    let len = bytes.len().min(5);
    base32::fmt(&bytes[..len])
}
