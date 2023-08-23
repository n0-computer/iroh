use ansi_term::Colour;
use anyhow::Result;
use clap::{Parser, Subcommand};
use iroh::client::quic::{Iroh, RpcClient};
use iroh_gossip::proto::util::base32;
use iroh_sync::sync::{AuthorId, NamespaceId};
use rustyline::{error::ReadlineError, Config, DefaultEditor};
use tokio::sync::{mpsc, oneshot};

use super::sync::SyncEnv;

pub async fn run(client: RpcClient, env: SyncEnv) -> Result<()> {
    println!("Welcome to the Iroh console!");
    println!("Type `help` for a list of commands.");
    let mut state = ReplState::with_env(env);
    let mut repl_rx = Repl::spawn(state.clone());
    while let Some((event, reply)) = repl_rx.recv().await {
        let (next, res) = match event {
            FromRepl::DocCmd { id, cmd, env } => {
                let iroh = Iroh::new(client.clone());
                let res = cmd.run(&iroh, id, env).await;
                (ToRepl::Continue, res)
            }
            FromRepl::RpcCmd { cmd } => {
                let res = cmd.run(client.clone()).await;
                (ToRepl::Continue, res)
            }
            FromRepl::ReplCmd { cmd } => match cmd {
                ReplCmd::SetDoc { id } => {
                    state.pwd = Pwd::Doc { id };
                    (ToRepl::UpdateState(state.clone()), Ok(()))
                }
                ReplCmd::SetAuthor { id } => {
                    let res = state.env.set_author(id).await;
                    (ToRepl::UpdateState(state.clone()), res)
                }
                ReplCmd::Close => {
                    state.pwd = Pwd::Home;
                    (ToRepl::UpdateState(state.clone()), Ok(()))
                }
                ReplCmd::Exit => (ToRepl::Exit, Ok(())),
            },
        };

        if let Err(err) = res {
            println!(
                "{} {:?}",
                ansi_term::Colour::Red.bold().paint("Error:"),
                err
            )
        }

        reply.send(next).ok();
    }
    Ok(())
}

#[derive(Debug)]
pub enum FromRepl {
    RpcCmd {
        cmd: super::RpcCommands,
    },
    DocCmd {
        id: NamespaceId,
        env: SyncEnv,
        cmd: super::sync::Doc,
    },
    ReplCmd {
        cmd: ReplCmd,
    },
}

/// Reply to the repl after a command completed
#[derive(Debug)]
pub enum ToRepl {
    /// Continue execution by reading the next command
    Continue,
    /// Continue execution by reading the next command, and update the repl state
    UpdateState(ReplState),
    /// Exit the repl
    Exit,
}

pub struct Repl {
    state: ReplState,
    cmd_tx: mpsc::Sender<(FromRepl, oneshot::Sender<ToRepl>)>,
}
impl Repl {
    pub fn spawn(state: ReplState) -> mpsc::Receiver<(FromRepl, oneshot::Sender<ToRepl>)> {
        let (cmd_tx, cmd_rx) = mpsc::channel(1);
        let repl = Repl { state, cmd_tx };
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
        loop {
            // prepare a channel to receive a signal from the main thread when a command completed
            let (to_repl_tx, to_repl_rx) = oneshot::channel();
            let readline = rl.readline(&self.state.prompt());
            match readline {
                Ok(line) if line.is_empty() => continue,
                Ok(line) => {
                    rl.add_history_entry(line.as_str())?;
                    let cmd = self.state.handle_command(&line);
                    if let Some(cmd) = cmd {
                        self.cmd_tx.blocking_send((cmd, to_repl_tx))?;
                    } else {
                        continue;
                    }
                }
                Err(ReadlineError::Interrupted | ReadlineError::Eof) => {
                    self.cmd_tx
                        .blocking_send((FromRepl::ReplCmd { cmd: ReplCmd::Exit }, to_repl_tx))?;
                }
                Err(ReadlineError::WindowResized) => continue,
                Err(err) => return Err(err.into()),
            }
            // wait for reply from main thread
            match to_repl_rx.blocking_recv()? {
                ToRepl::UpdateState(state) => {
                    self.state = state;
                    continue;
                }
                ToRepl::Continue => continue,
                ToRepl::Exit => break,
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone)]
pub struct ReplState {
    pwd: Pwd,
    env: SyncEnv,
}

impl ReplState {
    fn with_env(env: SyncEnv) -> Self {
        Self {
            pwd: Pwd::Home,
            env,
        }
    }
}

#[derive(Debug, Clone)]
enum Pwd {
    Home,
    Doc { id: NamespaceId },
}

impl ReplState {
    pub fn prompt(&self) -> String {
        let bang = Colour::Blue.paint("> ");
        let pwd = match self.pwd {
            Pwd::Home => None,
            Pwd::Doc { id } => {
                let author = match self.env.author().as_ref() {
                    Some(author) => fmt_short(author.as_bytes()),
                    None => "<unset>".to_string(),
                };
                let pwd = format!("doc:{} author:{}", fmt_short(id.as_bytes()), author);
                let pwd = Colour::Blue.paint(pwd);
                Some(pwd.to_string())
            }
        };
        let pwd = pwd.map(|pwd| format!("{}\n", pwd)).unwrap_or_default();
        format!("\n{pwd}{bang}")
    }

    pub fn handle_command(&mut self, line: &str) -> Option<FromRepl> {
        match self.pwd {
            Pwd::Home => match parse_cmd::<HomeCommands>(line)? {
                HomeCommands::Repl(cmd) => Some(FromRepl::ReplCmd { cmd }),
                HomeCommands::Rpc(cmd) => Some(FromRepl::RpcCmd { cmd }),
            },
            Pwd::Doc { id } => match parse_cmd::<DocCommands>(line)? {
                DocCommands::Repl(cmd) => Some(FromRepl::ReplCmd { cmd }),
                DocCommands::Sync(cmd) => Some(FromRepl::RpcCmd {
                    cmd: super::RpcCommands::Sync(cmd),
                }),
                DocCommands::Doc(cmd) => Some(FromRepl::DocCmd {
                    id,
                    cmd,
                    env: self.env.clone(),
                }),
            },
        }
    }
}

#[derive(Debug, Parser)]
pub enum ReplCmd {
    /// Open a document
    #[clap(next_help_heading = "foo")]
    SetDoc { id: NamespaceId },
    /// Set the active author for doc insertion
    SetAuthor { id: AuthorId },
    /// Close the open document
    Close,

    /// Quit the Iroh console
    #[clap(alias = "quit")]
    Exit,
}

#[derive(Debug, Parser)]
pub enum DocCommands {
    #[clap(flatten)]
    Doc(#[clap(subcommand)] super::sync::Doc),
    #[clap(flatten)]
    Repl(#[clap(subcommand)] ReplCmd),
    // TODO: We can't embed RpcCommand here atm because there'd be a conflict between
    // `list` top level and `list` doc command
    // Thus for now only embedding sync commands
    #[clap(flatten)]
    Sync(#[clap(subcommand)] super::sync::Commands),
}

#[derive(Debug, Parser)]
pub enum HomeCommands {
    #[clap(flatten)]
    Repl(#[clap(subcommand)] ReplCmd),
    #[clap(flatten)]
    Rpc(#[clap(subcommand)] super::RpcCommands),
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
    let len = bytes.len().min(5);
    base32::fmt(&bytes[..len])
}
