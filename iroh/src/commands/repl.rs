use ansi_term::Colour;
use clap::{Parser, Subcommand};
use iroh::client::quic::{Iroh, RpcClient};
use iroh_gossip::proto::util::base32;
use iroh_sync::sync::{AuthorId, NamespaceId};
use rustyline::{error::ReadlineError, Config, DefaultEditor};
use tokio::sync::{mpsc, oneshot};

use super::sync::DocEnv;

pub async fn run(client: RpcClient) -> anyhow::Result<()> {
    println!("Welcome to the Iroh console!");
    println!("Type `help` for a list of commands.");
    let mut repl_rx = Repl::spawn();
    while let Some((event, reply)) = repl_rx.recv().await {
        let (next, res) = match event {
            FromRepl::DocCmd { id, cmd, doc_env } => {
                let iroh = Iroh::new(client.clone());
                let res = cmd.run(&iroh, id, doc_env).await;
                (ToRepl::Continue, res)
            }
            FromRepl::RpcCmd { cmd } => {
                let res = cmd.run(client.clone()).await;
                (ToRepl::Continue, res)
            }
            FromRepl::Exit => (ToRepl::Exit, Ok(())),
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
        doc_env: DocEnv,
        cmd: super::sync::Doc,
    },
    Exit,
}

#[derive(Debug)]
pub enum ToRepl {
    Continue,
    Exit,
}

pub struct Repl {
    state: ReplState,
    cmd_tx: mpsc::Sender<(FromRepl, oneshot::Sender<ToRepl>)>,
}
impl Repl {
    pub fn spawn() -> mpsc::Receiver<(FromRepl, oneshot::Sender<ToRepl>)> {
        let (cmd_tx, cmd_rx) = mpsc::channel(1);
        let repl = Repl {
            state: ReplState::from_env(),
            cmd_tx,
        };
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
                    let cmd = self.state.parse_command(&line);
                    if let Some(cmd) = cmd {
                        self.cmd_tx.blocking_send((cmd, to_repl_tx))?;
                    } else {
                        continue;
                    }
                }
                Err(ReadlineError::Interrupted | ReadlineError::Eof) => {
                    self.cmd_tx.blocking_send((FromRepl::Exit, to_repl_tx))?;
                }
                Err(ReadlineError::WindowResized) => continue,
                Err(err) => return Err(err.into()),
            }
            // wait for reply from main thread
            match to_repl_rx.blocking_recv()? {
                ToRepl::Continue => continue,
                ToRepl::Exit => break,
            }
        }
        Ok(())
    }
}

pub struct ReplState {
    pwd: Pwd,
    doc_env: DocEnv,
}

impl ReplState {
    fn from_env() -> Self {
        Self {
            pwd: Pwd::Home,
            doc_env: DocEnv::from_env().unwrap_or_default(),
        }
    }
}

#[derive(Debug)]
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
                let author = self
                    .doc_env
                    .author
                    .map(|author| format!(" author:{}", fmt_short(author.as_bytes())))
                    .map(|author| Colour::Red.paint(author).to_string())
                    .unwrap_or_default();
                let pwd = format!("doc:{}{author}", fmt_short(id.as_bytes()));
                let pwd = Colour::Blue.paint(pwd);
                Some(pwd.to_string())
            }
        };
        let pwd = pwd.map(|pwd| format!("{}\n", pwd)).unwrap_or_default();
        format!("\n{pwd}{bang}")
    }

    pub fn parse_command(&mut self, line: &str) -> Option<FromRepl> {
        match self.pwd {
            Pwd::Home => match parse_cmd::<HomeCommands>(line)? {
                HomeCommands::Repl(cmd) => self.process_repl_command(cmd),
                HomeCommands::Rpc(cmd) => Some(FromRepl::RpcCmd { cmd }),
            },
            Pwd::Doc { id } => match parse_cmd::<DocCommands>(line)? {
                DocCommands::Repl(cmd) => self.process_repl_command(cmd),
                DocCommands::Sync(cmd) => Some(FromRepl::RpcCmd {
                    cmd: super::RpcCommands::Sync(cmd),
                }),
                DocCommands::Doc(cmd) => Some(FromRepl::DocCmd {
                    id,
                    cmd,
                    doc_env: self.doc_env.clone(),
                }),
            },
        }
    }

    fn process_repl_command(&mut self, command: ReplCommand) -> Option<FromRepl> {
        match command {
            ReplCommand::SetDoc { id } => {
                self.pwd = Pwd::Doc { id };
                None
            }
            ReplCommand::SetAuthor { id } => {
                self.doc_env.author = Some(id);
                None
            }
            ReplCommand::Close => {
                self.pwd = Pwd::Home;
                None
            }
            ReplCommand::Exit => Some(FromRepl::Exit),
        }
    }
}

#[derive(Debug, Parser)]
pub enum ReplCommand {
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
    Repl(#[clap(subcommand)] ReplCommand),
    // TODO: We can't embed RpcCommand here atm because there'd be a conflict between
    // `list` top level and `list` doc command
    // Thus for now only embedding sync commands
    #[clap(flatten)]
    Sync(#[clap(subcommand)] super::sync::Commands),
}

#[derive(Debug, Parser)]
pub enum HomeCommands {
    #[clap(flatten)]
    Repl(#[clap(subcommand)] ReplCommand),
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
