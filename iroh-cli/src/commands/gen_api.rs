use anyhow::Context;
use clap::CommandFactory;

#[derive(serde::Serialize)]
struct ApiDef {
    name: String,
    description: String,
    // I have no idea what's this
    slug: String,
    arguments: Vec<ApiArg>,
    examples: Example,
}

#[derive(serde::Serialize)]
struct Example {
    console: String,
}

#[derive(serde::Serialize)]
struct ApiArg {
    name: String,
    necessity: &'static str,
    // required: bool,
    description: String,
}

const fn necessity(is_required: bool) -> &'static str {
    if is_required {
        "required"
    } else {
        ""
    }
}

// subcmd ex `blobs`, `tags`, etc
pub(crate) fn gen_json_api(subcmd: &str) -> anyhow::Result<()> {
    let cli = super::Cli::command();
    let cmd = cli
        .get_subcommands()
        .find(|cmd| cmd.get_name() == subcmd)
        .context("subcommand not found")?;
    let definitions = describe_cmd(cmd)?;
    let repr = serde_json::to_string_pretty(&definitions)
        .context("failed to write api descriptions")?
        .replace('\'', "\\'") // escape single quotes
        .replace("\"name\"", "name") // remove quotes around keys
        .replace("\"description\"", "description")
        .replace("\"slug\"", "slug")
        .replace("\"arguments\"", "arguments")
        .replace("\"necessity\"", "necessity")
        .replace("\"examples\"", "examples")
        .replace("\"console\"", "console")
        .replace('"', "'");
    println!("{repr}");
    Ok(())
}

/// Iterate the cmd subcommands and build an [`ApiDef`] for each.
///
/// The list is generated using recursive flattening. For instance, calling this function with the
/// blobs command will indlude an item with name `blobs list incomplete-blobs`
fn describe_cmd(cmd: &clap::Command) -> anyhow::Result<Vec<ApiDef>> {
    let mut cmds = Vec::with_capacity(cmd.get_subcommands().count());
    get_api_def(cmd, "", &mut cmds)?;
    Ok(cmds)
}

fn get_api_def(cmd: &clap::Command, parent: &str, acc: &mut Vec<ApiDef>) -> anyhow::Result<()> {
    let me = format!("{parent} {}", cmd.get_name()).trim().to_owned();
    if cmd.get_subcommands().next().is_some() {
        for subcmd in cmd.get_subcommands() {
            get_api_def(subcmd, &me, acc)?;
        }
    } else {
        let description = cmd
            .get_about()
            .map(|help_txt| help_txt.to_string())
            .unwrap_or_default();
        let mut arguments = Vec::default();
        for positional in cmd.get_positionals().filter_map(get_arg_def) {
            arguments.push(positional?);
        }
        for flag_def in cmd.get_opts().filter_map(get_arg_def) {
            arguments.push(flag_def?);
        }
        let console = format!("> {me}");
        acc.push(ApiDef {
            name: me.clone(),
            description,
            slug: me.replace(' ', "-"),
            arguments,
            examples: Example { console },
        })
    }
    Ok(())
}

/// Gets the [`ApiArg`] for this [`clap::Arg`].
///
/// Returns None if the arg is hidden.
fn get_arg_def(arg: &clap::Arg) -> Option<anyhow::Result<ApiArg>> {
    (!arg.is_hide_set()).then(|| get_arg_def_inner(arg))
}

/// Unconditionall gets the [`ApiArg`] for this [`clap::Arg`].
fn get_arg_def_inner(arg: &clap::Arg) -> anyhow::Result<ApiArg> {
    let name = if let Some(long) = arg.get_long() {
        long.to_owned()
    } else if let Some(value_names) = arg.get_value_names() {
        value_names
            .first()
            .expect("clap returned Some with an empty array")
            .as_str()
            .to_ascii_lowercase()
    } else if let Some(short) = arg.get_short() {
        short.to_string()
    } else {
        anyhow::bail!("arg without a name")
    };
    let description = arg
        .get_help()
        .map(|help_txt| help_txt.to_string())
        .unwrap_or_default();
    let required = arg.is_required_set() || arg.is_positional();
    Ok(ApiArg {
        name,
        necessity: necessity(required),
        description,
    })
}
