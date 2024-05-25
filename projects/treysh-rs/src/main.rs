use std::io;
use std::io::Write;
use std::process::{Child, Command, Stdio};

fn main() {
    let mut input = String::new();

    loop {
        print!("--> ");
        // call .unwrap() so we panic upon I/O failure
        io::stdout().flush().unwrap();
        if io::stdin().read_line(&mut input).unwrap() == 0 {
            return; // EOF
        }

        // split by pipe to get individual commands
        let mut commands = input.trim_end().split_terminator("|").peekable();
        let mut last_cmd: Option<Child> = None;

        // loop over all commands that aren't None
        while let Some(cmdline) = commands.next() {
            let mut args = cmdline.split_whitespace();
            let cmd = args.next().unwrap();

            match cmd {
                "exit" => return,
                "quit" => return,
                cmd => {
                    // Choose source of stdin
                    let stdin = match last_cmd {
                        // use stdout from left side of pipe
                        Some(mut last_c) => Stdio::from(last_c.stdout.take().unwrap()),
                        // use stdin from parent (default)
                        None => Stdio::inherit(),
                    };
                    // Choose destination of stdout
                    let stdout = match commands.peek() {
                        // stdin(Stdio::from(<stuff>))
                        Some(_next) => Stdio::piped(),
                        None => Stdio::inherit(),
                    };

                    last_cmd = match Command::new(cmd)
                        .args(args)
                        .stdin(stdin)
                        .stdout(stdout)
                        .spawn()
                    {
                        Ok(child) => Some(child),
                        Err(e) => {
                            eprintln!("{e}");
                            None
                        }
                    }
                }
            }
        }
        if last_cmd.is_some() {
            let _ = last_cmd.unwrap().wait();
        }
        input.clear();
    }
}
