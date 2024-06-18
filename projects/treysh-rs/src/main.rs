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
        let mut commands = input.trim_end().split_terminator('|').peekable();
        let mut last_cmd: Option<Child> = None;

        // loop over all commands that aren't None
        while let Some(cmdline) = commands.next() {
            let mut args = cmdline.split_whitespace();
            let cmd = args.next().unwrap();

            match cmd {
                "exit" => return,
                "quit" => return,
                cmd => {
                    let input = match last_cmd {
                        // stdout from last cmd
                        Some(mut last_c) => Stdio::from(last_c.stdout.take().unwrap()),
                        // stdin of parent (default)
                        None => Stdio::inherit(),
                    };

                    let output = match commands.peek() {
                        // stdin of next cmd
                        Some(_) => Stdio::piped(),
                        // stdout of parent (default)
                        None => Stdio::inherit(),
                    };

                    last_cmd = match Command::new(cmd)
                        .args(args)
                        .stdin(input)
                        .stdout(output)
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
        if let Some(mut c) = last_cmd {
            let _ = c.wait();
        }
        input.clear();
    }
}
