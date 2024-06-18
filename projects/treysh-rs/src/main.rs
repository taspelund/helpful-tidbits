use std::env::{current_dir, set_current_dir};
use std::io;
use std::io::Write;
use std::process::{Child, Command, Stdio};

macro_rules! help_text {
    () => {
        "Enter program names and arguments and hit enter to execute.
The following ar built into treysh:
  - cd
  - clear
  - exit
  - help
  - pwd
  - quit
"
    };
}

macro_rules! help {
    () => {
        println!(help_text!())
    };
}

macro_rules! welcome {
    () => {
        println!("Welcome to Trey Aspelund's treysh-rs!\n")
    };
}

macro_rules! ascii_clear {
    /*
      Print ANSI control sequence to clear screen.
        1B = ANSI ESC char
        [H = Move Cursor to Row 1, Column 1
        [J = Clear entire screen
    */
    () => {
        print!("\x1B[H\x1B[J")
    };
}

fn main() {
    let mut input = String::new();
    welcome!();

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
                "cd" => match set_current_dir(args.next().unwrap()) {
                    Ok(_) => (),
                    Err(e) => eprintln!("{e}"),
                },
                "clear" => ascii_clear!(),
                "exit" => return,
                "help" => help!(),
                "pwd" => {
                    if let Ok(wd) = current_dir() {
                        println!("{}", wd.display());
                    }
                }
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
