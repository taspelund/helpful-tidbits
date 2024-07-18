use std::env::{current_dir, set_current_dir};
use std::fs::File;
use std::io::{self, BufRead, Write};
use std::process::{self, Child, Command, Stdio};

macro_rules! help_text {
    () => {
        "Enter program names and arguments and hit enter to execute.
The following builtins are provided:
  - cd
  - clear
  - exit
  - help
  - memdump
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

fn hexdump_range(start: usize, stop: usize) {
    let b = start as *const u8;
    let e = stop as *const u8;
    let mut i: isize = 0;
    unsafe {
        while b.offset(i) < e {
            if i % 16 == 0 {
                if i > 15 {
                    println!();
                }
                print!("[{:p}]  ", b.offset(i));
            }
            print!("{:02X} ", *(b.offset(i)));
            i += 1;
        }
        println!();
    }
}

fn get_matching_memrange(pid: u32, pattern: &str) -> Option<(usize, usize)> {
    let file = File::open(format!("/proc/{}/maps", pid)).unwrap();
    let procbuf = io::BufReader::new(file);

    /*
    Example /proc/<pid>/maps output:
       % grep 'heap\|stack' /proc/$$/maps
       b61378cd6000-b61378fbc000 rw-p 00000000 00:00 0                          [heap]
       fffff9c0a000-fffff9c83000 rw-p 00000000 00:00 0                          [stack]
    */
    for line in procbuf.lines().map(|l| l.unwrap()) {
        if line.contains(pattern) {
            // get first column: <begin_addr>-<end_addr>
            let splits = line.split_whitespace().next().unwrap();
            // get iterator of those two
            let mut addrs = splits.split_terminator('-');
            let begin_addr = usize::from_str_radix(addrs.next().unwrap(), 16).unwrap();
            let end_addr = usize::from_str_radix(addrs.next().unwrap(), 16).unwrap();
            return Some((begin_addr, end_addr));
        }
    }
    None
}

fn get_self_meminfo() {
    let pid: u32 = process::id();

    println!("\n[stack]");
    match get_matching_memrange(pid, "[stack]") {
        Some((b, e)) => hexdump_range(b, e),
        None => eprintln!("Cannot find meminfo for stack"),
    };

    println!("\n[heap]");
    match get_matching_memrange(pid, "[heap]") {
        Some((b, e)) => hexdump_range(b, e),
        None => eprintln!("Cannot find meminfo for heap"),
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
                "memdump" => get_self_meminfo(),
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
