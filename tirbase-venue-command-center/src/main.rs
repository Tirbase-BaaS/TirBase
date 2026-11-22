// SPDX-License-Identifier: AGPL-3.0-only

use std::env;

fn main() -> std::io::Result<()> {
    let mut port = 4190u16;
    let mut args = env::args().skip(1);
    while let Some(arg) = args.next() {
        if arg == "--port" {
            port = args
                .next()
                .and_then(|value| value.parse().ok())
                .unwrap_or(4190);
        }
    }
    tirbase_venue_command_center::http::run(port)
}
