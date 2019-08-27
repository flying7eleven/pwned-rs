# pwned-rs
[![Build Status](https://travis-ci.org/thuetz/pwned-rs.svg?branch=master)](https://travis-ci.org/thuetz/pwned-rs)

A simple tool to process the password hash files provided by [haveibeenpwned.com](https://haveibeenpwned.com). I've written
this tool to learn more about rust and to fulfill by own needs. Maybe it's also useful for someone else. Feel free to play
around with it or submit PRs.

## How to build the tool
This is one of the simples things to do. If you have [Rust]() installed, just type

```shell script
cargo build --release
```

in a terminal window. After a short period of time the tool is build and can be used. Please be sure that you've
provided the ```--release``` flag since otherwise the optimization process can take up to 10-times as long.

If you are running the tool on Linux, I recommend placing the binary in your path. An option - even though it's not
the recommended way - would be typing

```shell script
sudo cp target/release/pwned-rs /usr/bin
```

## How to use

### Prerequisites
As said above, the program just helps you searching offline in the password databases provided by
[haveibeenpwned.com](https://haveibeenpwned.com). Before you start, please visit
[https://haveibeenpwned.com/Passwords](https://haveibeenpwned.com/Passwords) and download the database in the **SHA-1**
format **ordered by hash**. This is quite important since the program is currently not designed to read the other
files correctly.

### Using the divide-and-conquer lookup
Afer downloading and extracting the password database, you can simply run

```shell script
pwned-rs quick-lookup /path/to/the/password/hash/file.txt
```

to search for password hashes inside the database.

### Using an "optimized" database (deprecated)
The tool does have different modes in which it can run. First, you have to start to "optimize" the password hash
file. This will group the password hashes by a prefix in separate files in which it can lookup hashes quite quick. This
"optimization" process is started by typing

```shell script
pwned-rs optimize /path/to/the/password/hash/file.txt /output/folder
```

It will run about 2 hours on a recently quick CPU and HDD/SSD combination. This process has to be done just a single time
and the single-file password hash file can be deleted afterwards.

After this optimization process, the search for a password in this database is quickly done by typing

```shell script
pwned-rs lookup /path/to/optimized/database
```

and follow the instructions given by the program itsemf.
