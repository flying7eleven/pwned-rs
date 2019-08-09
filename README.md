# pwned-rs
[![Build Status](https://travis-ci.org/thuetz/pwned-rs.svg?branch=master)](https://travis-ci.org/thuetz/pwned-rs)

A simple tool to process the password hash files provided by [haveibeenpwned.com](https://haveibeenpwned.com). I've written
this tool to learn more about rust and to fulfill by own needs. Maybe it's also useful for someone else. Feel free to play
around with it or submit PRs.

## How to use
The tool does have different modes in which it can run. First, you have to start to optimize the password hash
file. This will group the password hashes by a prefix in seperate files in which it can lookup hashes quite quick. This
optimization process is started by typing

```shell script
pwned-rs optimize /path/to/the/password/hash/file.txt /output/folder
```

This can be a lengthy process which takes at least an hour. After this optimization process, the search for a password in
this database is quickly done by typing

```shell script
pwned-rs lookup /path/to/optimized/database
```