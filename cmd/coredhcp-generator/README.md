## CoreDHCP Generator

`coredhcp-generator` builds a CoreDHCP `main.go` with exactly the plugins you
want.

Why is it needed? Go is a compiled language with no dynamic loading, so a
plugin has to be compiled in. The standard [main.go](/cmd/coredhcp/main.go)
includes the built-in plugins; anything more, or less, means generating your
own.

Pass plugins as import paths, as bare names (which resolve to the built-in
`plugins/` directory), from a file with one import path per line, or any mix:

```
$ go build
$ ./coredhcp-generator serverid file range
2026/08/19 12:09:36 Generating output file '/tmp/coredhcp2214597915/coredhcp.go' with 3 plugin(s):
2026/08/19 12:09:36   1) github.com/coredhcp/coredhcp/plugins/file
2026/08/19 12:09:36   2) github.com/coredhcp/coredhcp/plugins/range
2026/08/19 12:09:36   3) github.com/coredhcp/coredhcp/plugins/serverid
2026/08/19 12:09:36 Generated file '/tmp/coredhcp2214597915/coredhcp.go'. You can build it by running 'go build' in the output directory.
/tmp/coredhcp2214597915
```

The last line is the output directory on its own, so it can feed a script.
`--from core-plugins.txt` reads the built-in plugin list, and `-o` writes to a
chosen path instead of a temporary directory:

```
$ ./coredhcp-generator --from core-plugins.txt \
    github.com/coredhcp/plugins/redis
```

## Building the generated file

The output directory holds a single `coredhcp.go` and no `go.mod`. Create one
that points back at your checkout, then build:

```
$ cd /tmp/coredhcp2214597915
$ go mod init coredhcp
$ go mod edit -replace github.com/coredhcp/coredhcp=/path/to/your/checkout
$ go mod tidy
$ go build
```

This is exactly what the build workflow does in CI, where the result is also
diffed against the checked-in main.go to keep the two in sync.
