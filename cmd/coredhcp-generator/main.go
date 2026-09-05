// Copyright 2018-present the CoreDHCP Authors. All rights reserved
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

// The coredhcp-generator command renders a main.go for a coredhcp server
// with a chosen set of plugins compiled in.
package main

import (
	"bufio"
	"errors"
	"fmt"
	"log"
	"os"
	"path"
	"sort"
	"strings"
	"text/template"

	flag "github.com/spf13/pflag"
)

const (
	defaultTemplateFile = "coredhcp.go.template"
	importBase          = "github.com/coredhcp/coredhcp/"
)

var (
	flagTemplate = flag.StringP("template", "t", defaultTemplateFile, "Template file name")
	flagOutfile  = flag.StringP("outfile", "o", "", "Output file path")
	flagFromFile = flag.StringP("from", "f", "", "Optional file name to get the plugin list from, one import path per line")
)

var funcMap = template.FuncMap{
	"importname": func(importPath string) string {
		parts := strings.Split(importPath, "/")
		return "pl_" + parts[len(parts)-1]
	},
}

func usage() {
	_, _ = fmt.Fprintf(flag.CommandLine.Output(),
		"%s [-template tpl] [-outfile out] [-from pluginlist] [plugin [plugin...]]\n",
		os.Args[0],
	)
	flag.PrintDefaults()
	_, _ = fmt.Fprintln(flag.CommandLine.Output(), `  plugin
	Plugin name to include, as go import path.
	Short names can be used for builtin coredhcp plugins (eg "serverid")`)
}

func main() {
	flag.Usage = usage
	flag.Parse()
	if err := run(); err != nil {
		log.Fatal(err)
	}
}

func run() error {
	data, err := os.ReadFile(*flagTemplate)
	if err != nil {
		return fmt.Errorf("failed to read template file '%s': %w", *flagTemplate, err)
	}
	t, err := template.New("coredhcp").Funcs(funcMap).Parse(string(data))
	if err != nil {
		return fmt.Errorf("template parsing failed: %w", err)
	}

	pluginList, err := collectPlugins()
	if err != nil {
		return err
	}
	outfile, err := resolveOutfile()
	if err != nil {
		return err
	}

	log.Printf("Generating output file '%s' with %d plugin(s):", outfile, len(pluginList))
	for i, pl := range pluginList {
		log.Printf("% 3d) %s", i+1, pl)
	}
	if err := render(t, outfile, pluginList); err != nil {
		return err
	}
	log.Printf("Generated file '%s'. You can build it by running 'go build' in the output directory.", outfile)
	fmt.Println(path.Dir(outfile))
	return nil
}

func collectPlugins() ([]string, error) {
	plugins := make(map[string]bool)
	for _, pl := range flag.Args() {
		pl := strings.TrimSpace(pl)
		if pl == "" {
			continue
		}
		if !strings.ContainsRune(pl, '/') {
			// A bare name is assumed to be a builtin plugin. -from always takes
			// exact import paths, for anything this guess would get wrong.
			pl = importBase + "plugins/" + pl
		}
		plugins[pl] = true
	}
	if *flagFromFile != "" {
		if err := pluginsFromFile(*flagFromFile, plugins); err != nil {
			return nil, err
		}
	}
	if len(plugins) == 0 {
		return nil, errors.New("no plugin specified")
	}
	pluginList := make([]string, 0, len(plugins))
	for pl := range plugins {
		pluginList = append(pluginList, pl)
	}
	sort.Strings(pluginList)
	return pluginList, nil
}

func pluginsFromFile(fname string, plugins map[string]bool) error {
	fd, err := os.Open(fname)
	if err != nil {
		return fmt.Errorf("failed to read file '%s': %w", fname, err)
	}
	defer func() {
		if err := fd.Close(); err != nil {
			log.Printf("Error closing file '%s': %v", fname, err)
		}
	}()
	sc := bufio.NewScanner(fd)
	for sc.Scan() {
		pl := strings.TrimSpace(sc.Text())
		if pl == "" {
			continue
		}
		plugins[pl] = true
	}
	if err := sc.Err(); err != nil {
		return fmt.Errorf("error reading file '%s': %w", fname, err)
	}
	return nil
}

func resolveOutfile() (string, error) {
	if *flagOutfile != "" {
		return *flagOutfile, nil
	}
	tmpdir, err := os.MkdirTemp("", "coredhcp")
	if err != nil {
		return "", fmt.Errorf("cannot create temporary directory: %w", err)
	}
	return path.Join(tmpdir, "coredhcp.go"), nil
}

func render(t *template.Template, outfile string, pluginList []string) error {
	outFD, err := os.OpenFile(outfile, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return fmt.Errorf("failed to create output file '%s': %w", outfile, err)
	}
	defer func() {
		if err := outFD.Close(); err != nil {
			log.Printf("Error while closing file descriptor for '%s': %v", outfile, err)
		}
	}()
	// WARNING: no escaping of the provided strings is done
	if err := t.Execute(outFD, pluginList); err != nil {
		return fmt.Errorf("template execution failed: %w", err)
	}
	return nil
}
