package main

import (
	"bytes"
	"encoding/json"
	"io/ioutil"
	"path"
	"strings"
	"testing"
	"time"

	"gopkg.in/yaml.v2"
)

func TestFlagOverride(t *testing.T) {
	data := []struct {
		Name             string
		Override         string
		ExpectBlockTime  Duration
		ExpectAutoDelete bool
		ExpectVerbose    bool
		ExpectPort       uint16
	}{
		{"NoFlags", "", 0, false, false, 0},
		{"Blocktime", "-blocktime=8h", Duration(8 * time.Hour), false, false, 0},
		{"Autodelete", "-autodelete", 0, true, false, 0},
		{"Verbose", "-verbose", 0, false, true, 0},
		{"Port", "-port=1234", 0, false, false, 1234},
		{"AllFlags", "-blocktime=16h -autodelete -verbose -port=5678", Duration(16 * time.Hour), true, true, 5678}}

	for _, d := range data {
		setFlags(strings.Split(d.Override, " ")...)
		t.Run(d.Name, func(t *testing.T) {
			var cfg Config
			cfg.mergeFlags(uint16(*port), Duration(*blocktime), *autodelete, *verbose)
			if cfg.Settings.BlockTime != d.ExpectBlockTime {
				t.Errorf("settings.blocktime: expected %v, actual %v", d.ExpectBlockTime, cfg.Settings.BlockTime)
			}
			if cfg.Settings.Port != d.ExpectPort {
				t.Errorf("settings.port: expected %v, actual %v", d.ExpectPort, cfg.Settings.Port)
			}
			if cfg.Settings.AutoDelete != d.ExpectAutoDelete {
				t.Errorf("settings.autodelete: expected %v, actual %v", d.ExpectAutoDelete, cfg.Settings.AutoDelete)
			}
			if cfg.Settings.Verbose != d.ExpectVerbose {
				t.Errorf("settings.verbose: expected %v, actual %v", d.ExpectVerbose, cfg.Settings.Verbose)
			}
		})
	}
	setFlags()
}

func TestReadConfig(t *testing.T) {
	files, err := ioutil.ReadDir("testdata")
	if err != nil {
		t.Fatal(err)
	}
	for _, file := range files {
		if !file.Mode().IsRegular() || !strings.HasSuffix(file.Name(), ".yml") {
			continue
		}
		t.Run(strings.TrimSuffix(file.Name(), ".yml"), func(t *testing.T) {
			var yml struct {
				In  string
				Out string
				Err []string
			}
			fname := path.Join("testdata", file.Name())
			data, err := ioutil.ReadFile(fname)
			if err != nil {
				t.Fatal(err)
			}
			if err = yaml.Unmarshal(data, &yml); err != nil {
				t.Fatal(err)
			}
			if len(yml.Err) != 0 && len(yml.Out) != 0 {
				t.Fatal("One cannot have both err: and out: set")
			}

			cfg, err := newConfigString(yml.In, 0, Duration(0*time.Hour), false, false)
			if len(yml.Out) != 0 {
				if err != nil {
					t.Fatal(err)
				}
				var buf bytes.Buffer
				enc := json.NewEncoder(&buf)
				enc.SetEscapeHTML(false)
				enc.SetIndent("", "    ")
				if err := enc.Encode(cfg); err != nil {
					t.Fatal(err)
				}
				if buf.String() != yml.Out {
					t.Errorf("%s: does not match expected output\n---\n%s---\n%s---\n", file.Name(), buf.String(), yml.Out)
				}
			} else {
				if err == nil {
					t.Fatalf("%s: expected error, got nil", file.Name())
				}
				var buf bytes.Buffer
				buf.WriteString(err.Error())

				found := false
				for _, e := range yml.Err {
					if buf.String() == e {
						found = true
						break
					}
				}
				if !found {
					t.Errorf("%s: does not match any of the expected errors\n---\n%s---\n%s---\n", file.Name(), buf.String(), yml.Err[0])
				}
			}
		})
	}
}
