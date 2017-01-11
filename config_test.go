package main

import (
	"bytes"
	"encoding/json"
	"io/ioutil"
	"os"
	"path"
	"strings"
	"testing"
	"time"
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
			err := cfg.mergeFlags(uint16(*port), Duration(*blocktime), *autodelete, *verbose)
			if err != nil {
				t.Error(err)
			}
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
}

func TestReadConfig(t *testing.T) {
	files, err := ioutil.ReadDir("testdata")
	if err != nil {
		t.Fatal(err)
	}
	for _, file := range files {
		if !file.Mode().IsRegular() || !strings.HasSuffix(file.Name(), ".in") {
			continue
		}
		t.Run(strings.TrimSuffix(file.Name(), ".in"), func(t *testing.T) {
			fname := path.Join("testdata", file.Name())
			rname := strings.TrimSuffix(fname, "in")
			var expectOk bool
			if st, err := os.Stat(rname + "out"); err == nil && st.Mode().IsRegular() {
				expectOk = true
			}
			if st, err := os.Stat(rname + "err"); err == nil && st.Mode().IsRegular() {
				if expectOk {
					t.Fatalf("%s: not expecting both .out and .err files", file.Name())
				}
			}

			var buf bytes.Buffer
			cfg, err := newConfig(fname, 1234, Duration(5*time.Hour), true, true)
			if expectOk {
				if err != nil {
					t.Fatal(err)
				}
				enc := json.NewEncoder(&buf)
				enc.SetEscapeHTML(false)
				enc.SetIndent("", "    ")
				if err := enc.Encode(cfg); err != nil {
					t.Fatal(err)
				}
				rname += "out"
			} else {
				if err == nil {
					t.Fatalf("%s: expected error, got nil", file.Name())
				}
				buf.WriteString(err.Error())
				buf.WriteString("\n")
				rname += "err"
			}
			out, err := ioutil.ReadFile(rname)
			if err != nil {
				t.Fatal(err)
			}

			if !bytes.Equal(buf.Bytes(), out) {
				t.Errorf("%s: does not match expected output\n---\n%s---\n", file.Name(), buf.String())
			}
		})
	}
}
