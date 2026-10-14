package main

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/AndrewChacon/red-marque/internal/engagement"
	"github.com/AndrewChacon/red-marque/pkg/scope"
	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"
)

func newEngagementAddCmd() *cobra.Command {
	return newEngagementAddCmdWithStore(nil)
}

func newEngagementAddCmdWithStore(injected *engagement.Store) *cobra.Command {
	var scopeFlag string

	cmd := &cobra.Command{
		Use:   "add <name>",
		Short: "Add a new engagement, from a wizard or an existing scope file",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			name := args[0]

			var doc []byte
			if scopeFlag != "" {
				data, err := os.ReadFile(scopeFlag)
				if err != nil {
					return fmt.Errorf("reading scope file: %w", err)
				}
				doc = data
			} else {
				generated, err := runWizard(cmd.InOrStdin(), cmd.OutOrStdout(), name)
				if err != nil {
					return err
				}
				doc = generated
			}

			if _, err := scope.Parse(doc); err != nil {
				return err
			}

			store, err := storeOrDefault(injected)
			if err != nil {
				return err
			}
			if err := store.Add(name, doc); err != nil {
				return err
			}

			fmt.Fprintf(cmd.OutOrStdout(), "added engagement %q (%s)\n", name, store.ScopePath(name))
			return nil
		},
	}

	cmd.Flags().StringVar(&scopeFlag, "scope", "", "import an existing scope.yaml instead of running the interactive wizard")
	return cmd
}

type wizardScopeFile struct {
	Engagement struct {
		Name   string `yaml:"name"`
		Client string `yaml:"client,omitempty"`
		Start  string `yaml:"start"`
		End    string `yaml:"end"`
	} `yaml:"engagement"`
	Scope struct {
		Include []string `yaml:"include"`
		Exclude []string `yaml:"exclude,omitempty"`
	} `yaml:"scope"`
}

// runWizard prompts for an engagement's details and returns the
// resulting scope-file YAML. name is already known (the add command's
// positional argument) and isn't re-prompted. I/O is separated from
// logic — r and w rather than real stdin/stdout — so this is testable
// with canned input through a bytes.Buffer, same pattern as every
// other command in this CLI.
func runWizard(r io.Reader, w io.Writer, name string) ([]byte, error) {
	scanner := bufio.NewScanner(r)

	prompt := func(label string) (string, error) {
		fmt.Fprintf(w, "%s: ", label)
		if !scanner.Scan() {
			if err := scanner.Err(); err != nil {
				return "", err
			}
			return "", io.ErrUnexpectedEOF
		}
		return strings.TrimSpace(scanner.Text()), nil
	}

	client, err := prompt("Client name")
	if err != nil {
		return nil, err
	}

	startStr, err := prompt("Engagement start date (YYYY-MM-DD)")
	if err != nil {
		return nil, err
	}
	start, err := parseWizardDate(startStr)
	if err != nil {
		return nil, err
	}

	endStr, err := prompt("Engagement end date (YYYY-MM-DD)")
	if err != nil {
		return nil, err
	}
	end, err := parseWizardDate(endStr)
	if err != nil {
		return nil, err
	}

	fmt.Fprintln(w, "Paste your in-scope CIDRs/domains (comma- or newline-separated, blank line to finish):")
	include, err := promptList(scanner)
	if err != nil {
		return nil, err
	}

	fmt.Fprintln(w, "Any exclusions? (comma- or newline-separated, blank line if none):")
	exclude, err := promptList(scanner)
	if err != nil {
		return nil, err
	}

	return buildScopeYAML(name, client, start, end, include, exclude)
}

func parseWizardDate(s string) (time.Time, error) {
	t, err := time.Parse("2006-01-02", s)
	if err != nil {
		return time.Time{}, fmt.Errorf("%q is not a valid date (expected YYYY-MM-DD): %w", s, err)
	}
	return t, nil
}

// promptList reads lines until a blank line or EOF, splitting each
// line on commas too — one prompt that accepts either a single
// comma-separated line or a multi-line paste, not one-at-a-time
// nagging per entry.
func promptList(scanner *bufio.Scanner) ([]string, error) {
	var all []string
	for scanner.Scan() {
		line := scanner.Text()
		if strings.TrimSpace(line) == "" {
			break
		}
		for _, part := range strings.Split(line, ",") {
			if part = strings.TrimSpace(part); part != "" {
				all = append(all, part)
			}
		}
	}
	return all, scanner.Err()
}

func buildScopeYAML(name, client string, start, end time.Time, include, exclude []string) ([]byte, error) {
	var f wizardScopeFile
	f.Engagement.Name = name
	f.Engagement.Client = client
	f.Engagement.Start = start.UTC().Format(time.RFC3339)
	f.Engagement.End = end.UTC().Format(time.RFC3339)
	f.Scope.Include = include
	f.Scope.Exclude = exclude
	return yaml.Marshal(f)
}
