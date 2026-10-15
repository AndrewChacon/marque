package main

import "github.com/spf13/cobra"

// newRootCmd builds a fresh command tree. Constructing it fresh (rather
// than a package-level var) keeps flag state from leaking between
// invocations — important for tests that call Execute() more than once.
func newRootCmd() *cobra.Command {
	root := &cobra.Command{
		Use:   "marque",
		Short: "Mechanical scope enforcement for pentest engagements",
		Long: `RedMarque enforces engagement scope mechanically instead of leaving it
to tester memory. Point it at a signed-off scope.yaml and it tells you,
precisely, whether a target is authorized right now.`,
		SilenceUsage:  true,
		SilenceErrors: true,
		Version:       versionDetails(),
	}
	root.AddCommand(newValidateCmd())
	root.AddCommand(newProxyCmd())
	root.AddCommand(newEngagementCmd())
	root.AddCommand(newRunCmd())
	root.AddCommand(newDoctorCmd())
	root.AddCommand(newProxychainsConfigCmd())
	root.AddCommand(newAuditCmd())
	root.AddCommand(newVersionCmd())
	return root
}
