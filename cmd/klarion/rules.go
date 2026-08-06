package main

import (
	"encoding/json"
	"fmt"
	"os"
	"text/tabwriter"

	"github.com/spf13/cobra"

	"github.com/0x1Adi/Klarion/internal/detect"
)

var rulesJSON bool

var rulesCmd = &cobra.Command{
	Use:   "rules",
	Short: "List the active detection rules",
	RunE: func(cmd *cobra.Command, args []string) error {
		cfg, err := loadConfig()
		if err != nil {
			return err
		}
		det, err := detect.New(cfg)
		if err != nil {
			return err
		}
		rs := det.Rules()

		if rulesJSON {
			type ruleView struct {
				ID          string   `json:"id"`
				Description string   `json:"description"`
				Severity    string   `json:"severity"`
				Tags        []string `json:"tags,omitempty"`
			}
			views := make([]ruleView, len(rs))
			for i, r := range rs {
				views[i] = ruleView{r.ID, r.Description, string(r.Severity), r.Tags}
			}
			enc := json.NewEncoder(os.Stdout)
			enc.SetIndent("", "  ")
			return enc.Encode(views)
		}

		tw := tabwriter.NewWriter(os.Stdout, 0, 2, 2, ' ', 0)
		fmt.Fprintln(tw, "ID\tSEVERITY\tDESCRIPTION")
		for _, r := range rs {
			fmt.Fprintf(tw, "%s\t%s\t%s\n", r.ID, r.Severity, r.Description)
		}
		fmt.Fprintf(tw, "\n%d rules active\n", len(rs))
		return tw.Flush()
	},
}

func init() {
	rulesCmd.Flags().BoolVar(&rulesJSON, "json", false, "output rules as JSON")
	rootCmd.AddCommand(rulesCmd)
}
