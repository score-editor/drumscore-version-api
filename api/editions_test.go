package main

import (
	"path/filepath"
	"testing"
)

// An edition nobody stated is "unknown", the dashboard says which product it is
// showing, and a dropped event is counted where somebody will see it (#13).
//
// "studio" used to be the answer for anything blank or unrecognised, so one
// word meant a licensed user, an unlicensed user whose header went missing, and
// every row from before the column existed. Alan, 17 Nov 2026: "Definitely do
// not default unknowns to Studio."

func TestAnUnstatedEditionIsUnknownNotStudio(t *testing.T) {
	for _, said := range []string{"", "  ", "pro", "STUDIO EDITION", "null"} {
		if got := normalizeEdition(said); got != "unknown" {
			t.Errorf("normalizeEdition(%q) = %q; an edition nobody stated was recorded as one", said, got)
		}
	}
	for said, want := range map[string]string{"studio": "studio", " Community ": "community", "STUDIO": "studio"} {
		if got := normalizeEdition(said); got != want {
			t.Errorf("normalizeEdition(%q) = %q, want %q", said, got, want)
		}
	}
}

func TestTheDashboardFilterTakesAVersionAndAnEdition(t *testing.T) {
	f, ok := parseDashboardFilter(" 4.0.0 ", "Community")
	if !ok || f.Version != "4.0.0" || f.Edition != "community" {
		t.Fatalf("a plain version and edition were refused or changed: %+v %v", f, ok)
	}
	clause, args := f.clause("s.")
	if clause != " AND s.app_version = ? AND s.edition = ?" || len(args) != 2 || args[0] != "4.0.0" || args[1] != "community" {
		t.Errorf("the filter does not narrow the query to what was asked: %q %v", clause, args)
	}
	if none, ok := parseDashboardFilter("", ""); !ok || none != (dashboardFilter{}) {
		t.Errorf("no filter at all was refused: %+v %v", none, ok)
	}
	if clause, args := (dashboardFilter{}).clause(""); clause != "" || len(args) != 0 {
		t.Errorf("no filter still narrowed the query: %q %v", clause, args)
	}
	if _, ok := parseDashboardFilter("", "unknown"); !ok {
		t.Error("unknown is recorded, so it must be possible to look at it")
	}
}

func TestTheDashboardFilterRefusesWhatIsNotAVersionOrAnEdition(t *testing.T) {
	// These go into a page and a query. The query takes them as arguments, but
	// a filter that accepts anything is one that shows an empty dashboard for a
	// typing mistake and calls it data.
	for _, version := range []string{"4.0.0' OR '1'='1", "<script>", "4.0.0 ", "-4", "a b", "0123456789012345678901234567890123"} {
		if version == "4.0.0 " {
			continue // trimmed, and fine
		}
		if _, ok := parseDashboardFilter(version, ""); ok {
			t.Errorf("%q was taken for a version", version)
		}
	}
	for _, edition := range []string{"pro", "studio'--", "all"} {
		if _, ok := parseDashboardFilter("", edition); ok {
			t.Errorf("%q was taken for an edition", edition)
		}
	}
}

func TestRejectedEventsAreCountedByReason(t *testing.T) {
	db, err := initDatabase(filepath.Join(t.TempDir(), "analytics.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	recordRejections(db, "2026-11-21", "4.0.0", "community", map[string]int{"unknown feature name: file_teleport": 3})
	recordRejections(db, "2026-11-21", "4.0.0", "community", map[string]int{"unknown feature name: file_teleport": 2, "timestamp too old": 1})
	recordRejections(db, "2026-11-21", "3.6.7", "studio", map[string]int{"timestamp too old": 3})

	all, err := rejectionsSince(db, "'2026-11-01'", dashboardFilter{})
	if err != nil {
		t.Fatal(err)
	}
	if len(all) != 2 || all[0].Reason != "unknown feature name: file_teleport" || all[0].Events != 5 ||
		all[1].Reason != "timestamp too old" || all[1].Events != 4 {
		t.Errorf("two batches of the same reason were not added together, most first: %+v", all)
	}

	four, err := rejectionsSince(db, "'2026-11-01'", dashboardFilter{Version: "4.0.0"})
	if err != nil {
		t.Fatal(err)
	}
	var old int64
	for _, c := range four {
		if c.Reason == "timestamp too old" {
			old = c.Events
		}
	}
	if old != 1 {
		t.Errorf("filtered to 4.0.0, 3.6.7's rejections were still counted: %+v", four)
	}

	later, err := rejectionsSince(db, "'2026-12-01'", dashboardFilter{})
	if err != nil {
		t.Fatal(err)
	}
	if len(later) != 0 {
		t.Errorf("rejections from before the period were shown in it: %+v", later)
	}
}

func TestANewDatabaseDefaultsTheEditionToUnknown(t *testing.T) {
	db, err := initDatabase(filepath.Join(t.TempDir(), "analytics.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err := db.Exec(`INSERT INTO version_checks (client_id, app_version) VALUES ('x', 'macos-aarch64-4.0.0')`); err != nil {
		t.Fatal(err)
	}
	var edition string
	if err := db.QueryRow(`SELECT edition FROM version_checks WHERE client_id = 'x'`).Scan(&edition); err != nil {
		t.Fatal(err)
	}
	if edition != "unknown" {
		t.Errorf("a row that stated no edition was stored as %q", edition)
	}
}
