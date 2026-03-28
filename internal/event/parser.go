package event

import (
	"encoding/xml"
	"fmt"
	"os/exec"
	"strings"
	"time"
)

// Unified XML structures for wevtutil output.

type xmlEvents struct {
	XMLName xml.Name   `xml:"Events"`
	Events  []xmlEvent `xml:"Event"`
}

type xmlEvent struct {
	System    xmlSystem    `xml:"System"`
	EventData xmlEventData `xml:"EventData"`
}

type xmlSystem struct {
	EventID     int    `xml:"EventID"`
	TimeCreated struct {
		SystemTime string `xml:"SystemTime,attr"`
	} `xml:"TimeCreated"`
	Computer string `xml:"Computer"`
	Channel  string `xml:"Channel"`
	Security struct {
		UserID string `xml:"UserID,attr"`
	} `xml:"Security"`
}

type xmlEventData struct {
	Data []xmlDataItem `xml:"Data"`
}

type xmlDataItem struct {
	Name  string `xml:"Name,attr"`
	Value string `xml:",chardata"`
}

func (d *xmlEventData) get(name string) string {
	for _, item := range d.Data {
		if item.Name == name {
			return item.Value
		}
	}
	return ""
}

// queryEvents runs wevtutil and parses results.
// logName: log channel or file path (with isFile=true)
// query: XPath query string
// maxEvents: max number of events to return
// isFile: if true, treat logName as an .evtx file path
func queryEvents(logName, query string, maxEvents int, isFile bool) ([]xmlEvent, error) {
	args := []string{"qe", logName}
	if isFile {
		args = append(args, "/lf:true")
	}
	args = append(args,
		fmt.Sprintf("/q:%s", query),
		fmt.Sprintf("/c:%d", maxEvents),
		"/f:xml", "/rd:true",
	)

	cmd := exec.Command("wevtutil", args...)
	out, err := cmd.Output()
	if err != nil {
		return nil, err
	}

	if len(out) == 0 {
		return nil, nil
	}

	xmlStr := "<Events>" + string(out) + "</Events>"
	var evts xmlEvents
	if err := xml.Unmarshal([]byte(xmlStr), &evts); err != nil {
		return nil, err
	}

	return evts.Events, nil
}

// parseTime converts event system time to local format.
func parseTime(systemTime string) string {
	for _, layout := range []string{
		time.RFC3339Nano,
		"2006-01-02T15:04:05.000000000Z",
		"2006-01-02T15:04:05.0000000Z",
		"2006-01-02T15:04:05Z",
	} {
		t, err := time.Parse(layout, systemTime)
		if err == nil {
			return t.Local().Format("2006-01-02 15:04:05")
		}
	}
	return systemTime
}

// timeFilter builds an XPath time filter for "within last N days".
func timeFilter(days int) string {
	ms := int64(days) * 24 * 60 * 60 * 1000
	return fmt.Sprintf("timediff(@SystemTime) <= %d", ms)
}

func baseName(path string) string {
	if idx := strings.LastIndex(path, `\`); idx >= 0 {
		return path[idx+1:]
	}
	return path
}

func truncStr(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max] + "..."
}
