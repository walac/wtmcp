// google-calendar handler is a persistent plugin for Google Calendar.
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"

	"google.golang.org/api/calendar/v3"
	"google.golang.org/api/option"

	"github.com/LeGambiArt/wtmcp/pkg/handler"
)

var calendarSvc *calendar.Service

func main() {
	p := handler.New()

	p.OnInit(func(_ json.RawMessage) error {
		client := handler.NewProxyTransport(p).Client()
		svc, err := calendar.NewService(context.Background(), option.WithHTTPClient(client))
		if err != nil {
			return fmt.Errorf("calendar service: %w", err)
		}
		calendarSvc = svc
		return nil
	})

	p.Handle("calendar_get_events", toolGetEvents)
	p.Handle("calendar_get_event", toolGetEvent)
	p.Handle("calendar_create_event", toolCreateEvent)
	p.Handle("calendar_update_event", toolUpdateEvent)
	p.Handle("calendar_delete_event", toolDeleteEvent)
	p.Handle("calendar_get_calendars", toolGetCalendars)
	p.Handle("calendar_search_events", toolSearchEvents)
	p.Handle("calendar_get_free_busy", toolGetFreeBusy)

	if err := p.Run(); err != nil {
		fmt.Fprintf(os.Stderr, "handler: %v\n", err)
		os.Exit(1)
	}
}
