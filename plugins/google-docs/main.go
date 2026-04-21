// google-docs handler is a persistent plugin for Google Docs.
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"

	"google.golang.org/api/docs/v1"
	"google.golang.org/api/option"

	"github.com/LeGambiArt/wtmcp/pkg/handler"
)

var (
	docsSvc    *docs.Service
	sessionDir string
	outputDir  string
)

func main() {
	p := handler.New()

	p.OnInit(func(_ json.RawMessage) error {
		client := handler.NewProxyTransport(p).Client()
		svc, err := docs.NewService(context.Background(), option.WithHTTPClient(client))
		if err != nil {
			return fmt.Errorf("docs service: %w", err)
		}
		docsSvc = svc
		sessionDir = cfg["_session_dir"]
		outputDir = cfg["_output_dir"]
		return nil
	})

	p.Handle("gdocs_get_document", toolGetDocument)
	p.Handle("gdocs_get_document_text", toolGetDocumentText)
	p.Handle("gdocs_get_document_markdown", toolGetDocumentMarkdown)
	p.Handle("gdocs_summarize_document", toolSummarizeDocument)
	p.Handle("gdocs_extract_and_get_from_text", toolExtractAndGet)
	p.Handle("gdocs_write", toolWrite)
	p.Handle("gdocs_create_document", toolCreateDocument)

	if err := p.Run(); err != nil {
		fmt.Fprintf(os.Stderr, "handler: %v\n", err)
		os.Exit(1)
	}
}
