package rpc

import (
	"context"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"runtime"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/status"

	"github.com/target/strelka/src/go/api/strelka"
	"github.com/target/strelka/src/go/pkg/structs"
)

// Formats rpc errors into easily read messages
func errToMsg(err error) string {
	st, _ := status.FromError(err)
	return fmt.Sprintf(
		"rpc err:\n\t\t\t code: %v: \n\t\t\t message: %v",
		st.Code(),
		st.Message(),
	)
}

func min(a, b int) int {
	if a <= b {
		return a
	}
	return b
}

// Identifies operating system and returns the appropriate
// newline character(s) for the operating system
func osNewline() string {
	nl := ""
	switch os := runtime.GOOS; os {
	case "darwin":
		nl = "\n"
	case "linux":
		nl = "\n"
	case "windows":
		nl = "\r\n"
	default:
		nl = "\n"
	}

	return nl
}

// Establishes insecure or secure gRPC transport based
// on the presence of a server certificate
func SetAuth(cert string) grpc.DialOption {
	if cert != "" {
		creds, err := credentials.NewClientTLSFromFile(cert, "")
		if err != nil {
			log.Printf("failed to load server certificate file %s: %v", cert, err)
		}

		return grpc.WithTransportCredentials(creds)
	} else {
		return grpc.WithInsecure()
	}
}

// Reports number of responses received according to a delta
func ReportResponses(responses <-chan *strelka.ScanResponse, delta time.Duration) {
	t := time.Now()
	recv := 0

	for r := range responses {
		if r != nil {
			recv++
			if time.Now().Sub(t) >= delta {
				log.Printf("responses received: %d", recv)
				t = time.Now()
				recv = 0
			}
			continue
		}
		log.Printf("responses received: %d", recv)
		break
	}
}

// Logs events in responses to local disk
func LogResponses(responses <-chan *strelka.ScanResponse, path string) {
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		log.Fatalf("failed to create file %s: %v", path, err)
	}
	defer f.Close()

	nl := osNewline()
	for r := range responses {
		if r != nil {
			f.WriteString(fmt.Sprintf("%s%s", r.Event, nl))
			continue
		}
		break
	}
}

// Logs String for individual responses
func LogIndividualResponse(individualLog string, path string) {
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		log.Fatalf("failed to create file %s: %v", path, err)
	}
	defer f.Close()

	nl := osNewline()
	f.WriteString(fmt.Sprintf("%s%s", individualLog, nl))

}

// Logs events in responses to stdout
func PrintResponses(responses <-chan *strelka.ScanResponse) {
	nl := osNewline()
	for r := range responses {
		if r != nil {
			os.Stdout.WriteString(fmt.Sprintf("%s%s", r.Event, nl))
			continue
		}
		break
	}
}

// Discards responses
func DiscardResponses(responses <-chan *strelka.ScanResponse) {
	for r := range responses {
		if r != nil {
			continue
		}
		break
	}
}

func ScanFile(client strelka.FrontendClient, timeout time.Duration, req structs.ScanFileRequest, responses chan<- *strelka.ScanResponse) {

	deadline := time.Now().Add(timeout)
	ctx, cancel := context.WithDeadline(context.Background(), deadline)
	defer cancel()

	// Read in file
	file, err := os.Open(req.Attributes.Filename)
	if err != nil {
		log.Printf("failed to open file %s: %v", req.Attributes.Filename, err)
		return
	}

	// If specified, delete or move file to processed directory
	if req.Delete {
		defer os.Remove(req.Attributes.Filename)
	} else if req.Processed != "" {
		defer func() {
			_, name := filepath.Split(req.Attributes.Filename)
			m := filepath.Join(req.Processed, name)
			err := os.Rename(req.Attributes.Filename, m)
			if err != nil {
				log.Printf("failed to move file %s to directory %s: %v", name, req.Processed, err)
			}
		}()
	}
	defer file.Close()

	scanFile, err := client.ScanFile(ctx, grpc.WaitForReady(true))
	if err != nil {
		log.Println(errToMsg(err))
		return
	}

	// Send file to the frontend in chunks
	buffer := make([]byte, req.Chunk)
	for {
		n, err := file.Read(buffer)
		if err != nil {
			if err != io.EOF {
				log.Printf("failed to read file %s: %v", req.Attributes.Filename, err)
				return
			}

			break
		}

		// Adhere to send delay
		time.Sleep(req.Delay)

		scanFile.Send(
			&strelka.ScanFileRequest{
				Data:       buffer[:n],
				Request:    req.Request,
				Attributes: req.Attributes,
			},
		)
	}

	if err := scanFile.CloseSend(); err != nil {
		log.Printf("failed to close stream: %v", err)
		return
	}

	// Wait for the response from the frontend containing the event
	for {
		resp, err := scanFile.Recv()
		if err == io.EOF {
			break
		}
		if err != nil {
			log.Println(errToMsg(err))
			break
		}

		// Add the event to the responses channel
		responses <- resp
	}
}
