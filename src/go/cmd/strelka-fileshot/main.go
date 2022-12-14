package main

import (
	"context"
	"flag"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"
	"runtime/pprof"
	"sync"

	"github.com/target/strelka/src/go/api/strelka"
	"github.com/target/strelka/src/go/pkg/rpc"
	"github.com/target/strelka/src/go/pkg/structs"

	"google.golang.org/grpc"
	"gopkg.in/yaml.v2"
)

func main() {
	// Declare flags
	confPath := flag.String("c", "/etc/strelka/fileshot.yaml", "path to fileshot conf")
	cpuProf := flag.Bool("cpu", false, "enables cpu profiling")
	heapProf := flag.Bool("heap", false, "enables heap profiling")

	// Parse flags
	flag.Parse()

	// Check if CPU profiling is enabled
	if *cpuProf {
		// Create file for CPU profiling data
		cpu, err := os.Create("./cpu.pprof")
		if err != nil {
			log.Fatalf("failed to create cpu.pprof file: %v", err)
		}

		// Start CPU profiling
		pprof.StartCPUProfile(cpu)
		defer pprof.StopCPUProfile()
	}

	// Read configuration file
	confData, err := ioutil.ReadFile(*confPath)
	if err != nil {
		log.Fatalf("failed to read config file %s: %v", confPath, err)
	}

	// Unmarshal configuration data into struct
	var conf structs.FileShot
	err = yaml.Unmarshal(confData, &conf)
	if err != nil {
		log.Fatalf("failed to load config data: %v", err)
	}

	// Dial server using configuration data
	serv := conf.Conn.Server
	auth := rpc.SetAuth(conf.Conn.Cert)
	ctx, cancel := context.WithTimeout(context.Background(), conf.Conn.Timeout.Dial)
	defer cancel()
	conn, err := grpc.DialContext(ctx, serv, auth, grpc.WithBlock())
	if err != nil {
		log.Fatalf("failed to connect to %s: %v", serv, err)
	}
	defer conn.Close()

	// Create WaitGroup for managing goroutines
	var wgRequest sync.WaitGroup
	var wgResponse sync.WaitGroup

	// Create client for communicating with server
	frontend := strelka.NewFrontendClient(conn)

	// Create channel for limiting concurrency
	sem := make(chan int, conf.Throughput.Concurrency)
	defer close(sem)

	// Create channel for receiving responses from server
	responses := make(chan *strelka.ScanResponse, 100)
	defer close(responses)

	// Increment WaitGroup counter
	wgResponse.Add(1)

	// Create goroutine for handling responses
	go func() {
		if conf.Response.Log != "" {
			rpc.LogResponses(responses, conf.Response.Log)
		} else if conf.Response.Report != 0 {
			rpc.ReportResponses(responses, conf.Response.Report)
		} else {
			rpc.DiscardResponses(responses)
		}
		wgResponse.Done()
	}()

	// Print log message based on response handling configuration
	if conf.Response.Log != "" {
		log.Printf("responses will be logged to %v", conf.Response.Log)
	} else if conf.Response.Report != 0 {
		log.Printf("responses will be reported every %v", conf.Response.Report)
	} else {
		log.Println("responses will be discarded")
	}

	// Use default client name if not specified in configuration
	client := "go-fileshot"
	if conf.Client != "" {
		client = conf.Client
	}

	// Get hostname
	hostname, err := os.Hostname()
	if err != nil {
		log.Fatalf("failed to retrieve hostname: %v", err)
	}

	// Create request object
	request := &strelka.Request{
		Client:     client,
		Source:     hostname,
		Gatekeeper: conf.Files.Gatekeeper,
	}

    // Loop through each pattern in the list of file patterns
    for _, p := range conf.Files.Patterns {
        // Expand the pattern to a list of matching file paths
        match, err := filepath.Glob(p)
        if err != nil {
            log.Printf("failed to glob pattern %s: %v", p, err)
            continue
        }

        // Iterate over the list of files that match the provided pattern.
        for _, f := range match {
            // Get the file stats for the current file.
            fi, err := os.Stat(f)
            if err != nil {
                // Log an error and continue to the next file if an error occurred.
                log.Printf("failed to stat file %s: %v", f, err)
                continue
            }

            // Check if the file is a regular file (not a directory or symlink, etc.)
            if fi.Mode()&os.ModeType != 0 {
                // Log an error and continue to the next file if the file is not a regular file.
                log.Printf("file %s is not a regular file", f)
                continue
            }

            // Create the ScanFileRequest struct with the provided attributes.
            req := structs.ScanFileRequest{
                Request: request,
                Attributes: &strelka.Attributes{
                    Filename: f,
                },
                Chunk:  conf.Throughput.Chunk,
                Delay:  conf.Throughput.Delay,
                Delete: conf.Files.Delete,
            }

            // Send the ScanFileRequest to the RPC server using a goroutine.
            sem <- 1
            wgRequest.Add(1)
            go func() {
                rpc.ScanFile(
                    frontend,
                    conf.Conn.Timeout.File,
                    req,
                    responses,
                )

                // Notify the wgRequest wait group that the goroutine has finished.
                wgRequest.Done()

                // Release the semaphore to indicate that the goroutine has finished.
                <-sem
            }()
        }
    }

    wgRequest.Wait()
    responses <- nil
    wgResponse.Wait()

    // Check if the heapProf flag is set and write a heap profile if it is.
    if *heapProf {
        // Create the heap.pprof file.
        heap, err := os.Create("./heap.pprof")
        if err != nil {
            log.Fatalf("failed to create heap.pprof file: %v", err)
        }

        // Write the heap profile to the file.
        pprof.WriteHeapProfile(heap)

        // Close the file to release associated resources.
        heap.Close()
    }
}
