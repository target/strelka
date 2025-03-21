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
	"time"

	"google.golang.org/grpc"
	"gopkg.in/yaml.v2"

	"github.com/target/strelka/src/go/api/strelka"
	"github.com/target/strelka/src/go/pkg/rpc"
	"github.com/target/strelka/src/go/pkg/structs"
)

func main() {
	confPath := flag.String(
		"c",
		"/etc/strelka/filestream.yaml",
		"path to filestream config",
	)
	cpuProf := flag.Bool(
		"cpu",
		false,
		"enables cpu profiling",
	)
	heapProf := flag.Bool(
		"heap",
		false,
		"enables heap profiling",
	)
	flag.Parse()

	if *cpuProf {
		cpu, err := os.Create("./cpu.pprof")
		if err != nil {
			log.Fatalf("failed to create cpu.pprof file: %v", err)
		}
		pprof.StartCPUProfile(cpu)
		defer pprof.StopCPUProfile()
	}

	confData, err := ioutil.ReadFile(*confPath)
	if err != nil {
		log.Fatalf("failed to read config file %s: %v", confPath, err)
	}

	var conf structs.FileStream
	err = yaml.Unmarshal(confData, &conf)
	if err != nil {
		log.Fatalf("failed to load config data: %v", err)
	}

	serv := conf.Conn.Server

	// Set up gRPC authentication
	auth := rpc.SetAuth(conf.Conn.Cert)

	ctx, cancel := context.WithTimeout(context.Background(), conf.Conn.Timeout.Dial)
	defer cancel()
	conn, err := grpc.DialContext(ctx, serv, auth, grpc.WithBlock())
	if err != nil {
		log.Fatalf("failed to connect to %s: %v", serv, err)
	}
	defer conn.Close()

	var wgRequest sync.WaitGroup
	var wgResponse sync.WaitGroup

	// Connect to frontend
	frontend := strelka.NewFrontendClient(conn)

	// Create buffered channel to track concurrency
	sem := make(chan int, conf.Throughput.Concurrency)
	defer close(sem)

	// Create buffered channel to collect responses
	responses := make(chan *strelka.ScanResponse, 100)
	defer close(responses)

	// Set callback for completed requests, returning events
	wgResponse.Add(1)
	if conf.Response.Log != "" {
		go func() {
			rpc.LogResponses(responses, conf.Response.Log)
			wgResponse.Done()
		}()
		log.Printf("responses will be logged to %v", conf.Response.Log)
	} else if conf.Response.Report != 0 {
		go func() {
			rpc.ReportResponses(responses, conf.Response.Report)
			wgResponse.Done()
		}()
		log.Printf("responses will be reported every %v", conf.Response.Report)
	} else {
		go func() {
			rpc.DiscardResponses(responses)
			wgResponse.Done()
		}()
		log.Println("responses will be discarded")
	}

	client := conf.Conn.Client
	if conf.Client != "" {
		client = conf.Client
	}

	hostname, err := os.Hostname()
	if err != nil {
		log.Fatalf("failed to retrieve hostname: %v", err)
	}

	// Create request metadata
	request := &strelka.Request{
		Client:     client,
		Source:     hostname,
		Gatekeeper: conf.Files.Gatekeeper,
	}

	// Collect files from staging directory
	staging := conf.Staging
	if _, err := os.Stat(staging); os.IsNotExist(err) {
		os.Mkdir(staging, 0600)
	} else {

		// Find matching files in the stage directory
		match, err := filepath.Glob(filepath.Join(staging, "*"))
		if err != nil {
			log.Fatalf("failed to glob staging %s: %v", staging, err)
		}

		for _, f := range match {
			fi, err := os.Stat(f)
			if err != nil {
				log.Printf("failed to stat file %s: %v", f, err)
				continue
			}

			// Ignore non-file paths
			if fi.Mode()&os.ModeType != 0 {
				continue
			}

			// Create request
			req := structs.ScanFileRequest{
				Request: request,
				Attributes: &strelka.Attributes{
					Filename: f,
				},
				Chunk:     conf.Throughput.Chunk,
				Delay:     conf.Throughput.Delay,
				Delete:    conf.Files.Delete,
				Processed: conf.Files.Processed,
			}

			// Increment request concurrency channel
			// This will block if the channel is full
			sem <- 1
			// Add request to asyncronous wait group
			wgRequest.Add(1)
			go func() {
				rpc.ScanFile(
					frontend,
					conf.Conn.Timeout.File,
					req,
					responses,
				)
				wgRequest.Done()
				// Decrement request concurrency channel
				<-sem
			}()
		}
	}

	// Collect files from configuration-specified directories
	for {
		t := time.Now()
		for _, p := range conf.Files.Patterns {

			// Find matching files
			match, err := filepath.Glob(p)
			if err != nil {
				log.Printf("failed to glob pattern %s: %v", p, err)
				continue
			}

			for _, f := range match {
				fi, err := os.Stat(f)
				if err != nil {
					log.Printf("failed to stat file %s: %v", f, err)
					continue
				}

				// Ignore non-file paths
				if fi.Mode()&os.ModeType != 0 {
					continue
				}

				// Temporarily ignore newly written files
				if t.Sub(fi.ModTime()) < conf.Delta {
					continue
				}

				_, name := filepath.Split(f)
				s := filepath.Join(staging, name)
				err = os.Rename(f, s)
				if err != nil {
					log.Fatalf("failed to stage file %s: %v", s, err)
				}

				// Create request
				req := structs.ScanFileRequest{
					Request: request,
					Attributes: &strelka.Attributes{
						Filename: s,
					},
					Chunk:     conf.Throughput.Chunk,
					Delay:     conf.Throughput.Delay,
					Delete:    conf.Files.Delete,
					Processed: conf.Files.Processed,
				}

				// Increment request concurrency channel
				// This will block if the channel is full
				sem <- 1

				// Add request to asyncronous wait group
				wgRequest.Add(1)
				go func() {
					rpc.ScanFile(
						frontend,
						conf.Conn.Timeout.File,
						req,
						responses,
					)
					wgRequest.Done()
					// Decrement request concurrency channel
					<-sem
				}()
			}
		}

		time.Sleep(1 * time.Second)
	}

	// TODO: the app never actually gets to this point, we need some kind of signal handling
	wgRequest.Wait()

	// Adding nil to the end of the responses channel
	// When a nil is reached, the Responses output functions exit
	responses <- nil

	wgResponse.Wait()

	if *heapProf {
		heap, err := os.Create("./heap.pprof")
		if err != nil {
			log.Fatalf("failed to create heap.pprof file: %v", err)
		}
		pprof.WriteHeapProfile(heap)
	}
}
