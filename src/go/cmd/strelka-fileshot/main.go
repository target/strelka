package main

import (
	"bufio"
	"context"
	"crypto/md5"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"
	"runtime/pprof"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/target/strelka/src/go/api/strelka"
	"github.com/target/strelka/src/go/pkg/rpc"
	"github.com/target/strelka/src/go/pkg/structs"

	"github.com/gabriel-vasile/mimetype"

	"google.golang.org/grpc"
	"gopkg.in/yaml.v2"
)

func main() {
	// Declare flags
	confPath := flag.String("c", "/etc/strelka/fileshot.yaml", "Path to fileshot configuration file.")
	hashPath := flag.String("e", "", "Path to MD5 exclusions list.")
	verbose := flag.Bool("v", false, "Enables additional error logging.")
	cpuProf := flag.Bool("cpu", false, "Enables cpu profiling.")
	heapProf := flag.Bool("heap", false, "Enables heap profiling.")

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

	// Create a slice to hold the lines of the file
	hashes := make([]string, 0)

	// Check if hash exclusion path is set
	// Load exclusion hashes
	if *hashPath != "" {
		hashData, err := ioutil.ReadFile(*hashPath)
		if err != nil {
			log.Fatalf("failed to read hash exclusion file %s: %v", hashPath, err)
		}

		// Create a new Scanner to read the hash data
		hashScanner := bufio.NewScanner(strings.NewReader(string(hashData)))

		// Iterate through the lines of the file
		for hashScanner.Scan() {
			// Append the current line to the slice
			// Convert the string to an int64
			i := hashScanner.Text()
			hashes = append(hashes, i)
		}
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

	// Set Total Limiter for Max Files to be consumed by host
	totalCount := 0

	// Loop through each pattern in the list of file patterns
	for _, p := range conf.Files.Patterns {

		if *verbose {
			log.Printf("Collecting files from: %s.", p)
		}

		// If total files collecte dexceeds amount allowed per collection, finish.
		if conf.Files.LimitTotal > 0 && totalCount > conf.Files.LimitTotal {
			if *verbose {
				log.Printf("[LIMIT REACHED] Total file collection limit of %d reached.", conf.Files.LimitTotal)
			}
			continue
		}

		// Set Pattern Limiter for Max Files to be consumed by Pattern
		patternCount := 0

		// Expand the pattern to a list of matching file pathsƒ
		match, err := filepath.Glob(p)
		if err != nil {
			log.Printf("failed to glob pattern %s: %v", p, err)
			continue
		}

		// If recently modified is set, run this, otherwise place match into new var matches
		if conf.Files.Modified > 0 {
			match = getRecentlyModified(match, conf.Files.Modified, *verbose)
		}

		// Iterate over the list of files that match the provided pattern.
		// Order of operation for gate processing:
		//		1) If Min/Max file size specified, check file size gate and proceed if True.
		//		2) If Mimetype list specified, check identified mimetype and proceed if True.
		//	 	3) If MD5 hashing enabled, MD5 hash the file amd compare with exclusions list, proceed if False.
		for _, f := range match {

			if *verbose {
				log.Printf("Submitting file: %s.", f)
			}

			// If current path exceeds amount allowed per collection path, move onto next path.
			if conf.Files.LimitPattern > 0 && patternCount > conf.Files.LimitPattern {
				if *verbose {
					log.Printf("[LIMIT REACHED] Total pattern collection limit of %d reached.", conf.Files.LimitPattern)
				}
				continue
			}

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

			// GATE CHECK
			// Check file size
			// If file size not in range, skip to next file.
			if !(conf.Files.Minsize < 0) && conf.Files.Maxsize > 0 {
				if !checkFileSize(fi, int64(conf.Files.Minsize), int64(conf.Files.Maxsize), *verbose) {
					continue
				}
			}

			// Open the file
			// Need to open to perform hash and mimetype gate check.
			file, err := os.Open(f)
			if err != nil {
				log.Printf("failed to open file %s: %v", f, err)
				continue
			}
			defer file.Close()

			// GATE CHECK
			// Check file mimetypes
			// If mimetype not found, skip to next file.
			if len(conf.Files.Mimetypes) > 0 {
				if !checkFileMimetype(file, conf.Files.Mimetypes, *verbose) {
					continue
				}
			}

			// GATE CHECK
			// Check hash exclusions
			// If an exclusion is found, skip to next file.
			if len(hashes) > 0 {
				if checkFileHash(file, hashes, *verbose) {
					continue
				}
			}

			// Iterate Limiter Counts
			patternCount += 1
			totalCount += 1

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

// Checks if the size of a file is within a given range and returns
// true if it is, or false otherwise.
func checkFileSize(file fs.FileInfo, minSize int64, maxSize int64, verbose bool) bool {
	// Check if the file size is within the specified range
	if file.Size() >= minSize && file.Size() <= maxSize {
		return true
	}

	if verbose {
		log.Printf("[IGNORING] File size (%d) is not within configured Minsize (%d) and Maxsize (%d): %s.", file.Size(), minSize, maxSize, file.Name())
	}

	return false
}

// Checks the MIME type of a file against a list of MIME types and returns
// true if a match is found, or false otherwise.
func checkFileMimetype(file *os.File, mimetypes []string, verbose bool) bool {
	// Read the first 512 bytes of the file
	buffer := make([]byte, 512)
	_, err := file.Read(buffer)
	if err != nil {
		log.Printf("failed to read file %s: %v", file, err)
		return false
	}

	// Determine the MIME type of the file based on its content
	mimeType := mimetype.Detect(buffer)
	if mimeType.String() == "" {
		// If the MIME type could not be determined, log an error and continue to the next file.
		log.Printf("failed to determine MIME type for file %s", file)
		return false
	}

	// Iterate through the list of approved MIME types
	for _, v := range mimetypes {
		// Check if the current MIME type matches a known MIME type
		if strings.Contains(mimeType.String(), v) {
			return true
		}
	}

	if verbose {
		log.Printf("[IGNORING] File mimetype (%s) is not within configured list of mimetypes: %s.", mimeType, file.Name())
	}

	return false
}

// checkFileHash checks the MD5 hash of a file against a list of hashes and returns
// true if a match is found, or false otherwise.
func checkFileHash(file *os.File, hashlist []string, verbose bool) bool {
	// Create a new MD5 hash
	hash := md5.New()

	// Read the contents of the file into the hash
	if _, err := io.Copy(hash, file); err != nil {
		log.Println("File could not be hashed: %s", err)
		return false
	}

	// Iterate through the list of exclusion hashes
	// Return true if file hash matches an exclusion hash.
	for _, s := range hashlist {
		if s == fmt.Sprintf("%x", hash.Sum(nil)) {
			if verbose {
				log.Printf("[IGNORING] File hash (%s) was found in MD5 exclusion list: %s.", fmt.Sprintf("%x", hash.Sum(nil)), file.Name())
			}
			return true
		}
	}
	return false
}

// getRecentlyModified returns a slice of file paths that match the provided slice of file names and
// have been modified within the last modified hours.
func getRecentlyModified(match []string, modified int, verbose bool) []string {
	var matches []string     // slice to hold the matching file paths
	var paths []string       // slice to hold the file paths
	var modTimes []time.Time // slice to hold the modification times of the files

	// Loop through the provided slice of file names
	for _, file := range match {
		// Get the file info and handle any errors
		info, err := os.Stat(file)
		if err != nil {
			fmt.Println(err)
			continue
		}
		// Append the file path and modification time to the corresponding slices
		paths = append(paths, file)
		modTimes = append(modTimes, info.ModTime())
	}

	// Sort the slices by modification time
	sort.SliceStable(paths, func(i, j int) bool {
		return modTimes[i].After(modTimes[j])
	})

	// Get the current time
	now := time.Now()

	// Loop through the sorted slice of file paths
	for i, path := range paths {
		// Check if the file was modified within the last modified hours
		if now.Sub(modTimes[i]) < (time.Duration(modified) * time.Hour) {
			// If it was, append the file path to the matches slice
			matches = append(matches, path)
		} else {
			if verbose {
				log.Printf("[IGNORING] Last modified time: %s older than configured timeframe (%d hours): %s.", modTimes[i], modified, path)
			}
		}
	}

	// Return the slice of matching file paths
	return matches
}
