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
                "/etc/strelka/fileshot.yaml",
                "path to fileshot conf",
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

        var conf structs.FileShot
        err = yaml.Unmarshal(confData, &conf)
        if err != nil {
                log.Fatalf("failed to load config data: %v", err)
        }

        serv := conf.Conn.Server
        auth := rpc.SetAuth(conf.Conn.Cert)
        ctx, cancel := context.WithTimeout(context.Background(), 5 * time.Second)
        defer cancel()
        conn, err := grpc.DialContext(ctx, serv, auth, grpc.WithBlock())
        if err != nil {
                log.Fatalf("failed to connect to %s: %v", serv, err)
        }
        defer conn.Close()

        var wgRequest sync.WaitGroup
        var wgResponse sync.WaitGroup

        frontend := strelka.NewFrontendClient(conn)
        sem := make(chan int, conf.Conn.Concurrency)
        defer close(sem)
        responses := make(chan *strelka.ScanResponse, 100)
        defer close(responses)

        wgResponse.Add(1)
        if conf.Response.Log != "" {
                go func(){
                        rpc.LogResponses(responses, conf.Response.Log)
                        wgResponse.Done()
                }()
                log.Printf("responses will be logged to %v", conf.Response.Log)
        } else if conf.Response.Report != 0 {
                go func(){
                        rpc.ReportResponses(responses, conf.Response.Report)
                        wgResponse.Done()
                }()
                log.Printf("responses will be reported every %v", conf.Response.Report)
        } else {
                go func(){
                        rpc.DiscardResponses(responses)
                        wgResponse.Done()
                }()
                log.Println("responses will be discarded")
        }

        client := "go-fileshot"
        if conf.Client != "" {
                client = conf.Client
        }

        hostname, err := os.Hostname()
        if err != nil {
                log.Fatalf("failed to retrieve hostname: %v", err)
        }

        request := &strelka.Request{
                Client:client,
                Source:hostname,
        }

        for _, p := range conf.Files.Patterns {
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

                        if (fi.Mode() & os.ModeType != 0) {
                                continue
                        }

                        req := structs.ScanFileRequest{
                            Request:request,
                            Attributes:&strelka.Attributes{
                                Filename:f,
                            },
                            Chunk:conf.Files.Chunk,
                            Delete:conf.Files.Delete,
                        }

                        sem <- 1
                        wgRequest.Add(1)
                        go func(){
                                rpc.ScanFile(
                                        frontend,
                                        conf.Conn.Timeout,
                                        req,
                                        responses,
                                )
                                wgRequest.Done()
                                <-sem
                        }()
                }
        }

        wgRequest.Wait()
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
