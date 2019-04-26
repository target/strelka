package main

import (
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

        "github.com/target/strelka/src/go/api/health"
        "github.com/target/strelka/src/go/api/strelka"
        "github.com/target/strelka/src/go/pkg/rpc"
        "github.com/target/strelka/src/go/pkg/structs"
)

func main() {
        confPath := flag.String(
                "c",
                "/etc/strelka/filestream.yaml",
                "path to filestream config")
        profile := flag.Bool(
                "p",
                false,
                "enables pprof profiling")
        flag.Parse()

        if *profile {
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
        auth := rpc.SetAuth(conf.Conn.Cert)
        conn, err := grpc.Dial(serv, auth)
        if err != nil {
                log.Fatalf("failed to connect to %s: %v", serv, err)
        }
        defer conn.Close()

        frontend := strelka.NewFrontendClient(conn)
        health := health.NewHealthClient(conn)
        err = rpc.HealthCheck(health)
        if err != nil {
                log.Fatalf("failed to connect to %s: %v", serv, err)
        }

        var wg sync.WaitGroup
        var wg2 sync.WaitGroup
        sem := make(chan int, conf.Conn.Routines)
        defer close(sem)
        responses := make(chan *strelka.ScanResponse, 100)
        defer close(responses)

        wg2.Add(1)
        if conf.Response.Log != "" {
                go func(){
                        rpc.LogResponses(responses, conf.Response.Log)
                        wg2.Done()
                }()
                log.Printf("responses will be logged to %v", conf.Response.Log)
        } else if conf.Response.Report != 0 {
                go func(){
                        rpc.ReportResponses(responses, conf.Response.Report)
                        wg2.Done()
                }()
                log.Printf("responses will be reported every %v", conf.Response.Report)
        } else {
                go func(){
                        rpc.DiscardResponses(responses)
                        wg2.Done()
                }()
                log.Println("responses will be discarded")
        }

        client := "go-filestream"
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

        staging := conf.Staging
        if _, err := os.Stat(staging); os.IsNotExist(err) {
                os.Mkdir(staging, 0755)
        } else {
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
                        wg.Add(1)
                        go func(){
                                rpc.ScanFile(
                                        frontend,
                                        conf.Conn.Timeout,
                                        req,
                                        responses,
                                )
                                wg.Done()
                                <-sem
                        }()
                }
        }

        for {
                t := time.Now()
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

                                if t.Sub(fi.ModTime()) < conf.Delta {
                                        continue
                                }

                                _, name := filepath.Split(f)
                                s := filepath.Join(staging, name)
                                err = os.Rename(f, s)
                                if err != nil {
                                        log.Fatalf("failed to stage file %s: %v", s, err)
                                }

                                req := structs.ScanFileRequest{
                                    Request:request,
                                    Attributes:&strelka.Attributes{
                                        Filename:s,
                                    },
                                    Chunk:conf.Files.Chunk,
                                    Delete:conf.Files.Delete,
                                }

                                sem <- 1
                                wg.Add(1)
                                go func(){
                                        rpc.ScanFile(
                                                frontend,
                                                conf.Conn.Timeout,
                                                req,
                                                responses,
                                        )
                                        wg.Done()
                                        <-sem
                                }()
                        }
                }

                time.Sleep(1 * time.Second)
        }

        // TODO: the app never actually gets to this point, we need some kind of signal handling
        wg.Wait()
        responses <- nil
        wg2.Wait()

        if *profile {
                mem, err := os.Create("./mem.pprof")
                if err != nil {
                        log.Fatalf("failed to create mem.pprof file: %v", err)
                }
                pprof.WriteHeapProfile(mem)
        }
}
