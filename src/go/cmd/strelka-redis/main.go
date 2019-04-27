package main

import (
        "flag"
        "fmt"
        "io/ioutil"
        "log"
        "time"

        "github.com/go-redis/redis"
        "gopkg.in/yaml.v2"

        "github.com/target/strelka/src/go/pkg/structs"
)

func main() {
        confPath := flag.String(
                "c",
                "/etc/strelka/redis.yaml",
                "path to redis config")
        flag.Parse()

        confData, err := ioutil.ReadFile(*confPath)
        if err != nil {
                log.Fatalf("failed to read config file %s: %v", confPath, err)
        }
        var conf structs.Redis
        err = yaml.Unmarshal(confData, &conf)
        if err != nil {
                log.Fatalf("failed to load config data: %v", err)
        }

        coordinator := redis.NewClient(&redis.Options{
                Addr:       conf.Coordinator.Addr,
                DB:         conf.Coordinator.Db,
        })
        err = coordinator.Ping().Err()
        if err != nil {
                log.Fatalf("failed to connect to coordinator: %v", err)
        }

        // TODO: this should be a goroutine
        for {
                zrem, err := coordinator.ZRemRangeByScore(
                        "tasks",
                        "-inf",
                        fmt.Sprintf("(%v", time.Now().Unix()),
                ).Result()
                if err != nil {
                        log.Printf("zrem err: %v", err)
                        continue
                }
                if zrem != 0 {
                        log.Printf("removed %v task(s)", zrem)
                }
                time.Sleep(1 * time.Second)
        }
}
