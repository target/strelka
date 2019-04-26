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

// TODO: this should be an optional goroutine
// func pruneQueue(r *redis.Client) {
//         for {
//                 zrem := queue.ZRemRangeByScore(
//                         "queue",
//                         "-inf",
//                         fmt.Sprintf("(%v", time.Now().Unix()),
//                 )
//                 if zrem.Val() != 0 {
//                         log.Println(zrem.Val())
//                 }
//                 time.sleep(1 * time.Second)
//         }
// }

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
        var conf structs.RedisManager
        err = yaml.Unmarshal(confData, &conf)
        if err != nil {
                log.Fatalf("failed to load config data: %v", err)
        }

        queue := redis.NewClient(&redis.Options{
                Addr:       conf.Queue.Addr,
                DB:         conf.Queue.Db,
        })

        // TODO: this should be a goroutine
        for {
                zrem := queue.ZRemRangeByScore(
                        "queue",
                        "-inf",
                        fmt.Sprintf("(%v", time.Now().Unix()),
                )
                if zrem.Val() != 0 {
                        log.Println(zrem.Val())
                }
                time.Sleep(1 * time.Second)
        }
}
