package main

import (
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"time"

	"github.com/go-redis/redis/v8"
	"gopkg.in/yaml.v2"

	"github.com/target/strelka/src/go/pkg/structs"
)

func main() {
	confPath := flag.String(
		"c",
		"/etc/strelka/manager.yaml",
		"path to manager config",
	)
	flag.Parse()

	confData, err := ioutil.ReadFile(*confPath)
	if err != nil {
		log.Fatalf("failed to read config file %s: %v", confPath, err)
	}
	var conf structs.Manager
	err = yaml.Unmarshal(confData, &conf)
	if err != nil {
		log.Fatalf("failed to load config data: %v", err)
	}

	cd := redis.NewClient(&redis.Options{
		Addr:        conf.Coordinator.Addr,
		DB:          conf.Coordinator.DB,
		PoolSize:    conf.Coordinator.Pool,
		ReadTimeout: conf.Coordinator.Read,
	})
	if err := cd.Ping(cd.Context()).Err(); err != nil {
		log.Fatalf("failed to connect to coordinator: %v", err)
	}

	// TODO: this should be a goroutine
	for {
		zrem, err := cd.ZRemRangeByScore(
		    cd.Context(),
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
		time.Sleep(250 * time.Millisecond)
	}
}
