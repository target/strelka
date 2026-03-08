package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"time"

	"github.com/confluentinc/confluent-kafka-go/v2/kafka"
	"github.com/go-redis/redis/v8"
	"github.com/google/uuid"

	"github.com/target/strelka/src/go/api/strelka"
)

// ==============================
//  Kafka RAW message structure
// ==============================

type RawKafkaMessage struct {
	Id       string            `json:"id"`
	Filename string            `json:"filename"`
	DataB64  string            `json:"data_base64"`
	Client   string            `json:"client"`
	Source   string            `json:"source"`
	Time     int64             `json:"time"`
	Meta     map[string]string `json:"meta"`
}

// ==============================
//  Start Kafka Ingest
// ==============================

func (s *server) StartKafkaIngest(bootstrap, topic string) {
	consumer, err := kafka.NewConsumer(&kafka.ConfigMap{
		"bootstrap.servers":         bootstrap,
		"group.id":                  "strelka-kafka-ingest",
		"auto.offset.reset":         "earliest",
		"max.partition.fetch.bytes": 104857600,
		"fetch.message.max.bytes":   104857600,
	})
	if err != nil {
		log.Fatalf("Kafka consumer init error: %v", err)
	}

	if err := consumer.SubscribeTopics([]string{topic}, nil); err != nil {
		log.Fatalf("Kafka subscribe failed: %v", err)
	}

	log.Printf("🔥 Strelka Kafka Frontend started — consuming from topic: %s", topic)

	for {
		msg, err := consumer.ReadMessage(-1)
		if err != nil {
			log.Printf("Kafka read error: %v", err)
			continue
		}

		var raw RawKafkaMessage
		if err := json.Unmarshal(msg.Value, &raw); err != nil {
			log.Printf("Invalid Kafka message format: %v", err)
			continue
		}

		go s.processRawMessage(raw)
	}
}

// ==============================
//  Process each RAW message
// ==============================

func (s *server) processRawMessage(raw RawKafkaMessage) {
	ctx := context.Background()

	// Unique task ID per Kafka message, even if raw.Id repeats
	taskID := uuid.NewString()

	// Decode base64 file
	data, err := base64.StdEncoding.DecodeString(raw.DataB64)
	if err != nil {
		log.Printf("Bad base64 for raw id=%s task id=%s: %v", raw.Id, taskID, err)
		return
	}

	keyd := fmt.Sprintf("data:%s", taskID)
	keye := fmt.Sprintf("event:%s", taskID)

	// Deadline — like ScanFile
	deadline := time.Now().Add(2 * time.Minute)

	// Push file contents to Redis as ONE CHUNK
	p := s.coordinator.cli.Pipeline()
	p.RPush(ctx, keyd, data)
	p.ExpireAt(ctx, keyd, deadline)
	p.ExpireAt(ctx, keye, deadline)
	if _, err := p.Exec(ctx); err != nil {
		log.Printf("Redis write error for raw id=%s task id=%s: %v", raw.Id, taskID, err)
		return
	}

	log.Printf("📥 Stored file raw id=%s as task id=%s in Redis key %s", raw.Id, taskID, keyd)

	// Build request metadata
	reqObj := map[string]interface{}{
		"task_id": taskID,
		"id":      taskID, // important: Strelka workers usually use "id" to resolve data:<id> and event:<id>
		"raw_id":  raw.Id, // keep original external/message id for reference
		"attributes": map[string]interface{}{
			"filename": raw.Filename,
		},
		"client": raw.Client,
		"source": raw.Source,
		"time":   raw.Time,
	}

	if len(raw.Meta) > 0 {
		reqObj["meta"] = raw.Meta
	}

	// Add to Redis sorted task list
	reqJSON, err := json.Marshal(reqObj)
	if err != nil {
		log.Printf("Failed to marshal task raw id=%s task id=%s: %v", raw.Id, taskID, err)
		return
	}

	err = s.coordinator.cli.ZAdd(
		ctx,
		"tasks",
		&redis.Z{
			Score:  float64(deadline.Unix()),
			Member: reqJSON,
		},
	).Err()
	if err != nil {
		log.Printf("Failed to add task raw id=%s task id=%s to Redis: %v", raw.Id, taskID, err)
		return
	}

	log.Printf("📝 Added task raw id=%s task id=%s to Redis sorted set 'tasks'", raw.Id, taskID)

	// Now wait for scanning result
	go s.waitForResult(taskID, keye, reqObj)
}

// ==============================
//  Wait for result (same as ScanFile logic)
// ==============================

func (s *server) waitForResult(taskID, keye string, em map[string]interface{}) {
	ctx := context.Background()

	for {
		lpop, err := s.coordinator.LPop(ctx, keye)
		if err != nil {
			time.Sleep(250 * time.Millisecond)
			continue
		}

		if lpop == "" {
			continue
		}

		if lpop == "FIN" {
			log.Printf("✔️ FIN received for task id=%s", taskID)
			break
		}

		// Merge event into metadata
		if err := json.Unmarshal([]byte(lpop), &em); err != nil {
			log.Printf("Failed to unmarshal event for task id=%s: %v", taskID, err)
			continue
		}

		// prepare final JSON
		event, err := json.Marshal(em)
		if err != nil {
			log.Printf("Failed to marshal final event for task id=%s: %v", taskID, err)
			continue
		}

		resp := &strelka.ScanResponse{
			Id:    taskID,
			Event: string(event),
		}

		// Push to frontend responses channel (Kafka logger will pick it)
		s.responses <- resp

		log.Printf("📤 Delivered analysis for task id=%s", taskID)
	}
}