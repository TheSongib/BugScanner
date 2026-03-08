package broker

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"

	amqp "github.com/rabbitmq/amqp091-go"
)

// Handler processes a job from the queue.
type Handler func(ctx context.Context, job Job) error

// Consume starts consuming messages from the specified queue.
// It blocks until the context is cancelled.
func (b *Broker) Consume(ctx context.Context, queueName string, prefetch int, handler Handler) error {
	ch := b.Channel()

	if err := ch.Qos(prefetch, 0, false); err != nil {
		return fmt.Errorf("set qos: %w", err)
	}

	msgs, err := ch.Consume(
		queueName,
		"",    // consumer tag (auto-generated)
		false, // auto-ack (manual ack for reliability)
		false, // exclusive
		false, // no-local
		false, // no-wait
		nil,
	)
	if err != nil {
		return fmt.Errorf("consume queue %s: %w", queueName, err)
	}

	slog.Info("started consuming", "queue", queueName, "prefetch", prefetch)

	for {
		select {
		case <-ctx.Done():
			slog.Info("consumer shutting down", "queue", queueName)
			return ctx.Err()

		case msg, ok := <-msgs:
			if !ok {
				return fmt.Errorf("channel closed for queue %s", queueName)
			}

			if err := b.processMessage(ctx, msg, handler); err != nil {
				slog.Error("failed to process message",
					"queue", queueName,
					"error", err,
					"message_id", msg.MessageId,
				)
				// Nack and don't requeue — let it go to DLQ
				msg.Nack(false, false)
			} else {
				msg.Ack(false)
			}
		}
	}
}

func (b *Broker) processMessage(ctx context.Context, msg amqp.Delivery, handler Handler) error {
	var job Job
	if err := json.Unmarshal(msg.Body, &job); err != nil {
		return fmt.Errorf("unmarshal job: %w", err)
	}

	slog.Info("processing job",
		"job_id", job.ID,
		"scan_id", job.ScanID,
		"stage", job.Stage,
	)

	return handler(ctx, job)
}
