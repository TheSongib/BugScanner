package broker

import (
	"fmt"
	"sync"

	amqp "github.com/rabbitmq/amqp091-go"

	"github.com/brandon/bugscanner/internal/config"
)

// Queue names for each pipeline stage.
const (
	QueueDiscovery = "queue.discovery"
	QueuePortScan  = "queue.portscan"
	QueueHTTPProbe = "queue.httpprobe"
	QueueCrawl     = "queue.crawl"
	QueueVulnScan  = "queue.vulnscan"
)

var AllQueues = []string{
	QueueDiscovery,
	QueuePortScan,
	QueueHTTPProbe,
	QueueCrawl,
	QueueVulnScan,
}

type Broker struct {
	conn    *amqp.Connection
	channel *amqp.Channel
	url     string
	mu      sync.Mutex
}

func New(cfg config.RabbitMQConfig) (*Broker, error) {
	b := &Broker{url: cfg.URL}
	if err := b.connect(); err != nil {
		return nil, err
	}
	return b, nil
}

func (b *Broker) connect() error {
	conn, err := amqp.Dial(b.url)
	if err != nil {
		return fmt.Errorf("rabbitmq dial: %w", err)
	}

	ch, err := conn.Channel()
	if err != nil {
		conn.Close()
		return fmt.Errorf("rabbitmq channel: %w", err)
	}

	// Declare all pipeline queues
	for _, queue := range AllQueues {
		_, err := ch.QueueDeclare(
			queue,
			true,  // durable
			false, // auto-delete
			false, // exclusive
			false, // no-wait
			amqp.Table{
				"x-dead-letter-exchange":    "",
				"x-dead-letter-routing-key": queue + ".dlq",
			},
		)
		if err != nil {
			ch.Close()
			conn.Close()
			return fmt.Errorf("declare queue %s: %w", queue, err)
		}

		// Declare dead-letter queue for failed messages
		_, err = ch.QueueDeclare(
			queue+".dlq",
			true,  // durable
			false, // auto-delete
			false, // exclusive
			false, // no-wait
			nil,
		)
		if err != nil {
			ch.Close()
			conn.Close()
			return fmt.Errorf("declare dlq %s: %w", queue+".dlq", err)
		}
	}

	b.conn = conn
	b.channel = ch
	return nil
}

func (b *Broker) Channel() *amqp.Channel {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.channel
}

func (b *Broker) Reconnect() error {
	b.mu.Lock()
	defer b.mu.Unlock()

	if b.channel != nil {
		b.channel.Close()
	}
	if b.conn != nil {
		b.conn.Close()
	}
	return b.connect()
}

func (b *Broker) Close() {
	b.mu.Lock()
	defer b.mu.Unlock()

	if b.channel != nil {
		b.channel.Close()
	}
	if b.conn != nil {
		b.conn.Close()
	}
}
