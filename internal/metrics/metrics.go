package metrics

import (
	"log"

	"github.com/prometheus/client_golang/prometheus"
)

var (
	// AvgProcessingTime - Average processing time for a DNS query
	AvgProcessingTime = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name:      "avg_processing_time",
			Namespace: "adguard",
			Help:      "This represent the average processing time for a DNS query in s",
		},
		[]string{"hostname"},
	)

	// DnsQueries - Number of DNS queries
	DnsQueries = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name:      "num_dns_queries",
			Namespace: "adguard",
			Help:      "Number of DNS queries",
		},
		[]string{"hostname"},
	)

	// DnsQueryLogCount - Counter of log entries seen in query log
	DnsQueryLogCount = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name:      "dns_query_log_count",
			Namespace: "adguard",
			Help:      "Counter of log entries seen in query log",
		},
		[]string{"hostname"},
	)

	// DnsQueryAnswerCount - Counter of query answers based on query log
	DnsQueryAnswerCount = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name:      "dns_query_answer_count",
			Namespace: "adguard",
			Help:      "Counter of query answers based on query log",
		},
		[]string{"hostname", "type"},
	)

	// BlockedFiltering - Number of DNS queries blocked
	BlockedFiltering = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name:      "num_blocked_filtering",
			Namespace: "adguard",
			Help:      "This represent the number of domains blocked",
		},
		[]string{"hostname"},
	)

	// ParentalFiltering - Number of DNS queries replaced by parental control
	ParentalFiltering = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name:      "num_replaced_parental",
			Namespace: "adguard",
			Help:      "This represent the number of domains blocked (parental)",
		},
		[]string{"hostname"},
	)

	// SafeBrowsingFiltering - Number of DNS queries replaced by safe browsing
	SafeBrowsingFiltering = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name:      "num_replaced_safebrowsing",
			Namespace: "adguard",
			Help:      "This represent the number of domains blocked (safe browsing)",
		},
		[]string{"hostname"},
	)

	// SafeSearchFiltering - Number of DNS queries replaced by safe search
	SafeSearchFiltering = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name:      "num_replaced_safesearch",
			Namespace: "adguard",
			Help:      "This represent the number of domains blocked (safe search)",
		},
		[]string{"hostname"},
	)

	// TopQueries - The number of top queries
	TopQueries = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name:      "top_queried_domains",
			Namespace: "adguard",
			Help:      "This represent the top queried domains",
		},
		[]string{"hostname", "domain"},
	)

	// TopBlocked - The number of top domains blocked
	TopBlocked = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name:      "top_blocked_domains",
			Namespace: "adguard",
			Help:      "This represent the top bloacked domains",
		},
		[]string{"hostname", "domain"},
	)

	// TopClients - The number of top clients
	TopClients = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name:      "top_clients",
			Namespace: "adguard",
			Help:      "This represent the top clients",
		},
		[]string{"hostname", "client"},
	)

	// Running - If Adguard is running
	Running = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name:      "running",
			Namespace: "adguard",
			Help:      "This represent if Adguard is running",
		},
		[]string{"hostname"},
	)

	// ProtectionEnable - If Adguard protection is enabled
	ProtectionEnabled = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name:      "protection_enabled",
			Namespace: "adguard",
			Help:      "This represent if Adguard Protection is enabled",
		},
		[]string{"hostname"},
	)
)

// Init initializes all Prometheus metrics made available by AdGuard  exporter.
func Init() {
	initMetric("avg_processing_time", AvgProcessingTime)
	initMetric("num_dns_queries", DnsQueries)
	initMetric("dns_query_log_count", DnsQueryLogCount)
	initMetric("dns_query_answer_count", DnsQueryAnswerCount)
	initMetric("num_blocked_filtering", BlockedFiltering)
	initMetric("num_replaced_parental", ParentalFiltering)
	initMetric("num_replaced_safebrowsing", SafeBrowsingFiltering)
	initMetric("num_replaced_safesearch", SafeSearchFiltering)
	initMetric("top_queried_domains", TopQueries)
	initMetric("top_blocked_domains", TopBlocked)
	initMetric("top_clients", TopClients)
	initMetric("running", Running)
	initMetric("protection_enabled", ProtectionEnabled)
}

func initMetric(name string, metric prometheus.Collector) {
	prometheus.MustRegister(metric)
	log.Printf("New Prometheus metric registered: %s", name)
}
