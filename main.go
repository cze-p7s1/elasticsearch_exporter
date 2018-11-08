package main

import (
	"flag"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/cze-p7s1/elasticsearch_exporter/collector"
	"github.com/go-kit/kit/log/level"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/common/version"
)

func main() {
	var (
		Name                 = "elasticsearch_exporter"
		proxyEnvVariable     = "http_proxy"
		listenAddress        = flag.String("web.listen-address", ":9108", "Address to listen on for web interface and telemetry.")
		metricsPath          = flag.String("web.telemetry-path", "/metrics", "Path under which to expose metrics.")
		esURI                = flag.String("es.uri", "http://localhost:9200", "HTTP API address of an Elasticsearch node.")
		esTimeout            = flag.Duration("es.timeout", 5*time.Second, "Timeout for trying to get stats from Elasticsearch.")
		esAllNodes           = flag.Bool("es.all", false, "Export stats for all nodes in the cluster. If used, this flag will override the flag es.node.")
		esNode               = flag.String("es.node", "_local", "Node's name of which metrics should be exposed.")
		esExportIndices      = flag.Bool("es.indices", false, "Export stats for indices in the cluster.")
		esExportShards       = flag.Bool("es.shards", false, "Export stats for shards in the cluster (implies es.indices=true).")
		esExportSnapshots    = flag.Bool("es.snapshots", false, "Export stats for the cluster snapshots.")
		esCA                 = flag.String("es.ca", "", "Path to PEM file that contains trusted CAs for the Elasticsearch connection.")
		esClientPrivateKey   = flag.String("es.client-private-key", "", "Path to PEM file that contains the private key for client auth when connecting to Elasticsearch.")
		esClientCert         = flag.String("es.client-cert", "", "Path to PEM file that contains the corresponding cert for the private key to connect to Elasticsearch.")
		esInsecureSkipVerify = flag.Bool("es.ssl-skip-verify", false, "Skip SSL verification when connecting to Elasticsearch.")
		logLevel             = flag.String("log.level", "info", "Sets the loglevel. Valid levels are debug, info, warn, error")
		logFormat            = flag.String("log.format", "logfmt", "Sets the log format. Valid formats are json and logfmt")
		logOutput            = flag.String("log.output", "stdout", "Sets the log output. Valid outputs are stdout and stderr")
		netProxyHost         = flag.String("network.proxy", "", "Configure the http client with an http proxy")
		netProxyDisable      = flag.Bool("network.disableproxy", false, "Enable proxy configuration")
		httpBasicUser        = flag.String("http.user", "", "HTTP Basic Username")
		httpBasicPassword    = flag.String("http.password", "", "HTTP Basic Password")
		showVersion          = flag.Bool("version", false, "Show version and exit")
	)
	flag.Parse()
	// exporter:bil4Itxz
	if *showVersion {
		fmt.Print(version.Print(Name))
		os.Exit(0)
	}

	logger := getLogger(*logLevel, *logOutput, *logFormat)

	esURIEnv, ok := os.LookupEnv("ES_URI")
	if ok {
		*esURI = esURIEnv
	}
	esURL, err := url.Parse(*esURI)
	if err != nil {
		_ = level.Error(logger).Log(
			"msg", "failed to parse es.uri",
			"err", err,
		)
		os.Exit(1)
	}

	httpBasicUserEnv, ok := os.LookupEnv("ES_USER")
	if ok {
		level.Debug(logger).Log(
			"msg", "Read USER name from enviroment variable ES_USER",
		)
		*httpBasicUser = httpBasicUserEnv
	}

	httpBasicPasswordEnv, ok := os.LookupEnv("ES_PASSWORD")
	if ok {
		level.Debug(logger).Log(
			"msg", "Read PASSWORD name from enviroment variable ES_PASSWORD",
		)
		*httpBasicPassword = httpBasicPasswordEnv
	}

	// returns nil if not provided and falls back to simple TCP.
	tlsConfig := createTLSConfig(*esCA, *esClientCert, *esClientPrivateKey, *esInsecureSkipVerify)

	constructedTransport := &http.Transport{
		TLSClientConfig: tlsConfig,
	}

	if *netProxyDisable {
		level.Info(logger).Log(
			"msg", "Bypass proxy configuration",
		)
	} else {

		if len(*netProxyHost) == 0 {
			if strings.HasPrefix(*esURI, "https") {
				proxyEnvVariable = "https_proxy"
				level.Debug(logger).Log(
					"msg", fmt.Sprintf("https detected switch ENV_VAR to %s", proxyEnvVariable),
				)
			}

			proxyServerEnv, ok := os.LookupEnv(proxyEnvVariable)
			if ok {
				level.Debug(logger).Log(
					"msg", fmt.Sprintf("Set proxy to %s from ENV_VAR %s", proxyServerEnv, proxyEnvVariable),
				)
				*netProxyHost = proxyServerEnv
			}
		}

		level.Debug(logger).Log(
			"msg", fmt.Sprintf("Configure proxy to %s", *netProxyHost),
		)
		proxyURL, err := url.Parse(*netProxyHost)
		if err != nil {
			_ = level.Debug(logger).Log(
				"msg", "failed to parse network.proxy",
				"err", err,
			)
			os.Exit(1)
		}
		constructedTransport.Proxy = http.ProxyURL(proxyURL)
	}

	httpClient := &http.Client{
		Timeout:   *esTimeout,
		Transport: constructedTransport,
	}

	// version metric
	versionMetric := version.NewCollector(Name)
	prometheus.MustRegister(versionMetric)
	prometheus.MustRegister(collector.NewClusterHealth(logger, httpClient, esURL, httpBasicUser, httpBasicPassword))
	prometheus.MustRegister(collector.NewNodes(logger, httpClient, esURL, httpBasicUser, httpBasicPassword, *esAllNodes, *esNode))
	if *esExportIndices || *esExportShards {
		prometheus.MustRegister(collector.NewIndices(logger, httpClient, esURL, httpBasicUser, httpBasicPassword, *esExportShards))
	}
	if *esExportSnapshots {
		prometheus.MustRegister(collector.NewSnapshots(logger, httpClient, esURL, httpBasicUser, httpBasicPassword))
	}
	http.Handle(*metricsPath, prometheus.Handler())
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		_, err = w.Write([]byte(`<html>
			<head><title>Elasticsearch Exporter</title></head>
			<body>
			<h1>Elasticsearch Exporter</h1>
			<p><a href="` + *metricsPath + `">Metrics</a></p>
			</body>
			</html>`))
		if err != nil {
			_ = level.Error(logger).Log(
				"msg", "failed handling writer",
				"err", err,
			)
		}
	})

	_ = level.Info(logger).Log(
		"msg", "starting elasticsearch_exporter",
		"addr", *listenAddress,
	)

	if err := http.ListenAndServe(*listenAddress, nil); err != nil {
		_ = level.Error(logger).Log(
			"msg", "http server quit",
			"err", err,
		)
	}
}
