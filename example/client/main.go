package main

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"

	"github.com/lucas-clemente/quic-go"
	"github.com/lucas-clemente/quic-go/http3"
	"github.com/lucas-clemente/quic-go/internal/testdata"
	"github.com/lucas-clemente/quic-go/internal/utils"
	"github.com/lucas-clemente/quic-go/logging"
	"github.com/lucas-clemente/quic-go/qlog"
	"github.com/montanaflynn/stats"
)

func main() {
	verbose := flag.Bool("v", false, "verbose")
	quiet := flag.Bool("q", false, "don't print the data")
	keyLogFile := flag.String("keylog", "", "key log file")
	insecure := flag.Bool("insecure", false, "skip certificate verification")
	enableQlog := flag.Bool("qlog", false, "output a qlog (in the same directory)")
	discovery := flag.String("n", "alt-svc", "the way to find availability and endpoint detail of HTTP/3")
	times := flag.Int("times", 1, "how many time to repeat request to the client")
	flag.Parse()
	urls := flag.Args()

	logger := utils.DefaultLogger

	if *verbose {
		logger.SetLogLevel(utils.LogLevelDebug)
	} else {
		logger.SetLogLevel(utils.LogLevelInfo)
	}
	logger.SetLogTimeFormat("")

	var keyLog io.Writer
	if len(*keyLogFile) > 0 {
		f, err := os.Create(*keyLogFile)
		if err != nil {
			log.Fatal(err)
		}
		defer f.Close()
		keyLog = f
	}

	pool, err := x509.SystemCertPool()
	if err != nil {
		log.Fatal(err)
	}
	testdata.AddRootCA(pool)

	var qconf quic.Config
	if *enableQlog {
		qconf.Tracer = qlog.NewTracer(func(_ logging.Perspective, connID []byte) io.WriteCloser {
			filename := fmt.Sprintf("client_%x.qlog", connID)
			f, err := os.Create(filename)
			if err != nil {
				log.Fatal(err)
			}
			log.Printf("Creating qlog file %s.\n", filename)
			return utils.NewBufferedWriteCloser(bufio.NewWriter(f), f)
		})
	}

	var connectionDiscovery http3.ConnectionDiscovery
	switch *discovery {
	case "alt-svc":
		connectionDiscovery = http3.ConnectionDiscoveryAltSvc
	case "eyeball":
		connectionDiscovery = http3.ConnectionDiscoveryHappyEyeballs
	default:
		panic("invalid option of connection discovery")
	}

	for _, addr := range urls {
		h3Count := 0
		records := make([]float64, 0, *times)
		for i := 0; i < *times; i++ {

			// new client
			roundTripper := &http3.RoundTripper{
				TLSClientConfig: &tls.Config{
					RootCAs:            pool,
					InsecureSkipVerify: *insecure,
					KeyLogWriter:       keyLog,
				},
				QuicConfig:          &qconf,
				ConnectionDiscovery: connectionDiscovery,
			}
			defer roundTripper.Close()
			client := &http.Client{
				Transport: roundTripper,
			}

			rsp, err := client.Get(addr)
			if err != nil {
				log.Fatal(err)
			}

			if rsp.ProtoMajor == 3 {
				h3Count++
			}

			if !*quiet {
				body := &bytes.Buffer{}
				_, err = io.Copy(body, rsp.Body)
				if err != nil {
					log.Fatal(err)
				}
				logger.Infof("Got response for %s: %#v", addr, rsp)
				logger.Infof("Response Body: %d bytes", body.Len())
				logger.Infof("Response Body:")
				logger.Infof("%s", body.Bytes())
			}
			if roundTripper.MetricsHandshakeDone.IsZero() || roundTripper.MetricsHandshakeStart.IsZero() {
				panic("metric is not available!")
			}
			duration := roundTripper.MetricsHandshakeDone.Sub(roundTripper.MetricsHandshakeStart).Milliseconds()
			records = append(records, float64(duration))
		}

		mean, _ := stats.Mean(records)
		stdev, _ := stats.StandardDeviation(records)
		min, _ := stats.Min(records)
		p25, _ := stats.Percentile(records, 25.0)
		median, _ := stats.Median(records)
		p75, _ := stats.Percentile(records, 75.0)
		max, _ := stats.Max(records)

		fmt.Printf("----------------------------------------------------------------\n")
		fmt.Printf("H3 access to %s : %d times out of %d time\n", addr, h3Count, *times)
		fmt.Printf("Average: %gms, Standard deviation: %gms\n", mean, stdev)
		fmt.Printf("Box plot... %gms, %gms, %gms, %gms, %gms\n", min, p25, median, p75, max)
		fmt.Printf("----------------------------------------------------------------\n")
	}
}
