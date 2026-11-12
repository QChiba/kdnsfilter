// kdnsfilter filters ads and trackers for a Keenetic router without
// replacing its DNS: replies leaving the router are inspected via NFQUEUE and
// blocked names are rewritten.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log"
	"net/http"
	"net/netip"
	"os"
	"os/signal"
	"runtime/debug"
	"syscall"
	"time"

	_ "time/tzdata" // routers often lack zoneinfo

	"github.com/QChiba/kdnsfilter/internal/app"
	"github.com/QChiba/kdnsfilter/internal/config"
	"github.com/QChiba/kdnsfilter/internal/firewall"
	"github.com/QChiba/kdnsfilter/internal/ipset"
	"github.com/QChiba/kdnsfilter/internal/routing"
	"github.com/QChiba/kdnsfilter/internal/web"
)

var version = "dev"

// entwareCABundle is where Entware's ca-certificates package puts the CA
// bundle; Go doesn't look there by itself.
const entwareCABundle = "/opt/etc/ssl/certs/ca-certificates.crt"

func main() {
	if _, err := os.Stat(entwareCABundle); err == nil && os.Getenv("SSL_CERT_FILE") == "" {
		os.Setenv("SSL_CERT_FILE", entwareCABundle)
	}
	// Every GC scans the whole rule index (~35 MB with the AdGuard DNS filter),
	// which costs ~100 ms on a Cortex-A53, so a tight heap target is expensive.
	// 50% keeps RSS around 55-60 MB while making GCs rare.
	if os.Getenv("GOGC") == "" {
		debug.SetGCPercent(50)
	}
	cfgPath := flag.String("c", "/opt/etc/kdnsfilter/kdnsfilter.yaml", "config file")
	importAGH := flag.String("import-adguard", "", "create the config from this AdGuardHome.yaml and exit")
	force := flag.Bool("force", false, "with -import-adguard: overwrite an existing config")
	fw := flag.String("firewall", "", "ensure|ensure-routing|remove the firewall rules and exit (for netfilter.d hooks)")
	fwFamily := flag.String("family", "", "with -firewall ensure: iptables or ip6tables only")
	showVersion := flag.Bool("version", false, "print version")
	flag.Parse()
	log.SetFlags(log.LstdFlags)

	switch {
	case *showVersion:
		fmt.Println(version)
	case *importAGH != "":
		exitOn(importAdGuard(*importAGH, *cfgPath, *force))
	case *fw != "":
		exitOn(firewallCmd(*cfgPath, *fw, *fwFamily))
	default:
		exitOn(run(*cfgPath))
	}
}

func exitOn(err error) {
	if err != nil {
		fmt.Fprintln(os.Stderr, "kdnsfilter:", err)
		os.Exit(1)
	}
}

func loadOrCreate(path string) (*config.Config, error) {
	cfg, err := config.Load(path)
	if errors.Is(err, os.ErrNotExist) {
		cfg = config.Default()
		log.Printf("no config at %s, writing defaults", path)
		return cfg, cfg.Save(path)
	}
	return cfg, err
}

func run(path string) error {
	cfg, err := loadOrCreate(path)
	if err != nil {
		return err
	}
	a, err := app.New(path, cfg)
	if err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	rules, err := fwRules(cfg)
	if err != nil {
		return err
	}
	queueErr := make(chan error, 1)
	go func() { queueErr <- a.RunQueue(ctx, cfg.NFQueue.Queue) }()
	// Install rules only once the queue is bound; --queue-bypass covers the gap anyway.
	time.Sleep(200 * time.Millisecond)
	if cfg.NFQueue.ManageFirewall {
		// The routing rules stay when kdnsfilter stops: the sets keep their
		// entries, so routing goes on across restarts.
		if err := firewall.Ensure(append(rules, firewall.RoutingRules(cfg.Routing)...), ""); err != nil {
			log.Printf("firewall: %v", err)
		}
		defer firewall.Remove(rules)
	}
	go a.RunUpdater(ctx)
	go a.RunPersistence(ctx)
	defer a.Close() // flush the query log and save statistics

	srv := &http.Server{
		Addr:              cfg.HTTP.Address,
		Handler:           web.New(a, version).Handler(),
		ReadHeaderTimeout: 10 * time.Second,
	}
	go func() {
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Printf("http: %v", err)
			stop()
		}
	}()
	log.Printf("kdnsfilter %s: queue %d, UI on http://%s, %d rules", version, cfg.NFQueue.Queue, cfg.HTTP.Address, a.Filter().RulesCount())

	select {
	case <-ctx.Done():
	case err = <-queueErr:
		if err != nil {
			log.Printf("queue: %v", err)
		}
		stop()
	}
	shutdown, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	srv.Shutdown(shutdown)
	return err
}

func fwRules(cfg *config.Config) ([]firewall.Rule, error) {
	var dests []netip.Prefix
	for _, d := range cfg.NFQueue.Destinations {
		p, err := config.ParsePrefix(d)
		if err != nil {
			return nil, err
		}
		dests = append(dests, p)
	}
	return firewall.Rules(cfg.NFQueue.Queue, dests), nil
}

func firewallCmd(path, op, family string) error {
	cfg, err := config.Load(path)
	if err != nil {
		return err
	}
	rules, err := fwRules(cfg)
	if err != nil {
		return err
	}
	switch op {
	case "ensure":
		// The ndm hook calls this on every firewall rebuild; with
		// manage_firewall off the app must leave the firewall alone.
		if !cfg.NFQueue.ManageFirewall {
			return nil
		}
		return errors.Join(firewall.Ensure(rules, family), ensureRouting(cfg, family))
	case "ensure-routing":
		// For the ndm hook while kdnsfilter is down: its sets still route.
		if !cfg.NFQueue.ManageFirewall {
			return nil
		}
		return ensureRouting(cfg, family)
	case "remove":
		firewall.Remove(append(rules, firewall.RoutingRules(cfg.Routing)...))
		return nil
	}
	return fmt.Errorf("-firewall must be ensure, ensure-routing or remove, got %q", op)
}

func ensureRouting(cfg *config.Config, family string) error {
	rr := firewall.RoutingRules(cfg.Routing)
	if len(rr) == 0 {
		return nil
	}
	// A rule can't name a set that doesn't exist yet (e.g. at boot).
	return errors.Join(ensureSets(cfg.Routing), firewall.Ensure(rr, family))
}

// ensureSets creates the routing lists' ipsets (existing ones are kept).
func ensureSets(rt config.Routing) error {
	c, err := ipset.Dial()
	if err != nil {
		return err
	}
	defer c.Close()
	var errs []error
	for _, l := range rt.Lists {
		v4, v6 := l.SetNames()
		errs = append(errs,
			c.Create(v4, false, time.Duration(rt.MinTimeout), routing.MaxElem),
			c.Create(v6, true, time.Duration(rt.MinTimeout), routing.MaxElem))
	}
	return errors.Join(errs...)
}

func importAdGuard(src, dst string, force bool) error {
	if _, err := os.Stat(dst); err == nil && !force {
		return fmt.Errorf("%s exists; use -force to overwrite", dst)
	}
	cfg, err := config.ImportAdGuardHome(src)
	if err != nil {
		return err
	}
	if err := cfg.Save(dst); err != nil {
		return err
	}
	fmt.Printf("imported %d filter lists, %d user rules, %d clients into %s\n",
		len(cfg.Filters), len(cfg.UserRules), len(cfg.Clients), dst)
	return nil
}
