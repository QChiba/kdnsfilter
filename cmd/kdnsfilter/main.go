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
	"slices"
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
	fw := flag.String("firewall", "", "ensure|ensure-routing|remove|remove-all the firewall rules and exit (for netfilter.d hooks, init and uninstall)")
	fwFamily := flag.String("family", "", "with -firewall ensure: iptables or ip6tables only")
	tproxyPort := flag.Int("tproxy-port", -1, "set the TPROXY port of routing list -list (0 turns it off), enable routing, save the config and exit")
	tproxyList := flag.String("list", "bypass", "with -tproxy-port: the routing list, created if missing")
	showVersion := flag.Bool("version", false, "print version")
	flag.Parse()
	log.SetFlags(log.LstdFlags)

	switch {
	case *showVersion:
		fmt.Println(version)
	case *importAGH != "":
		exitOn(importAdGuard(*importAGH, *cfgPath, *force))
	case *tproxyPort >= 0:
		exitOn(setTProxyPort(*cfgPath, *tproxyList, *tproxyPort))
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
	// Binding the queue needs nfnetlink_queue, which KeeneticOS loads only
	// on demand.
	if err := firewall.LoadModules(firewall.QueueModules...); err != nil {
		log.Printf("modules: %v", err)
	}
	queueErr := make(chan error, 1)
	bound := make(chan struct{}, 1)
	go func() { queueErr <- a.RunQueue(ctx, cfg.NFQueue.Queue, bound) }()
	// Install the rules only once the queue is bound (or it failed fast);
	// --queue-bypass covers the gap anyway.
	select {
	case <-bound:
	case err := <-queueErr:
		if err != nil {
			log.Printf("queue: %v", err)
		}
	case <-time.After(3 * time.Second):
		log.Printf("queue not bound after 3s, installing the rules anyway")
	}
	if cfg.NFQueue.ManageFirewall {
		// The routing rules stay when kdnsfilter stops: the sets keep their
		// entries, so routing goes on across restarts.
		if err := errors.Join(firewall.Ensure(rules, ""), firewall.ApplyRouting(config.Routing{}, cfg.Routing, "")); err != nil {
			log.Printf("firewall: %v", err)
		}
		defer firewall.Remove(rules)
	}
	go a.RunUpdater(ctx)
	go a.RunPersistence(ctx)
	defer a.Close() // flush the query log and save statistics

	srv := &http.Server{
		Addr:    cfg.HTTP.Address,
		Handler: web.New(a, version).Handler(),
		// A LAN device (or a compromised IoT gadget) must not be able to
		// pin connections or trickle a request body forever. WriteTimeout
		// stays off: some handlers (list refresh) run for minutes.
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		IdleTimeout:       2 * time.Minute,
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
		return errors.Join(firewall.LoadModules(firewall.QueueModules...), firewall.Ensure(rules, family), ensureRouting(cfg, family))
	case "ensure-routing":
		// For the ndm hook while kdnsfilter is down: its sets still route.
		if !cfg.NFQueue.ManageFirewall {
			return nil
		}
		return ensureRouting(cfg, family)
	case "remove":
		// What kdnsfilter undoes when it stops (init script, after a kill):
		// the routing rules stay, the sets keep routing. Like ensure, this
		// leaves the firewall alone when the user manages it themselves.
		if !cfg.NFQueue.ManageFirewall {
			return nil
		}
		firewall.Remove(rules)
		return nil
	case "remove-all":
		// Uninstall: also the routing rules, TPROXY chains and ip rules.
		firewall.Remove(rules)
		return firewall.ApplyRouting(cfg.Routing, config.Routing{}, "")
	}
	return fmt.Errorf("-firewall must be ensure, ensure-routing, remove or remove-all, got %q", op)
}

func ensureRouting(cfg *config.Config, family string) error {
	if len(firewall.RoutingRules(cfg.Routing)) == 0 {
		return nil
	}
	// A rule can't name a set that doesn't exist yet (e.g. at boot).
	return errors.Join(ensureSets(cfg.Routing), firewall.ApplyRouting(config.Routing{}, cfg.Routing, family))
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

// setTProxyPort is for the installer: it points a routing list at a
// proxy's TPROXY port without hand-editing the YAML.
func setTProxyPort(path, list string, port int) error {
	if port > 65535 {
		return fmt.Errorf("-tproxy-port %d: want 0-65535", port)
	}
	cfg, err := loadOrCreate(path)
	if err != nil {
		return err
	}
	rt := &cfg.Routing
	i := slices.IndexFunc(rt.Lists, func(l config.RouteList) bool { return l.Name == list })
	if i < 0 {
		rt.Lists = append(rt.Lists, config.RouteList{Name: list, Domains: []string{}})
		i = len(rt.Lists) - 1
	}
	l := &rt.Lists[i]
	if l.Chain != "" || l.OutputChain != "" {
		return fmt.Errorf("routing list %q is routed by its own chains (chain/output_chain); remove them from %s first", list, path)
	}
	l.TProxyPort = uint16(port)
	if port > 0 {
		rt.Enabled = true
	}
	if err := cfg.Validate(); err != nil {
		return err
	}
	if err := cfg.Save(path); err != nil {
		return err
	}
	fmt.Printf("routing list %s: TPROXY port %d\n", list, port)
	return nil
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
