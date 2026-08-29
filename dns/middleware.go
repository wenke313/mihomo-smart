package dns

import (
	"net"
	"net/netip"
	"path/filepath"
	"strings"
	"time"

	"github.com/metacubex/mihomo/common/lru"
	"github.com/metacubex/mihomo/component/fakeip"
	"github.com/metacubex/mihomo/component/process"
	"github.com/metacubex/mihomo/component/resolver"
	C "github.com/metacubex/mihomo/constant"
	icontext "github.com/metacubex/mihomo/context"
	"github.com/metacubex/mihomo/log"

	D "github.com/miekg/dns"
)

type (
	handler    func(ctx *icontext.DNSContext, r *D.Msg) (*D.Msg, error)
	middleware func(next handler) handler
)

func withHosts(mapping *lru.LruCache[netip.Addr, string]) middleware {
	return func(next handler) handler {
		return func(ctx *icontext.DNSContext, r *D.Msg) (*D.Msg, error) {
			q := r.Question[0]

			if !isIPRequest(q) {
				return next(ctx, r)
			}

			host := strings.TrimRight(q.Name, ".")
			handleCName := func(resp *D.Msg, domain string) {
				rr := &D.CNAME{}
				rr.Hdr = D.RR_Header{Name: q.Name, Rrtype: D.TypeCNAME, Class: D.ClassINET, Ttl: 10}
				rr.Target = domain + "."
				resp.Answer = append([]D.RR{rr}, resp.Answer...)
			}
			record, ok := resolver.DefaultHosts.Search(host, q.Qtype != D.TypeA && q.Qtype != D.TypeAAAA)
			if !ok {
				if record != nil && record.IsDomain {
					// replace request domain
					newR := r.Copy()
					newR.Question[0].Name = record.Domain + "."
					resp, err := next(ctx, newR)
					if err == nil {
						resp.Id = r.Id
						resp.Question = r.Question
						handleCName(resp, record.Domain)
					}
					return resp, err
				}
				return next(ctx, r)
			}

			msg := r.Copy()
			handleIPs := func() {
				for _, ipAddr := range record.IPs {
					if ipAddr.Is4() && q.Qtype == D.TypeA {
						rr := &D.A{}
						rr.Hdr = D.RR_Header{Name: q.Name, Rrtype: D.TypeA, Class: D.ClassINET, Ttl: 10}
						rr.A = ipAddr.AsSlice()
						msg.Answer = append(msg.Answer, rr)
						if mapping != nil {
							mapping.SetWithExpire(ipAddr, host, time.Now().Add(time.Second*10))
						}
					} else if ipAddr.Is6() && q.Qtype == D.TypeAAAA {
						rr := &D.AAAA{}
						rr.Hdr = D.RR_Header{Name: q.Name, Rrtype: D.TypeAAAA, Class: D.ClassINET, Ttl: 10}
						rr.AAAA = ipAddr.AsSlice()
						msg.Answer = append(msg.Answer, rr)
						if mapping != nil {
							mapping.SetWithExpire(ipAddr, host, time.Now().Add(time.Second*10))
						}
					}
				}
			}

			switch q.Qtype {
			case D.TypeA:
				handleIPs()
			case D.TypeAAAA:
				handleIPs()
			case D.TypeCNAME:
				handleCName(msg, record.Domain)
			default:
				return next(ctx, r)
			}

			ctx.SetType(icontext.DNSTypeHost)
			msg.SetRcode(r, D.RcodeSuccess)
			msg.Authoritative = true
			msg.RecursionAvailable = true
			return msg, nil
		}
	}
}

func withMapping(mapping *lru.LruCache[netip.Addr, string]) middleware {
	return func(next handler) handler {
		return func(ctx *icontext.DNSContext, r *D.Msg) (*D.Msg, error) {
			q := r.Question[0]

			if !isIPRequest(q) {
				return next(ctx, r)
			}

			msg, err := next(ctx, r)
			if err != nil {
				return nil, err
			}

			host := strings.TrimRight(q.Name, ".")

			for _, ans := range msg.Answer {
				var ip netip.Addr
				var ttl uint32

				switch a := ans.(type) {
				case *D.A:
					ip, _ = netip.AddrFromSlice(a.A)
					ttl = a.Hdr.Ttl
				case *D.AAAA:
					ip, _ = netip.AddrFromSlice(a.AAAA)
					ttl = a.Hdr.Ttl
				default:
					continue
				}
				if !ip.IsValid() {
					continue
				}
				if !ip.IsGlobalUnicast() {
					continue
				}
				ip = ip.Unmap()

				if ttl < 1 {
					ttl = 1
				}

				mapping.SetWithExpire(ip, host, time.Now().Add(time.Second*time.Duration(ttl)))
			}

			return msg, nil
		}
	}
}

// procCacheKey 进程反查缓存键（源 IP + 源端口）
type procCacheKey struct {
	ip   netip.Addr
	port uint16
}

// dnsSrcAddr 从 DNS context 取查询源地址
func dnsSrcAddr(ctx *icontext.DNSContext) net.Addr {
	if v := ctx.Value(srcAddrKey{}); v != nil {
		if addr, ok := v.(net.Addr); ok {
			return addr
		}
	}
	return nil
}

// parseSrcAddr 解析源地址为 (srcIP, srcPort)
func parseSrcAddr(addr net.Addr) (netip.Addr, uint16, bool) {
	switch a := addr.(type) {
	case *net.UDPAddr:
		ip, ok := netip.AddrFromSlice(a.IP)
		if !ok {
			return netip.Addr{}, 0, false
		}
		return ip.Unmap(), uint16(a.Port), true
	case *net.TCPAddr:
		ip, ok := netip.AddrFromSlice(a.IP)
		if !ok {
			return netip.Addr{}, 0, false
		}
		return ip.Unmap(), uint16(a.Port), true
	}
	return netip.Addr{}, 0, false
}

// shouldSkipByProcess 判断 DNS 查询来源进程是否在排除列表中（命中则跳过 fake-ip，返回真实 IP）
func shouldSkipByProcess(ctx *icontext.DNSContext, excludeProcesses []string, cache *lru.LruCache[procCacheKey, string]) bool {
	addr := dnsSrcAddr(ctx)
	if addr == nil {
		return false
	}
	srcIP, srcPort, ok := parseSrcAddr(addr)
	if !ok {
		return false
	}
	key := procCacheKey{ip: srcIP, port: srcPort}
	if name, hit := cache.Get(key); hit {
		return matchProcess(name, excludeProcesses)
	}
	_, path, err := process.FindProcessName(process.UDP, srcIP, int(srcPort))
	if err != nil {
		return false
	}
	name := filepath.Base(path)
	cache.Set(key, name)
	return matchProcess(name, excludeProcesses)
}

// matchProcess 进程名匹配（Windows 进程名不区分大小写）
func matchProcess(name string, excludeProcesses []string) bool {
	name = strings.ToLower(name)
	for _, p := range excludeProcesses {
		if strings.ToLower(filepath.Base(p)) == name {
			return true
		}
	}
	return false
}

func withFakeIP(skipper *fakeip.Skipper, fakePool *fakeip.Pool, fakePool6 *fakeip.Pool, fakeIPTTL int, excludeProcesses []string, procCache *lru.LruCache[procCacheKey, string]) middleware {
	return func(next handler) handler {
		return func(ctx *icontext.DNSContext, r *D.Msg) (*D.Msg, error) {
			q := r.Question[0]

			host := strings.TrimRight(q.Name, ".")
			// 按进程排除 fake-ip：指定进程的 DNS 查询返回真实 IP，配合 route-address 让其流量绕过 TUN
			if len(excludeProcesses) > 0 && shouldSkipByProcess(ctx, excludeProcesses, procCache) {
				return next(ctx, r)
			}
			if skipper.ShouldSkipped(host) {
				return next(ctx, r)
			}

			var rr D.RR
			switch q.Qtype {
			case D.TypeA:
				if fakePool == nil {
					return handleMsgWithEmptyAnswer(r), nil
				}
				ip := fakePool.Lookup(host)
				rr = &D.A{
					Hdr: D.RR_Header{Name: q.Name, Rrtype: D.TypeA, Class: D.ClassINET, Ttl: dnsDefaultTTL},
					A:   ip.AsSlice(),
				}
			case D.TypeAAAA:
				if fakePool6 == nil {
					return handleMsgWithEmptyAnswer(r), nil
				}
				ip := fakePool6.Lookup(host)
				rr = &D.AAAA{
					Hdr:  D.RR_Header{Name: q.Name, Rrtype: D.TypeAAAA, Class: D.ClassINET, Ttl: dnsDefaultTTL},
					AAAA: ip.AsSlice(),
				}
			case D.TypeSVCB, D.TypeHTTPS:
				return handleMsgWithEmptyAnswer(r), nil
			default:
				return next(ctx, r)
			}

			msg := r.Copy()
			msg.Answer = []D.RR{rr}

			ctx.SetType(icontext.DNSTypeFakeIP)
			setMsgTTL(msg, uint32(fakeIPTTL))
			msg.SetRcode(r, D.RcodeSuccess)
			msg.Authoritative = true
			msg.RecursionAvailable = true

			return msg, nil
		}
	}
}

func withResolver(resolver resolver.Resolver, ipv6 bool) handler {
	return func(ctx *icontext.DNSContext, r *D.Msg) (*D.Msg, error) {
		ctx.SetType(icontext.DNSTypeRaw)

		q := r.Question[0]

		// return a empty AAAA msg when ipv6 disabled
		if !ipv6 && q.Qtype == D.TypeAAAA {
			return handleMsgWithEmptyAnswer(r), nil
		}

		msg, err := resolver.ExchangeContext(ctx, r)
		if err != nil {
			log.Debugln("[DNS Server] Exchange %s failed: %v", q.String(), err)
			return msg, err
		}
		msg.SetRcode(r, msg.Rcode)
		msg.Authoritative = true

		return msg, nil
	}
}

func compose(middlewares []middleware, endpoint handler) handler {
	length := len(middlewares)
	h := endpoint
	for i := length - 1; i >= 0; i-- {
		middleware := middlewares[i]
		h = middleware(h)
	}

	return h
}

func newHandler(resolver resolver.Resolver, mapper *ResolverEnhancer) handler {
	var middlewares []middleware

	if mapper.useHosts {
		middlewares = append(middlewares, withHosts(mapper.mapping))
	}

	if mapper.mode == C.DNSFakeIP {
		middlewares = append(middlewares, withFakeIP(mapper.fakeIPSkipper, mapper.fakeIPPool, mapper.fakeIPPool6, mapper.fakeIPTTL, mapper.excludeProcesses, mapper.procCache))
	}

	if mapper.mode != C.DNSNormal {
		middlewares = append(middlewares, withMapping(mapper.mapping))
	}

	return compose(middlewares, withResolver(resolver, mapper.ipv6))
}
