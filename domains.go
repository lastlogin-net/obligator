package obligator

import (
	"errors"
	"fmt"
	"html/template"
	"io"
	"net"
	"net/http"
	"net/url"
)

type DomainHandler struct {
	mux *http.ServeMux
}

func (h *DomainHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	h.mux.ServeHTTP(w, r)
}

func NewDomainHandler(db *Database, tmpl *template.Template, proxy Proxy, jose *JOSE) *DomainHandler {

	mux := http.NewServeMux()

	mux.HandleFunc("/domains", func(w http.ResponseWriter, r *http.Request) {

		// TODO: can probably be done once at startup
		ips, err := net.LookupIP(r.Host)
		if err != nil {
			w.WriteHeader(500)
			io.WriteString(w, err.Error())
			return
		}

		var ipv4 net.IP
		var ipv6 net.IP
		for _, ip := range ips {
			if ip.To4() != nil {
				ipv4 = ip
			} else {
				ipv6 = ip
			}
		}

		data := struct {
			*commonData
			Host string
			Ipv4 string
			Ipv6 string
		}{
			commonData: newCommonData(nil, db, r),
			Host:       r.Host,
			Ipv4:       ipv4.String(),
			Ipv6:       ipv6.String(),
		}

		err = tmpl.ExecuteTemplate(w, "domains.html", data)
		if err != nil {
			w.WriteHeader(500)
			io.WriteString(w, err.Error())
			return
		}
	})

	mux.HandleFunc("/add-domain", func(w http.ResponseWriter, r *http.Request) {

		r.ParseForm()

		// TODO: sanitize domain
		domain := r.Form.Get("domain")

		if domain == "" {
			w.WriteHeader(400)
			io.WriteString(w, "Missing domain")
			return
		}

		_, err := url.Parse(domain)
		if err != nil {
			w.WriteHeader(400)
			io.WriteString(w, err.Error())
			return
		}

		ownerId := r.Form.Get("owner_id")

		idents, _ := getIdentities(db, r)

		match := false
		for _, ident := range idents {
			if ident.Id == ownerId {
				match = true
				break
			}
		}

		if !match {
			w.WriteHeader(403)
			io.WriteString(w, "You don't own that ID")
			return
		}

		err = verifyIpsMatch(domain, r.Host)
		if err != nil {
			w.WriteHeader(400)
			io.WriteString(w, err.Error())
			return
		}

		//cname, err := getAuthoritativeCNAME(r.Context(), domain)
		//if err != nil {
		//        w.WriteHeader(500)
		//        io.WriteString(w, err.Error())
		//        return
		//}

		//if cname != rootUrl.Host {
		//        fmt.Println(cname, rootUrl.Host)
		//        w.WriteHeader(400)
		//        io.WriteString(w, "CNAME != host")
		//        return
		//}

		err = proxy.AddDomain(domain)
		if err != nil {
			w.WriteHeader(500)
			io.WriteString(w, err.Error())
			return
		}

		err = db.AddDomain(domain, ownerId)
		if err != nil {
			w.WriteHeader(500)
			io.WriteString(w, err.Error())
			return
		}

		http.Redirect(w, r, fmt.Sprintf("https://%s/login", domain), 303)
	})

	h := &DomainHandler{
		mux: mux,
	}

	return h
}

func verifyIpsMatch(domainA, domainB string) error {

	aIps, err := net.LookupHost(domainA)
	if err != nil {
		return err
	}

	bIps, err := net.LookupHost(domainB)
	if err != nil {
		return err
	}

	for _, aIp := range aIps {
		match := false
		for _, bIp := range bIps {
			if aIp == bIp {
				match = true
				break
			}
		}

		if !match {
			return errors.New("No matching IP. Make sure you either have either a CNAME or BOTH A and AAAA records set up.")
		}
	}

	return nil
}
