package dns

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"strings"

	"golang.org/x/net/dns/dnsmessage"
)

// Pack converts m to a DNS wire-format packet.
func Pack(m *Message) ([]byte, error) {
	b := dnsmessage.NewBuilder(nil, dnsmessage.Header{
		ID:                 m.ID,
		Response:           m.Response,
		OpCode:             dnsmessage.OpCode(m.Opcode),
		RCode:              dnsmessage.RCode(m.RCode),
		Authoritative:      m.Authoritative,
		Truncated:          m.Truncated,
		RecursionDesired:   m.RecursionDesired,
		RecursionAvailable: m.RecursionAvailable,
		AuthenticData:      m.AuthenticatedData,
		CheckingDisabled:   m.CheckingDisabled,
	})
	if err := b.StartQuestions(); err != nil {
		return nil, err
	}
	for _, q := range m.Questions {
		name, err := wireName(q.Name)
		if err != nil {
			return nil, err
		}
		if err := b.Question(dnsmessage.Question{
			Name:  name,
			Type:  dnsmessage.Type(q.Type),
			Class: dnsmessage.Class(q.Class),
		}); err != nil {
			return nil, err
		}
	}
	if err := packSection(&b, m.Answers, b.StartAnswers); err != nil {
		return nil, err
	}
	if err := packSection(&b, m.Authorities, b.StartAuthorities); err != nil {
		return nil, err
	}
	if err := packSection(&b, m.Additionals, b.StartAdditionals); err != nil {
		return nil, err
	}
	return b.Finish()
}

func packSection(
	b *dnsmessage.Builder,
	rrs []Resource,
	start func() error,
) error {
	if err := start(); err != nil {
		return err
	}
	for _, rr := range rrs {
		name, err := wireName(rr.Name)
		if err != nil {
			return err
		}
		h := dnsmessage.ResourceHeader{
			Name:  name,
			Type:  dnsmessage.Type(rr.Type),
			Class: dnsmessage.Class(rr.Class),
			TTL:   rr.TTL,
		}
		if err := packResource(b, h, rr.Data); err != nil {
			return err
		}
	}
	return nil
}

func packResource(
	b *dnsmessage.Builder,
	h dnsmessage.ResourceHeader,
	data []byte,
) error {
	switch uint16(h.Type) {
	case TypeA:
		if len(data) != net.IPv4len {
			return errors.New("dns: invalid A data")
		}
		var a [4]byte
		copy(a[:], data)
		return b.AResource(h, dnsmessage.AResource{A: a})
	case TypeAAAA:
		if len(data) != net.IPv6len {
			return errors.New("dns: invalid AAAA data")
		}
		var a [16]byte
		copy(a[:], data)
		return b.AAAAResource(h, dnsmessage.AAAAResource{AAAA: a})
	case TypeCNAME:
		cname, err := wireName(string(data))
		if err != nil {
			return err
		}
		return b.CNAMEResource(
			h,
			dnsmessage.CNAMEResource{CNAME: cname},
		)
	case TypeNS:
		ns, err := wireName(string(data))
		if err != nil {
			return err
		}
		return b.NSResource(
			h,
			dnsmessage.NSResource{NS: ns},
		)
	case TypePTR:
		ptr, err := wireName(string(data))
		if err != nil {
			return err
		}
		return b.PTRResource(
			h,
			dnsmessage.PTRResource{PTR: ptr},
		)
	case TypeMX:
		if len(data) < 3 {
			return errors.New("dns: invalid MX data")
		}
		mx, err := wireName(string(data[2:]))
		if err != nil {
			return err
		}
		return b.MXResource(h, dnsmessage.MXResource{
			Pref: binary.BigEndian.Uint16(data[:2]),
			MX:   mx,
		})
	case TypeSRV:
		if len(data) < 7 {
			return errors.New("dns: invalid SRV data")
		}
		target, err := wireName(string(data[6:]))
		if err != nil {
			return err
		}
		return b.SRVResource(h, dnsmessage.SRVResource{
			Priority: binary.BigEndian.Uint16(data[0:2]),
			Weight:   binary.BigEndian.Uint16(data[2:4]),
			Port:     binary.BigEndian.Uint16(data[4:6]),
			Target:   target,
		})
	case TypeSOA:
		soa, err := unpackSOAData(data)
		if err != nil {
			return err
		}
		return b.SOAResource(h, soa)
	case TypeTXT:
		if _, ok := txtSegments(data); ok {
			return b.UnknownResource(h, dnsmessage.UnknownResource{
				Type: h.Type,
				Data: data,
			})
		}
		return b.TXTResource(h, dnsmessage.TXTResource{
			TXT: rawTXTSegments(data),
		})
	case uint16(dnsmessage.TypeOPT):
		options, err := unpackOPTData(data)
		if err != nil {
			return err
		}
		return b.OPTResource(h, dnsmessage.OPTResource{Options: options})
	default:
		return b.UnknownResource(h, dnsmessage.UnknownResource{
			Type: h.Type,
			Data: data,
		})
	}
}

// Unpack parses a DNS wire-format packet.
func Unpack(pkt []byte) (*Message, error) {
	var p dnsmessage.Parser
	h, err := p.Start(pkt)
	if err != nil {
		return nil, err
	}
	m := &Message{
		ID:       h.ID,
		Response: h.Response,
		// #nosec G115 -- DNS opcodes and rcodes are header bit fields.
		Opcode: uint8(h.OpCode & 0xff),
		// #nosec G115 -- DNS opcodes and rcodes are header bit fields.
		RCode:              uint8(h.RCode & 0xff),
		Authoritative:      h.Authoritative,
		Truncated:          h.Truncated,
		RecursionDesired:   h.RecursionDesired,
		RecursionAvailable: h.RecursionAvailable,
		AuthenticatedData:  h.AuthenticData,
		CheckingDisabled:   h.CheckingDisabled,
	}
	qs, err := p.AllQuestions()
	if err != nil {
		return nil, err
	}
	for _, q := range qs {
		m.Questions = append(m.Questions, Question{
			Name:  q.Name.String(),
			Type:  uint16(q.Type),
			Class: uint16(q.Class),
		})
	}
	if m.Answers, err = unpackSection(p.Answer); err != nil {
		return nil, err
	}
	if m.Authorities, err = unpackSection(p.Authority); err != nil {
		return nil, err
	}
	if m.Additionals, err = unpackSection(p.Additional); err != nil {
		return nil, err
	}
	return m, nil
}

func unpackSection(
	next func() (dnsmessage.Resource, error),
) ([]Resource, error) {
	var out []Resource
	for {
		r, err := next()
		if errors.Is(err, dnsmessage.ErrSectionDone) {
			return out, nil
		}
		if err != nil {
			return nil, err
		}
		out = append(out, Resource{
			Name:  r.Header.Name.String(),
			Type:  uint16(r.Header.Type),
			Class: uint16(r.Header.Class),
			TTL:   r.Header.TTL,
			Data:  resourceData(r.Body),
		})
	}
}

func resourceData(body dnsmessage.ResourceBody) []byte {
	switch b := body.(type) {
	case *dnsmessage.AResource:
		return append([]byte(nil), b.A[:]...)
	case *dnsmessage.AAAAResource:
		return append([]byte(nil), b.AAAA[:]...)
	case *dnsmessage.CNAMEResource:
		return []byte(b.CNAME.String())
	case *dnsmessage.NSResource:
		return []byte(b.NS.String())
	case *dnsmessage.PTRResource:
		return []byte(b.PTR.String())
	case *dnsmessage.MXResource:
		out := make([]byte, 2, 2+len(b.MX.String()))
		binary.BigEndian.PutUint16(out, b.Pref)
		out = append(out, b.MX.String()...)
		return out
	case *dnsmessage.SRVResource:
		out := make([]byte, 6, 6+len(b.Target.String()))
		binary.BigEndian.PutUint16(out[0:2], b.Priority)
		binary.BigEndian.PutUint16(out[2:4], b.Weight)
		binary.BigEndian.PutUint16(out[4:6], b.Port)
		out = append(out, b.Target.String()...)
		return out
	case *dnsmessage.SOAResource:
		out := appendWireNameData(nil, b.NS.String())
		out = appendWireNameData(out, b.MBox.String())
		out = binary.BigEndian.AppendUint32(out, b.Serial)
		out = binary.BigEndian.AppendUint32(out, b.Refresh)
		out = binary.BigEndian.AppendUint32(out, b.Retry)
		out = binary.BigEndian.AppendUint32(out, b.Expire)
		return binary.BigEndian.AppendUint32(out, b.MinTTL)
	case *dnsmessage.TXTResource:
		var out []byte
		for _, s := range b.TXT {
			out = append(out, byte(len(s)))
			out = append(out, s...)
		}
		return out
	case *dnsmessage.OPTResource:
		var out []byte
		for _, option := range b.Options {
			// DNS option lengths are 16-bit wire values.
			optionLength := uint16(len(option.Data)) //nolint:gosec
			out = binary.BigEndian.AppendUint16(out, option.Code)
			out = binary.BigEndian.AppendUint16(out, optionLength)
			out = append(out, option.Data...)
		}
		return out
	case *dnsmessage.UnknownResource:
		return append([]byte(nil), b.Data...)
	default:
		return nil
	}
}

func unpackSOAData(data []byte) (dnsmessage.SOAResource, error) {
	nsText, offset, err := unpackWireNameData(data, 0)
	if err != nil {
		return dnsmessage.SOAResource{}, fmt.Errorf(
			"dns: invalid SOA NS: %w",
			err,
		)
	}
	mboxText, offset, err := unpackWireNameData(data, offset)
	if err != nil {
		return dnsmessage.SOAResource{}, fmt.Errorf(
			"dns: invalid SOA MBox: %w",
			err,
		)
	}
	if len(data)-offset != 20 {
		return dnsmessage.SOAResource{}, errors.New("dns: invalid SOA data")
	}
	ns, err := wireName(nsText)
	if err != nil {
		return dnsmessage.SOAResource{}, err
	}
	mbox, err := wireName(mboxText)
	if err != nil {
		return dnsmessage.SOAResource{}, err
	}
	return dnsmessage.SOAResource{
		NS:      ns,
		MBox:    mbox,
		Serial:  binary.BigEndian.Uint32(data[offset:]),
		Refresh: binary.BigEndian.Uint32(data[offset+4:]),
		Retry:   binary.BigEndian.Uint32(data[offset+8:]),
		Expire:  binary.BigEndian.Uint32(data[offset+12:]),
		MinTTL:  binary.BigEndian.Uint32(data[offset+16:]),
	}, nil
}

func unpackOPTData(data []byte) ([]dnsmessage.Option, error) {
	var options []dnsmessage.Option
	for len(data) != 0 {
		if len(data) < 4 {
			return nil, errors.New("dns: invalid OPT data")
		}
		length := int(binary.BigEndian.Uint16(data[2:4]))
		if length > len(data)-4 {
			return nil, errors.New("dns: invalid OPT option length")
		}
		options = append(options, dnsmessage.Option{
			Code: binary.BigEndian.Uint16(data[:2]),
			Data: append([]byte(nil), data[4:4+length]...),
		})
		data = data[4+length:]
	}
	return options, nil
}

func unpackWireNameData(data []byte, offset int) (string, int, error) {
	var name []byte
	for {
		if offset >= len(data) {
			return "", 0, errors.New("truncated wire name")
		}
		length := int(data[offset])
		offset++
		if length == 0 {
			if len(name) == 0 {
				return ".", offset, nil
			}
			return string(name), offset, nil
		}
		if length > 63 || length > len(data)-offset {
			return "", 0, errors.New("invalid wire name label")
		}
		if bytes.IndexByte(data[offset:offset+length], '.') >= 0 {
			return "", 0, errors.New("wire name label contains a dot")
		}
		name = append(name, data[offset:offset+length]...)
		name = append(name, '.')
		offset += length
	}
}

func appendWireNameData(dst []byte, name string) []byte {
	if name == "." {
		return append(dst, 0)
	}
	for label := range strings.SplitSeq(strings.TrimSuffix(name, "."), ".") {
		dst = append(dst, byte(len(label)))
		dst = append(dst, label...)
	}
	return append(dst, 0)
}

func txtSegments(data []byte) ([]string, bool) {
	var out []string
	for len(data) > 0 {
		n := int(data[0])
		data = data[1:]
		if n > len(data) {
			return nil, false
		}
		out = append(out, string(data[:n]))
		data = data[n:]
	}
	return out, true
}

func rawTXTSegments(data []byte) []string {
	if len(data) == 0 {
		return []string{""}
	}
	out := make([]string, 0, (len(data)+254)/255)
	for len(data) > 0 {
		n := min(len(data), 255)
		out = append(out, string(data[:n]))
		data = data[n:]
	}
	return out
}

func wireName(name string) (dnsmessage.Name, error) {
	n, err := dnsmessage.NewName(absName(name))
	if err != nil {
		return dnsmessage.Name{}, err
	}
	return n, nil
}

func absName(name string) string {
	if name == "" || name == "." {
		return "."
	}
	if name[len(name)-1] == '.' {
		return name
	}
	return name + "."
}
