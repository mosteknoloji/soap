package soap

import (
	"bytes"
	"crypto/tls"
	"encoding/base64"
	"encoding/xml"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"net/http"
	"time"
)

// against "unused imports"
var _ time.Time
var _ xml.Name

var timeout = time.Duration(30 * time.Second)

type RequestSOAPEnvelope struct {
	XMLName xml.Name `xml:"soapenv:Envelope"`
	SoapENV string   `xml:"xmlns:soapenv,attr,omitempty"`
	Ns1     string   `xml:"xmlns:ns1,attr,omitempty"`
	Ns2     string   `xml:"xmlns:ns2,attr,omitempty"`
	Ns3     string   `xml:"xmlns:ns3,attr,omitempty"`

	Header RequestSOAPHeader
	Body   RequestSOAPBody
}

type RequestSOAPHeader struct {
	XMLName xml.Name `xml:"soapenv:Header"`

	Header []interface{}
}

type RequestSOAPBody struct {
	XMLName xml.Name `xml:"soapenv:Body"`

	Fault   *SOAPFault  `xml:",omitempty"`
	Content interface{} `xml:",omitempty"`
}

type ResponseSOAPEnvelope struct {
	XMLName xml.Name `xml:"Envelope"`
	Ns1     string   `xml:"xmlns:ns1,attr,omitempty"`
	Ns2     string   `xml:"xmlns:ns2,attr,omitempty"`
	Ns3     string   `xml:"xmlns:ns3,attr,omitempty"`

	Header ResponseSOAPHeader
	Body   ResponseSOAPBody
}

type ResponseSOAPHeader struct {
	XMLName xml.Name `xml:"Header"`

	Header interface{}
}

type ResponseSOAPBody struct {
	XMLName xml.Name `xml:"Body"`

	Fault   *SOAPFault  `xml:",omitempty"`
	Content interface{} `xml:",omitempty"`
}

type SOAPClient struct {
	base  string
	tls   bool
	debug bool
	// Basic Authentication if needed
	username string
	password string

	userAgent   string
	contentType string
}

func (b *ResponseSOAPBody) UnmarshalXML(d *xml.Decoder, start xml.StartElement) error {
	if b.Content == nil {
		return xml.UnmarshalError("Content must be a pointer to a struct")
	}

	var (
		token    xml.Token
		err      error
		consumed bool
	)

Loop:
	for {
		if token, err = d.Token(); err != nil {
			return err
		}

		if token == nil {
			break
		}

		switch se := token.(type) {
		case xml.StartElement:
			if consumed {
				return xml.UnmarshalError("Found multiple elements inside SOAP body; not wrapped-document/literal WS-I compliant")
			} else if se.Name.Space == "http://schemas.xmlsoap.org/soap/envelope/" && se.Name.Local == "Fault" {
				b.Fault = &SOAPFault{}
				b.Content = nil

				err = d.DecodeElement(b.Fault, &se)
				if err != nil {
					return err
				}

				consumed = true
			} else {
				if err = d.DecodeElement(b.Content, &se); err != nil {
					return err
				}

				consumed = true
			}
		case xml.EndElement:
			break Loop
		}
	}

	return nil
}

func NewSOAPClient(base string, tls bool, debug bool) *SOAPClient {
	return &SOAPClient{
		base:  base,
		tls:   tls,
		debug: debug,
	}
}

func ParseFromRequest(req *http.Request, v interface{}) error {
	bytes, err := ioutil.ReadAll(req.Body)
	if err != nil {
		return err
	}
	return Parse(bytes, v)
}

func Parse(data []byte, v interface{}) error {
	env := new(ResponseSOAPEnvelope)
	env.Body = ResponseSOAPBody{Content: v}
	if err := xml.Unmarshal(data, env); err != nil {
		return err
	}
	fault := env.Body.Fault
	if fault != nil {
		return fault
	}
	return nil
}

func Fault(faultcode, faultstring, faultactor string) string {
	return fmt.Sprintf(`<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/">
							<soapenv:Body>
								<soapenv:Fault>
									<faultcode>%s</faultcode>
									<faultstring>%s</faultstring>
									<faultactor>%s</faultactor>
								</soapenv:Fault>
							</soapenv:Body>
						</soapenv:Envelope>`, faultcode, faultstring, faultactor)
}

func Serialize(header []interface{}, body interface{}, nsHeader, ns1, ns2, ns3 string) (*bytes.Buffer, error) {
	if nsHeader == "" {
		nsHeader = "http://schemas.xmlsoap.org/soap/envelope/"
	}
	envelope := RequestSOAPEnvelope{SoapENV: nsHeader, Ns1: ns1, Ns2: ns2, Ns3: ns3}

	if header != nil {
		envelope.Header = RequestSOAPHeader{Header: header}
	}

	envelope.Body.Content = body
	buff := new(bytes.Buffer)

	encoder := xml.NewEncoder(buff)

	if err := encoder.Encode(envelope); err != nil {
		return nil, err
	}

	if err := encoder.Flush(); err != nil {
		return nil, err
	}

	return buff, nil
}

func (s *SOAPClient) SetBasicAuth(username string, password string) {
	s.username = username
	s.password = password
}

func (s *SOAPClient) SetUserAgent(useragent string) {
	s.userAgent = useragent
}

func (s *SOAPClient) SetContentType(contentType string) {
	s.contentType = contentType
}

func basicAuth(username, password string) string {
	auth := username + ":" + password
	return base64.StdEncoding.EncodeToString([]byte(auth))
}

func (s *SOAPClient) Call(path, action string, header []interface{}, request, response interface{}, nsHeader, ns1, ns2, ns3 string) error {
	buffer, err := Serialize(header, request, nsHeader, ns1, ns2, ns3)
	if err != nil {
		return err
	}

	if s.debug {
		debugPrintXml("Request:", []byte(buffer.String()))
	}

	url := fmt.Sprintf("%s%s", s.base, path)

	req, err := http.NewRequest("POST", url, buffer)
	if err != nil {
		return err
	}

	if s.contentType != "" {
		req.Header.Add("Content-Type", s.contentType)
	} else {
		req.Header.Add("Content-Type", "text/xml; charset=\"utf-8\"")
	}

	if action != "" {
		req.Header.Add("SOAPAction", action)
	}

	if s.userAgent != "" {
		req.Header.Set("User-Agent", s.userAgent)
	} else {
		req.Header.Set("User-Agent", "Go")
	}

	req.Close = true

	if s.username != "" {
		req.Header.Set("Authorization", "Basic "+basicAuth(s.username, s.password))
	}

	tr := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: s.tls,
		},

		// Dial timeout limits the time spent establishing a TCP connection (if a new one is needed). [1]
		// [1] https://blog.cloudflare.com/the-complete-guide-to-golang-net-http-timeouts/
		DialContext: (&net.Dialer{
			Timeout: timeout,
		}).DialContext,
	}

	client := &http.Client{
		Transport: tr,
		// By default http.client doesn't timeout [2]
		// [2] https://medium.com/@nate510/don-t-use-go-s-default-http-client-4804cb19f779
		// http.Client.Timeout includes all time spent following redirects, while the granular timeouts are specific for each request, since http.Transport is a lower level system that has no concept of redirects. [1
		Timeout: 3 * timeout,
	}
	res, err := client.Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()

	rawbody, err := ioutil.ReadAll(res.Body)
	if err != nil {
		return err
	}
	if len(rawbody) == 0 {
		// log.Println("empty response")
		return nil
	}

	if s.debug {
		debugPrintXml("Response:", rawbody)
	}

	if err := Parse(rawbody, response); err != nil {
		return err
	}
	return nil
}

func formatXML(data []byte) ([]byte, error) {
	b := &bytes.Buffer{}
	decoder := xml.NewDecoder(bytes.NewReader(data))
	encoder := xml.NewEncoder(b)
	encoder.Indent("", "  ")
	for {
		token, err := decoder.Token()
		if err == io.EOF {
			encoder.Flush()
			return b.Bytes(), nil
		}
		if err != nil {
			return nil, err
		}
		err = encoder.EncodeToken(token)
		if err != nil {
			return nil, err
		}
	}
}

func debugPrintXml(info string, data []byte) {
	fmt.Println()
	fmt.Println("************************************************************************************")
	fmt.Println(info)
	b, _ := formatXML(data)
	fmt.Println(string(b))
	fmt.Println()
	fmt.Println("************************************************************************************")
	fmt.Println()
}
