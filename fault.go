package soap

import (
	"encoding/xml"
	"fmt"
)

type SOAPFault struct {
	XMLName xml.Name `xml:"http://schemas.xmlsoap.org/soap/envelope/ Fault"`

	Code   string `xml:"faultcode,omitempty"`
	String string `xml:"faultstring,omitempty"`
	Actor  string `xml:"faultactor,omitempty"`
	Detail string `xml:"detail,omitempty"`
}

func (f *SOAPFault) Error() string {
	return fmt.Sprintf("Soap Fault: %s: [%s] %s", f.Code, f.Actor, f.String)
}
