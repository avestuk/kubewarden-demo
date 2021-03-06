// Code generated by easyjson for marshaling/unmarshaling. DO NOT EDIT.

package v1

import (
	json "encoding/json"
	easyjson "github.com/mailru/easyjson"
	jlexer "github.com/mailru/easyjson/jlexer"
	jwriter "github.com/mailru/easyjson/jwriter"
)

// suppress unused package warning
var (
	_ *json.RawMessage
	_ *jlexer.Lexer
	_ *jwriter.Writer
	_ easyjson.Marshaler
)

func easyjson76d27232DecodeGithubComKubewardenK8sObjectsApiCoreV1(in *jlexer.Lexer, out *PodDNSConfig) {
	isTopLevel := in.IsStart()
	if in.IsNull() {
		if isTopLevel {
			in.Consumed()
		}
		in.Skip()
		return
	}
	in.Delim('{')
	for !in.IsDelim('}') {
		key := in.UnsafeFieldName(false)
		in.WantColon()
		if in.IsNull() {
			in.Skip()
			in.WantComma()
			continue
		}
		switch key {
		case "nameservers":
			if in.IsNull() {
				in.Skip()
				out.Nameservers = nil
			} else {
				in.Delim('[')
				if out.Nameservers == nil {
					if !in.IsDelim(']') {
						out.Nameservers = make([]string, 0, 4)
					} else {
						out.Nameservers = []string{}
					}
				} else {
					out.Nameservers = (out.Nameservers)[:0]
				}
				for !in.IsDelim(']') {
					var v1 string
					v1 = string(in.String())
					out.Nameservers = append(out.Nameservers, v1)
					in.WantComma()
				}
				in.Delim(']')
			}
		case "options":
			if in.IsNull() {
				in.Skip()
				out.Options = nil
			} else {
				in.Delim('[')
				if out.Options == nil {
					if !in.IsDelim(']') {
						out.Options = make([]*PodDNSConfigOption, 0, 8)
					} else {
						out.Options = []*PodDNSConfigOption{}
					}
				} else {
					out.Options = (out.Options)[:0]
				}
				for !in.IsDelim(']') {
					var v2 *PodDNSConfigOption
					if in.IsNull() {
						in.Skip()
						v2 = nil
					} else {
						if v2 == nil {
							v2 = new(PodDNSConfigOption)
						}
						easyjson76d27232DecodeGithubComKubewardenK8sObjectsApiCoreV11(in, v2)
					}
					out.Options = append(out.Options, v2)
					in.WantComma()
				}
				in.Delim(']')
			}
		case "searches":
			if in.IsNull() {
				in.Skip()
				out.Searches = nil
			} else {
				in.Delim('[')
				if out.Searches == nil {
					if !in.IsDelim(']') {
						out.Searches = make([]string, 0, 4)
					} else {
						out.Searches = []string{}
					}
				} else {
					out.Searches = (out.Searches)[:0]
				}
				for !in.IsDelim(']') {
					var v3 string
					v3 = string(in.String())
					out.Searches = append(out.Searches, v3)
					in.WantComma()
				}
				in.Delim(']')
			}
		default:
			in.SkipRecursive()
		}
		in.WantComma()
	}
	in.Delim('}')
	if isTopLevel {
		in.Consumed()
	}
}
func easyjson76d27232EncodeGithubComKubewardenK8sObjectsApiCoreV1(out *jwriter.Writer, in PodDNSConfig) {
	out.RawByte('{')
	first := true
	_ = first
	if len(in.Nameservers) != 0 {
		const prefix string = ",\"nameservers\":"
		first = false
		out.RawString(prefix[1:])
		{
			out.RawByte('[')
			for v4, v5 := range in.Nameservers {
				if v4 > 0 {
					out.RawByte(',')
				}
				out.String(string(v5))
			}
			out.RawByte(']')
		}
	}
	if len(in.Options) != 0 {
		const prefix string = ",\"options\":"
		if first {
			first = false
			out.RawString(prefix[1:])
		} else {
			out.RawString(prefix)
		}
		{
			out.RawByte('[')
			for v6, v7 := range in.Options {
				if v6 > 0 {
					out.RawByte(',')
				}
				if v7 == nil {
					out.RawString("null")
				} else {
					easyjson76d27232EncodeGithubComKubewardenK8sObjectsApiCoreV11(out, *v7)
				}
			}
			out.RawByte(']')
		}
	}
	if len(in.Searches) != 0 {
		const prefix string = ",\"searches\":"
		if first {
			first = false
			out.RawString(prefix[1:])
		} else {
			out.RawString(prefix)
		}
		{
			out.RawByte('[')
			for v8, v9 := range in.Searches {
				if v8 > 0 {
					out.RawByte(',')
				}
				out.String(string(v9))
			}
			out.RawByte(']')
		}
	}
	out.RawByte('}')
}

// MarshalJSON supports json.Marshaler interface
func (v PodDNSConfig) MarshalJSON() ([]byte, error) {
	w := jwriter.Writer{}
	easyjson76d27232EncodeGithubComKubewardenK8sObjectsApiCoreV1(&w, v)
	return w.Buffer.BuildBytes(), w.Error
}

// MarshalEasyJSON supports easyjson.Marshaler interface
func (v PodDNSConfig) MarshalEasyJSON(w *jwriter.Writer) {
	easyjson76d27232EncodeGithubComKubewardenK8sObjectsApiCoreV1(w, v)
}

// UnmarshalJSON supports json.Unmarshaler interface
func (v *PodDNSConfig) UnmarshalJSON(data []byte) error {
	r := jlexer.Lexer{Data: data}
	easyjson76d27232DecodeGithubComKubewardenK8sObjectsApiCoreV1(&r, v)
	return r.Error()
}

// UnmarshalEasyJSON supports easyjson.Unmarshaler interface
func (v *PodDNSConfig) UnmarshalEasyJSON(l *jlexer.Lexer) {
	easyjson76d27232DecodeGithubComKubewardenK8sObjectsApiCoreV1(l, v)
}
func easyjson76d27232DecodeGithubComKubewardenK8sObjectsApiCoreV11(in *jlexer.Lexer, out *PodDNSConfigOption) {
	isTopLevel := in.IsStart()
	if in.IsNull() {
		if isTopLevel {
			in.Consumed()
		}
		in.Skip()
		return
	}
	in.Delim('{')
	for !in.IsDelim('}') {
		key := in.UnsafeFieldName(false)
		in.WantColon()
		if in.IsNull() {
			in.Skip()
			in.WantComma()
			continue
		}
		switch key {
		case "name":
			out.Name = string(in.String())
		case "value":
			out.Value = string(in.String())
		default:
			in.SkipRecursive()
		}
		in.WantComma()
	}
	in.Delim('}')
	if isTopLevel {
		in.Consumed()
	}
}
func easyjson76d27232EncodeGithubComKubewardenK8sObjectsApiCoreV11(out *jwriter.Writer, in PodDNSConfigOption) {
	out.RawByte('{')
	first := true
	_ = first
	if in.Name != "" {
		const prefix string = ",\"name\":"
		first = false
		out.RawString(prefix[1:])
		out.String(string(in.Name))
	}
	if in.Value != "" {
		const prefix string = ",\"value\":"
		if first {
			first = false
			out.RawString(prefix[1:])
		} else {
			out.RawString(prefix)
		}
		out.String(string(in.Value))
	}
	out.RawByte('}')
}
