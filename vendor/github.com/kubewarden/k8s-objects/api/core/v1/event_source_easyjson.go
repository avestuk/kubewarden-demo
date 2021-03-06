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

func easyjson4496a294DecodeGithubComKubewardenK8sObjectsApiCoreV1(in *jlexer.Lexer, out *EventSource) {
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
		case "component":
			out.Component = string(in.String())
		case "host":
			out.Host = string(in.String())
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
func easyjson4496a294EncodeGithubComKubewardenK8sObjectsApiCoreV1(out *jwriter.Writer, in EventSource) {
	out.RawByte('{')
	first := true
	_ = first
	if in.Component != "" {
		const prefix string = ",\"component\":"
		first = false
		out.RawString(prefix[1:])
		out.String(string(in.Component))
	}
	if in.Host != "" {
		const prefix string = ",\"host\":"
		if first {
			first = false
			out.RawString(prefix[1:])
		} else {
			out.RawString(prefix)
		}
		out.String(string(in.Host))
	}
	out.RawByte('}')
}

// MarshalJSON supports json.Marshaler interface
func (v EventSource) MarshalJSON() ([]byte, error) {
	w := jwriter.Writer{}
	easyjson4496a294EncodeGithubComKubewardenK8sObjectsApiCoreV1(&w, v)
	return w.Buffer.BuildBytes(), w.Error
}

// MarshalEasyJSON supports easyjson.Marshaler interface
func (v EventSource) MarshalEasyJSON(w *jwriter.Writer) {
	easyjson4496a294EncodeGithubComKubewardenK8sObjectsApiCoreV1(w, v)
}

// UnmarshalJSON supports json.Unmarshaler interface
func (v *EventSource) UnmarshalJSON(data []byte) error {
	r := jlexer.Lexer{Data: data}
	easyjson4496a294DecodeGithubComKubewardenK8sObjectsApiCoreV1(&r, v)
	return r.Error()
}

// UnmarshalEasyJSON supports easyjson.Unmarshaler interface
func (v *EventSource) UnmarshalEasyJSON(l *jlexer.Lexer) {
	easyjson4496a294DecodeGithubComKubewardenK8sObjectsApiCoreV1(l, v)
}
