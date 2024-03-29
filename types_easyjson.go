// Code generated by easyjson for marshaling/unmarshaling. DO NOT EDIT.

package main

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

func easyjson6601e8cdDecodeTmpEasyjson(in *jlexer.Lexer, out *BasicSettings) {
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
		case "container_registries":
			if in.IsNull() {
				in.Skip()
				out.ContainerRegistries = nil
			} else {
				in.Delim('[')
				if out.ContainerRegistries == nil {
					if !in.IsDelim(']') {
						out.ContainerRegistries = make([]string, 0, 4)
					} else {
						out.ContainerRegistries = []string{}
					}
				} else {
					out.ContainerRegistries = (out.ContainerRegistries)[:0]
				}
				for !in.IsDelim(']') {
					var v1 string
					v1 = string(in.String())
					out.ContainerRegistries = append(out.ContainerRegistries, v1)
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
func easyjson6601e8cdEncodeTmpEasyjson(out *jwriter.Writer, in BasicSettings) {
	out.RawByte('{')
	first := true
	_ = first
	{
		const prefix string = ",\"container_registries\":"
		out.RawString(prefix[1:])
		if in.ContainerRegistries == nil && (out.Flags&jwriter.NilSliceAsEmpty) == 0 {
			out.RawString("null")
		} else {
			out.RawByte('[')
			for v2, v3 := range in.ContainerRegistries {
				if v2 > 0 {
					out.RawByte(',')
				}
				out.String(string(v3))
			}
			out.RawByte(']')
		}
	}
	out.RawByte('}')
}

// MarshalJSON supports json.Marshaler interface
func (v BasicSettings) MarshalJSON() ([]byte, error) {
	w := jwriter.Writer{}
	easyjson6601e8cdEncodeTmpEasyjson(&w, v)
	return w.Buffer.BuildBytes(), w.Error
}

// MarshalEasyJSON supports easyjson.Marshaler interface
func (v BasicSettings) MarshalEasyJSON(w *jwriter.Writer) {
	easyjson6601e8cdEncodeTmpEasyjson(w, v)
}

// UnmarshalJSON supports json.Unmarshaler interface
func (v *BasicSettings) UnmarshalJSON(data []byte) error {
	r := jlexer.Lexer{Data: data}
	easyjson6601e8cdDecodeTmpEasyjson(&r, v)
	return r.Error()
}

// UnmarshalEasyJSON supports easyjson.Unmarshaler interface
func (v *BasicSettings) UnmarshalEasyJSON(l *jlexer.Lexer) {
	easyjson6601e8cdDecodeTmpEasyjson(l, v)
}
