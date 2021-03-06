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

func easyjson62dce9f0DecodeGithubComKubewardenK8sObjectsApiCoreV1(in *jlexer.Lexer, out *GitRepoVolumeSource) {
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
		case "directory":
			out.Directory = string(in.String())
		case "repository":
			if in.IsNull() {
				in.Skip()
				out.Repository = nil
			} else {
				if out.Repository == nil {
					out.Repository = new(string)
				}
				*out.Repository = string(in.String())
			}
		case "revision":
			out.Revision = string(in.String())
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
func easyjson62dce9f0EncodeGithubComKubewardenK8sObjectsApiCoreV1(out *jwriter.Writer, in GitRepoVolumeSource) {
	out.RawByte('{')
	first := true
	_ = first
	if in.Directory != "" {
		const prefix string = ",\"directory\":"
		first = false
		out.RawString(prefix[1:])
		out.String(string(in.Directory))
	}
	{
		const prefix string = ",\"repository\":"
		if first {
			first = false
			out.RawString(prefix[1:])
		} else {
			out.RawString(prefix)
		}
		if in.Repository == nil {
			out.RawString("null")
		} else {
			out.String(string(*in.Repository))
		}
	}
	if in.Revision != "" {
		const prefix string = ",\"revision\":"
		out.RawString(prefix)
		out.String(string(in.Revision))
	}
	out.RawByte('}')
}

// MarshalJSON supports json.Marshaler interface
func (v GitRepoVolumeSource) MarshalJSON() ([]byte, error) {
	w := jwriter.Writer{}
	easyjson62dce9f0EncodeGithubComKubewardenK8sObjectsApiCoreV1(&w, v)
	return w.Buffer.BuildBytes(), w.Error
}

// MarshalEasyJSON supports easyjson.Marshaler interface
func (v GitRepoVolumeSource) MarshalEasyJSON(w *jwriter.Writer) {
	easyjson62dce9f0EncodeGithubComKubewardenK8sObjectsApiCoreV1(w, v)
}

// UnmarshalJSON supports json.Unmarshaler interface
func (v *GitRepoVolumeSource) UnmarshalJSON(data []byte) error {
	r := jlexer.Lexer{Data: data}
	easyjson62dce9f0DecodeGithubComKubewardenK8sObjectsApiCoreV1(&r, v)
	return r.Error()
}

// UnmarshalEasyJSON supports easyjson.Unmarshaler interface
func (v *GitRepoVolumeSource) UnmarshalEasyJSON(l *jlexer.Lexer) {
	easyjson62dce9f0DecodeGithubComKubewardenK8sObjectsApiCoreV1(l, v)
}
