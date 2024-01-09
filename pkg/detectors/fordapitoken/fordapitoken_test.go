//go:build detectors
// +build detectors

package fordapitoken

import (
	"context"
	"fmt"
	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"testing"
	"time"

	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"

	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detectorspb"
)

func TestFordapitoken_FromChunk(t *testing.T) {
	secret := "k/JKW34xTQh5lKJ0E1RB89FO/HgoW9ezuSvEZZXMQAZsrguZZNGqQCZAWX0fm2cu+LWZxmZdA6j58v5pG8mmpCBse3qkfcGZ6Bbw4mdYcN9CTcsI0ssPBjXjgCOb//lqVctsHUdGA3avYrQ0ineybYaWAN4LExHDFq+TEANzUysPaP8Q81k7IRgOsirhP9XQnrfuoAMtITXICUAZXo3N09MeTW7ixSjaSIl+2FaDqo2yewaBvHW//wfHzSL36a9+lrX0hUjxfIJ+1nTn1HYjOFS1AbIv/5bXJTMAEDJ8afh3nlF5Z5CI8X0kF9kNjfcnNqYFudcyUPeudkDw+4gt7iyToGfot9jTBPnOT1kJ/9MtsvkZvB4LrCHcJ+sDhBI08BsdJbr739wkbmul5p2RVgA5+d7BADH3nYJ/jvjh35jGSDUtvfBArJc6Ba+zeMmyVRsgeommrXNLdtP6lmFOcB/muNu0j2pn1a4CJZhNDiUrATtmRmbykqdvEGCvB+x2OV54Y0yxJXb6SzHSblbLgzSnACGe85WLul1CpreXG14se+OnCc60uay8st+XCa75++olzxzA6IY/4p+f80272+6G0cm0QnKU6N+pF7oQiMf+wp7QXROSrFm6/0AlMyQ4dm/yIvwj/7kVPrlJ+OOrvDRTnor/jYUacHXwIKrqH58AhI8+KFS6krkopd+6BtF8gCBU5nRXwONh+llloSDALP8KP20BEiv4pTjnqvQ5E1dZesGkt4/3TAvSQG+Arre0Qtpv+o3Spr/QN7Qk24u6ybzC4qSZSduIFd7/Q/kLy48azsteRHQ7PaaOc50sB90DYUI8NdHECyhJVwpXsOh2m1Ht7SsWzXqdPZxjGpldAR7PbzmDJIJKLzIVP6Oo0OCcGsXw89eEl2FT0NN3SlgWlSZxzOSidlX3B/tICIJmp/deZzs3AbnhEnRDvV2GNrrPKI/dbfUaHqcIxqL0Aav66NOFG4Eb2GRjeQUREeOpMTJl+4iQvnVl2r9TgASzoB05fYANKvIEjGPNgtVGgyWn4HtPJuX5unhnuMwB1eRSTfI9D54ALpUPOX6TzeQJZ+yeMTlzwMFyuPhZ1QZ5+6/iR83lXNtRrUZmjlWZQlFY7ULs7SuwuXpsHTu4uje4r18J+tiGByAe+zioqj965LiLFqmxeXxkI8IuZfRBuPL6I2WIgIioQrRNr3LS5C0h75SMuTuyKJb887m7z5WkMcRbJv5oJruNEDz1aUXmAtgUWFcjAo/SNM9EE8J2op5ge1CgKvP5Dm0fAGxydyDB8DDG6TY+5TiKWKGWrQT0wjDoVBH34kiC4zyh5Iop1GDAbLAU/BIsDgYduVomINqZZms0Qr6Q+6nMdZku8smwzxW5DVIRBeLPmsdL/WF1nDaBPo2CA3KVGOHS4HNEz6fFUpvawNy5TWIO5QILyb5DFiR0nzgBUyLjJlmTqriLDmV86Du3in9lZMyP8B4="
	inactiveSecret := "sdsa"

	type args struct {
		ctx    context.Context
		data   []byte
		verify bool
	}
	tests := []struct {
		name                string
		s                   Scanner
		args                args
		want                []detectors.Result
		wantErr             bool
		wantVerificationErr bool
	}{
		{
			name: "found, verified",
			s:    Scanner{},
			args: args{
				ctx:    context.Background(),
				data:   []byte(fmt.Sprintf("You can find a fordapitoken secret %s within", secret)),
				verify: true,
			},
			want: []detectors.Result{
				{
					DetectorType: detectorspb.DetectorType_FordAPIToken,
					Verified:     true,
				},
			},
			wantErr:             false,
			wantVerificationErr: false,
		},
		{
			name: "found, unverified",
			s:    Scanner{},
			args: args{
				ctx:    context.Background(),
				data:   []byte(fmt.Sprintf("You can find a fordapitoken secret %s within but not valid", inactiveSecret)), // the secret would satisfy the regex but not pass validation
				verify: true,
			},
			want: []detectors.Result{
				{
					DetectorType: detectorspb.DetectorType_FordAPIToken,
					Verified:     false,
				},
			},
			wantErr:             false,
			wantVerificationErr: false,
		},
		{
			name: "not found",
			s:    Scanner{},
			args: args{
				ctx:    context.Background(),
				data:   []byte("You cannot find the secret within"),
				verify: true,
			},
			want:                nil,
			wantErr:             false,
			wantVerificationErr: false,
		},
		{
			name: "found, would be verified if not for timeout",
			s:    Scanner{client: common.SaneHttpClientTimeOut(1 * time.Microsecond)},
			args: args{
				ctx:    context.Background(),
				data:   []byte(fmt.Sprintf("You can find a fordapitoken secret %s within", secret)),
				verify: true,
			},
			want: []detectors.Result{
				{
					DetectorType: detectorspb.DetectorType_FordAPIToken,
					Verified:     false,
				},
			},
			wantErr:             false,
			wantVerificationErr: true,
		},
		{
			name: "found, verified but unexpected api surface",
			s:    Scanner{client: common.ConstantResponseHttpClient(404, "")},
			args: args{
				ctx:    context.Background(),
				data:   []byte(fmt.Sprintf("You can find a fordapitoken secret %s within", secret)),
				verify: true,
			},
			want: []detectors.Result{
				{
					DetectorType: detectorspb.DetectorType_FordAPIToken,
					Verified:     false,
				},
			},
			wantErr:             false,
			wantVerificationErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tt.s.FromData(tt.args.ctx, tt.args.verify, tt.args.data)
			if (err != nil) != tt.wantErr {
				t.Errorf("Fordapitoken.FromData() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			for i := range got {
				if len(got[i].Raw) == 0 {
					t.Fatalf("no raw secret present: \n %+v", got[i])
				}
				if (got[i].VerificationError != nil) != tt.wantVerificationErr {
					t.Fatalf("wantVerificationError = %v, verification error = %v", tt.wantVerificationErr, got[i].VerificationError)
				}
			}
			ignoreOpts := cmpopts.IgnoreFields(detectors.Result{}, "Raw", "VerificationError")
			if diff := cmp.Diff(got, tt.want, ignoreOpts); diff != "" {
				t.Errorf("Fordapitoken.FromData() %s diff: (-got +want)\n%s", tt.name, diff)
			}
		})
	}
}

func BenchmarkFromData(benchmark *testing.B) {
	ctx := context.Background()
	s := Scanner{}
	for name, data := range detectors.MustGetBenchmarkData() {
		benchmark.Run(name, func(b *testing.B) {
			b.ResetTimer()
			for n := 0; n < b.N; n++ {
				_, err := s.FromData(ctx, false, data)
				if err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}
