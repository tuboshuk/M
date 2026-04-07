package scanner

import (
	"testing"
)

func TestParsePorts(t *testing.T) {
	tests := []struct {
		name     string
		portSpec string
		want     []int
		wantErr  bool
	}{
		{
			name:     "single port",
			portSpec: "80",
			want:     []int{80},
			wantErr:  false,
		},
		{
			name:     "multiple ports",
			portSpec: "80,443,8080",
			want:     []int{80, 443, 8080},
			wantErr:  false,
		},
		{
			name:     "port range",
			portSpec: "1-5",
			want:     []int{1, 2, 3, 4, 5},
			wantErr:  false,
		},
		{
			name:     "mixed",
			portSpec: "80,443,8000-8005",
			want:     []int{80, 443, 8000, 8001, 8002, 8003, 8004, 8005},
			wantErr:  false,
		},
		{
			name:     "invalid port",
			portSpec: "70000",
			want:     nil,
			wantErr:  true,
		},
		{
			name:     "invalid range",
			portSpec: "100-50",
			want:     nil,
			wantErr:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParsePorts(tt.portSpec)
			if (err != nil) != tt.wantErr {
				t.Errorf("ParsePorts() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr {
				if len(got) != len(tt.want) {
					t.Errorf("ParsePorts() got = %v, want %v", got, tt.want)
					return
				}
				for i, v := range got {
					if v != tt.want[i] {
						t.Errorf("ParsePorts()[%d] = %v, want %v", i, v, tt.want[i])
					}
				}
			}
		})
	}
}
