package jcrypt

import (
	"testing"
	"time"
)

func Test_gap(t *testing.T) {
	tests := []struct {
		name string
		c1   byte
		c2   byte
		want byte
	}{
		{name: "T1", c1: byte('d'), c2: byte('b'), want: 1},
		{name: "T2", c1: byte('b'), c2: byte('2'), want: 3},
		{name: "T2", c1: byte('a'), c2: byte('z'), want: 17},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := gap(tt.c1, tt.c2); got != tt.want {
				t.Errorf("gap() = %v, want %v", got, tt.want)
			}
		})
	}
}

// TestDecrypt unit tests Decrypt function
func TestDecrypt(t *testing.T) {
	tests := []struct {
		name    string
		crypt   string
		want    string
		wantErr bool
	}{
		{
			name:  "Decrypt_1",
			crypt: "$9$SpRrMLYgaZDirexdwgUDzFn9uO1RhlKW",
			want:  "QZ1agnL21L",
		},
		{
			name:  "Decrypt_2",
			crypt: "$9$sRgGiz390OIM8UjHqQzB1RcKMWLx7Vs",
			want:  "vzEK4eM60X",
		},
		{
			name:    "Decrypt_3",
			crypt:   "$1$sRgGiz390OIM8UjHqQzB1RcKMWLx7Vs",
			want:    "",
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := Decrypt(tt.crypt)
			if (err != nil) != tt.wantErr {
				t.Errorf("Decrypt() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("Decrypt() = %v, want %v", got, tt.want)
			}
		})
	}
}

// TestEncrypt unit tests Encrypt function
func TestEncrypt(t *testing.T) {
	tests := []struct {
		name  string
		plain string
		want  string
	}{
		{
			name:  "Encrypt_1",
			plain: "QZ1agnL21L",
		},
		{
			name:  "Encrypt_2",
			plain: "vzEK4eM60X",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got, _ := Decrypt(Encrypt(tt.plain, time.Now().Unix())); got != tt.plain {
				t.Errorf("Encrypt() = %v, want %v", got, tt.want)
			}
		})
	}
}
