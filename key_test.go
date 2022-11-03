package alsdk_test

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"testing"

	alsdk "github.com/activeledger/SDK-Golang/v2"
)

func TestGenerateRSA(t *testing.T) {
	k, err := alsdk.GenerateRSA()

	if err != nil {
		t.Errorf("Errored %q", err)
	}

	if k == (alsdk.Key{}) {
		t.Errorf("Got empty key")
	}

	kType := k.GetType()

	if kType != alsdk.RSA {
		t.Errorf("Incorrect key type, got %q, wanted %q", kType, alsdk.RSA)
	}
}

func TestRSADifferent(t *testing.T) {
	keys := []alsdk.KeyHandler{}

	for i := 0; i < 10; i++ {
		k, err := alsdk.GenerateRSA()
		if err != nil {
			t.Errorf("Errored %q", err)
		}

		keys = append(keys, k)
	}

	dupesGen := 0

	for kin, v := range keys {
		curKey := v.GetPrivatePEM()

		for k, v := range keys {
			if k == kin {
				continue
			}

			if v.GetPrivatePEM() == curKey {
				dupesGen++
			}
		}
	}

	if dupesGen > 0 {
		t.Errorf("Expected no duplicate keys but got %q duplicates", dupesGen)
	}
}

func BenchmarkRSAGen(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_, err := alsdk.GenerateRSA()
		if err != nil {
			b.Errorf("Errored %q", err)
		}
	}
}

func TestRSAGetPrivatePem(t *testing.T) {
	k, err := alsdk.GenerateRSA()

	if err != nil {
		t.Errorf("Errored %q", err)
	}

	pem := k.GetPrivatePEM()

	if pem == "" {
		t.Error("Private pem is blank")
	}
}

func TestRSAGetPublicPem(t *testing.T) {
	k, err := alsdk.GenerateRSA()

	if err != nil {
		t.Errorf("Errored %q", err)
	}

	pem := k.GetPublicPEM()

	if pem == "" {
		t.Error("Public pem is blank")
	}
}

func TestRSASetKeyViaPem(t *testing.T) {
	pem := "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA5lIJZqwomgsKUW3LJhtliA9h4PcCYs60EXssCUfN4oKv11Xj\nctH/7RGI7Yc84EPfY+KfJhiitEWJkJSNofEmOLZUq6PDW9oocM/rJaFG6P2PmMGB\nbqJjRdSfLSWe5A013F5cgkYDbWxOnK9tr9OxpZzyetqqt/Q07DD/i3hnkpN1lifh\nKlh8cq0Q0vuZaYe22pr6vGkhj4e5PUrT++VB+OSqLzq1jtQHkVQicGdIgJow39rp\nlXsBh813acLhATDeElN69MFA0Ji9h84PVyqeY2iXbE6TdI85XAiFmCSV/kjDlUs3\nZDZByOCF7S2zxlruEsiJK6ivvTEEA6FuIkl13QIDAQABAoIBAHL8fAMNakvVvTYA\nGY8R2HPAMj6NM1y/E7kyhD6x4YD3e/CGycIWQ65ItdLYVLUmTY3ho1DytbBIkzBi\naf9ylIF1zfnPDYZ6+PuxYhVsWimSBbHe0c65NdS0HS/9+0Chs8UsOwUzDR0BGJIz\nJxDEIImtPIXHS7oBKrbMk5g+6X6MOz+DV3AY+HGYJoLODqgvsXF2GRzZvFiIWC99\nGKR3pNuYUgxmWpXUseyq5HvWA4vt3jQeSf/P2s05o3v8F8ofDs1Xm4esKPCaHfxB\nH9AOqJZoJN3wFDMgXLkv4qMk7XhOj13Rz4qqQNsxuP0KIcPfsAyfOT+2GWYP+SM5\nUmZyBQUCgYEA/4PyM/e9TdJu0yD3mCrCzrRqUhgSgoQEBY5y9JXfaTnMfzG0qCle\nKE0ASbo/cG4sLhBrIwlIcGEgERGMr4gN5pEZ/qv+3663DklFH/Wo1e4MFiT/I0n6\nifebXs3DYo72GMc4Ju+ttDxBS1iGK571ceh5cAqgDXMZSZMC4meWXSMCgYEA5sHb\nvN2530q+UoQTSCtuze3YAY56jmib9YhiljzjhvVOkIbz23X5ojI5SD1knpKIOJQM\nDiNmveWln/METNMtvchT4qVidTAI/R2aG9In9sj3C+Q1nADzoAlzG2v37eg85R+j\n7zDZDVKj3/5zyrzfzSSwZqLVoIsZ3twqzCvVkP8CgYAQHxweCUiJa3iQm6jjkfce\noaV/roMkdv3l99nq8rXY5suvTsyOO6X0Nv+Ip1avWlQxR9nqqQBIDui+CvRsctIl\ntQwF1IZNSLHGFftli9NuRAnBL+5lJJrJL7U+4w6r3kdKwu8ZDdBQ6ehYv6ofgHUO\nDdPzrMfycUusJ7lr3YtQLwKBgBgUjNC1tqrViuzjeXujhKmas1reOm3X/sZtmBQj\ngH7Z5HvyiUoSkp1Zbl7agUCG/A4jbOqgyRzx9Qmu+3jk5LYUTKSvK4odHCMFzsou\ncRswt48XHn0MIGBH/CoVZ0b9YDVsytewGkZopE9Ap2a1tQkcVggv3+kj+uwlv5WU\n0XGTAoGBAOpvY0B9gkGfYU8NSe/5LE+WNE/pcusZcQEEpu0vxJZCmLHJEMYl8+h/\nm2UnNLN8Wc/cXZqxTuinw4KqIcR8TJamcq1j/zE4FpUN2XvbwebZPwmW0q19fSDA\nZuH/QVQQOQR754iaMXXqCaCZEpZIXzWzn8tfSjynKNsEXk0Uiy5z\n-----END RSA PRIVATE KEY-----\n"

	newK, err := alsdk.SetKey(pem, alsdk.RSA)

	if err != nil {
		t.Errorf("Error on setting %q", err)
	}

	prvPem := newK.GetPrivatePEM()

	if prvPem == "" {
		t.Error("Private PEM is blank")
	}

	if pem != prvPem {
		t.Errorf("New key doesn't match old key")
	}

}

func TestRSAVerifyUsingPem(t *testing.T) {

	testData := "activeledger test data"

	k, err := alsdk.GenerateRSA()
	if err != nil {
		t.Errorf("Errored %q", err)
	}

	sig, hash, err := k.Sign([]byte(testData))
	if err != nil {
		t.Errorf("Error signing test data %q", err)
	}

	pubPem := k.GetPublicPEM()

	verified, err := alsdk.VerifyUsingPem(sig, hash, pubPem, alsdk.RSA)
	if err != nil {
		t.Errorf("Error verifying usin pem %q", err)
	}

	if !verified {
		t.Error("Signature verification came back false")
	}

	// b64Sig := "kUIx13/A46xx7Bv2y56mos8Bge6bHquu4Yf3fFreef/U7Zm8VKQQ/rZzKpnH7g4h8h77/Wx5G8dhxFm1BZSgu4wYOeSJNBqBNUR3rS6CZNDOXSaWj7Vo9AZm8rTrge0e4PMcNdFvKGCTOmCpqkRgUhRG146447NhUixMKqI5RdpUGI61BpS7P4s0/LTwtwgTmLg1Bw1W2LZMCcqlaRs+Rr/zfx8h5BM/3j9PLKCmU0eb8G5Gcc4hmpEbGBwuhAGnE5QEHBSRuGOMHS4hBJ6MD8uNcDMetViDlkNRAOOni+LZzImMQGHkIN5IXqKAzzt6RKR67OKo2mVILVSnlhygsg=="
	//prvPem := "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA5lIJZqwomgsKUW3LJhtliA9h4PcCYs60EXssCUfN4oKv11Xj\nctH/7RGI7Yc84EPfY+KfJhiitEWJkJSNofEmOLZUq6PDW9oocM/rJaFG6P2PmMGB\nbqJjRdSfLSWe5A013F5cgkYDbWxOnK9tr9OxpZzyetqqt/Q07DD/i3hnkpN1lifh\nKlh8cq0Q0vuZaYe22pr6vGkhj4e5PUrT++VB+OSqLzq1jtQHkVQicGdIgJow39rp\nlXsBh813acLhATDeElN69MFA0Ji9h84PVyqeY2iXbE6TdI85XAiFmCSV/kjDlUs3\nZDZByOCF7S2zxlruEsiJK6ivvTEEA6FuIkl13QIDAQABAoIBAHL8fAMNakvVvTYA\nGY8R2HPAMj6NM1y/E7kyhD6x4YD3e/CGycIWQ65ItdLYVLUmTY3ho1DytbBIkzBi\naf9ylIF1zfnPDYZ6+PuxYhVsWimSBbHe0c65NdS0HS/9+0Chs8UsOwUzDR0BGJIz\nJxDEIImtPIXHS7oBKrbMk5g+6X6MOz+DV3AY+HGYJoLODqgvsXF2GRzZvFiIWC99\nGKR3pNuYUgxmWpXUseyq5HvWA4vt3jQeSf/P2s05o3v8F8ofDs1Xm4esKPCaHfxB\nH9AOqJZoJN3wFDMgXLkv4qMk7XhOj13Rz4qqQNsxuP0KIcPfsAyfOT+2GWYP+SM5\nUmZyBQUCgYEA/4PyM/e9TdJu0yD3mCrCzrRqUhgSgoQEBY5y9JXfaTnMfzG0qCle\nKE0ASbo/cG4sLhBrIwlIcGEgERGMr4gN5pEZ/qv+3663DklFH/Wo1e4MFiT/I0n6\nifebXs3DYo72GMc4Ju+ttDxBS1iGK571ceh5cAqgDXMZSZMC4meWXSMCgYEA5sHb\nvN2530q+UoQTSCtuze3YAY56jmib9YhiljzjhvVOkIbz23X5ojI5SD1knpKIOJQM\nDiNmveWln/METNMtvchT4qVidTAI/R2aG9In9sj3C+Q1nADzoAlzG2v37eg85R+j\n7zDZDVKj3/5zyrzfzSSwZqLVoIsZ3twqzCvVkP8CgYAQHxweCUiJa3iQm6jjkfce\noaV/roMkdv3l99nq8rXY5suvTsyOO6X0Nv+Ip1avWlQxR9nqqQBIDui+CvRsctIl\ntQwF1IZNSLHGFftli9NuRAnBL+5lJJrJL7U+4w6r3kdKwu8ZDdBQ6ehYv6ofgHUO\nDdPzrMfycUusJ7lr3YtQLwKBgBgUjNC1tqrViuzjeXujhKmas1reOm3X/sZtmBQj\ngH7Z5HvyiUoSkp1Zbl7agUCG/A4jbOqgyRzx9Qmu+3jk5LYUTKSvK4odHCMFzsou\ncRswt48XHn0MIGBH/CoVZ0b9YDVsytewGkZopE9Ap2a1tQkcVggv3+kj+uwlv5WU\n0XGTAoGBAOpvY0B9gkGfYU8NSe/5LE+WNE/pcusZcQEEpu0vxJZCmLHJEMYl8+h/\nm2UnNLN8Wc/cXZqxTuinw4KqIcR8TJamcq1j/zE4FpUN2XvbwebZPwmW0q19fSDA\nZuH/QVQQOQR754iaMXXqCaCZEpZIXzWzn8tfSjynKNsEXk0Uiy5z\n-----END RSA PRIVATE KEY-----\n"
	//pubPem := "-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA5lIJZqwomgsKUW3LJhtl\niA9h4PcCYs60EXssCUfN4oKv11XjctH/7RGI7Yc84EPfY+KfJhiitEWJkJSNofEm\nOLZUq6PDW9oocM/rJaFG6P2PmMGBbqJjRdSfLSWe5A013F5cgkYDbWxOnK9tr9Ox\npZzyetqqt/Q07DD/i3hnkpN1lifhKlh8cq0Q0vuZaYe22pr6vGkhj4e5PUrT++VB\n+OSqLzq1jtQHkVQicGdIgJow39rplXsBh813acLhATDeElN69MFA0Ji9h84PVyqe\nY2iXbE6TdI85XAiFmCSV/kjDlUs3ZDZByOCF7S2zxlruEsiJK6ivvTEEA6FuIkl1\n3QIDAQAB\n-----END PUBLIC KEY-----\n"
	// sigExpected, err := base64.StdEncoding.DecodeString(b64Sig)
	// if err != nil {
	// 	t.Error("Error decoding expected signature")
	// }

	//	h := sha256.New()
	//h.Write([]byte(testData))
	// digestExpected := h.Sum(nil)

	/*k, err := alsdk.SetKey(pem, alsdk.RSA)
	if err != nil {
		t.Errorf("Error on setting %q", err)
	}

	log.Println("k.GetPublicPEM()")
	log.Println(k.GetPublicPEM())
	*/
	/*sig, digest, err := k.Sign([]byte(testData))
	if err != nil {
		t.Errorf("Error signing %q", err)
		return
	}

	if string(digestExpected) != string(digest) {
		t.Errorf("Hashes don't match\nGOT: %q\nWANTED: %q", string(digest), string(digestExpected))
	}

	if !bytes.Equal(sig, sigExpected) {
		t.Errorf("Signatures don't match\nGOT: %q\nWANTED: %q", sig, sigExpected)
	}*/
}
func TestRSASignAndVerify(t *testing.T) {
	// Verify is run as part of the sigining process, if signing suceeds verify is working

	testData := "activeledger test data"
	b64Sig := "kUIx13/A46xx7Bv2y56mos8Bge6bHquu4Yf3fFreef/U7Zm8VKQQ/rZzKpnH7g4h8h77/Wx5G8dhxFm1BZSgu4wYOeSJNBqBNUR3rS6CZNDOXSaWj7Vo9AZm8rTrge0e4PMcNdFvKGCTOmCpqkRgUhRG146447NhUixMKqI5RdpUGI61BpS7P4s0/LTwtwgTmLg1Bw1W2LZMCcqlaRs+Rr/zfx8h5BM/3j9PLKCmU0eb8G5Gcc4hmpEbGBwuhAGnE5QEHBSRuGOMHS4hBJ6MD8uNcDMetViDlkNRAOOni+LZzImMQGHkIN5IXqKAzzt6RKR67OKo2mVILVSnlhygsg=="
	pem := "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA5lIJZqwomgsKUW3LJhtliA9h4PcCYs60EXssCUfN4oKv11Xj\nctH/7RGI7Yc84EPfY+KfJhiitEWJkJSNofEmOLZUq6PDW9oocM/rJaFG6P2PmMGB\nbqJjRdSfLSWe5A013F5cgkYDbWxOnK9tr9OxpZzyetqqt/Q07DD/i3hnkpN1lifh\nKlh8cq0Q0vuZaYe22pr6vGkhj4e5PUrT++VB+OSqLzq1jtQHkVQicGdIgJow39rp\nlXsBh813acLhATDeElN69MFA0Ji9h84PVyqeY2iXbE6TdI85XAiFmCSV/kjDlUs3\nZDZByOCF7S2zxlruEsiJK6ivvTEEA6FuIkl13QIDAQABAoIBAHL8fAMNakvVvTYA\nGY8R2HPAMj6NM1y/E7kyhD6x4YD3e/CGycIWQ65ItdLYVLUmTY3ho1DytbBIkzBi\naf9ylIF1zfnPDYZ6+PuxYhVsWimSBbHe0c65NdS0HS/9+0Chs8UsOwUzDR0BGJIz\nJxDEIImtPIXHS7oBKrbMk5g+6X6MOz+DV3AY+HGYJoLODqgvsXF2GRzZvFiIWC99\nGKR3pNuYUgxmWpXUseyq5HvWA4vt3jQeSf/P2s05o3v8F8ofDs1Xm4esKPCaHfxB\nH9AOqJZoJN3wFDMgXLkv4qMk7XhOj13Rz4qqQNsxuP0KIcPfsAyfOT+2GWYP+SM5\nUmZyBQUCgYEA/4PyM/e9TdJu0yD3mCrCzrRqUhgSgoQEBY5y9JXfaTnMfzG0qCle\nKE0ASbo/cG4sLhBrIwlIcGEgERGMr4gN5pEZ/qv+3663DklFH/Wo1e4MFiT/I0n6\nifebXs3DYo72GMc4Ju+ttDxBS1iGK571ceh5cAqgDXMZSZMC4meWXSMCgYEA5sHb\nvN2530q+UoQTSCtuze3YAY56jmib9YhiljzjhvVOkIbz23X5ojI5SD1knpKIOJQM\nDiNmveWln/METNMtvchT4qVidTAI/R2aG9In9sj3C+Q1nADzoAlzG2v37eg85R+j\n7zDZDVKj3/5zyrzfzSSwZqLVoIsZ3twqzCvVkP8CgYAQHxweCUiJa3iQm6jjkfce\noaV/roMkdv3l99nq8rXY5suvTsyOO6X0Nv+Ip1avWlQxR9nqqQBIDui+CvRsctIl\ntQwF1IZNSLHGFftli9NuRAnBL+5lJJrJL7U+4w6r3kdKwu8ZDdBQ6ehYv6ofgHUO\nDdPzrMfycUusJ7lr3YtQLwKBgBgUjNC1tqrViuzjeXujhKmas1reOm3X/sZtmBQj\ngH7Z5HvyiUoSkp1Zbl7agUCG/A4jbOqgyRzx9Qmu+3jk5LYUTKSvK4odHCMFzsou\ncRswt48XHn0MIGBH/CoVZ0b9YDVsytewGkZopE9Ap2a1tQkcVggv3+kj+uwlv5WU\n0XGTAoGBAOpvY0B9gkGfYU8NSe/5LE+WNE/pcusZcQEEpu0vxJZCmLHJEMYl8+h/\nm2UnNLN8Wc/cXZqxTuinw4KqIcR8TJamcq1j/zE4FpUN2XvbwebZPwmW0q19fSDA\nZuH/QVQQOQR754iaMXXqCaCZEpZIXzWzn8tfSjynKNsEXk0Uiy5z\n-----END RSA PRIVATE KEY-----\n"
	sigExpected, err := base64.StdEncoding.DecodeString(b64Sig)
	if err != nil {
		t.Error("Error decoding expected signature")
	}

	h := sha256.New()
	h.Write([]byte(testData))
	digestExpected := h.Sum(nil)

	k, err := alsdk.SetKey(pem, alsdk.RSA)
	if err != nil {
		t.Errorf("Error on setting %q", err)
	}

	sig, digest, err := k.Sign([]byte(testData))
	if err != nil {
		t.Errorf("Error signing %q", err)
		return
	}

	if string(digestExpected) != string(digest) {
		t.Errorf("Hashes don't match\nGOT: %q\nWANTED: %q", string(digest), string(digestExpected))
	}

	if !bytes.Equal(sig, sigExpected) {
		t.Errorf("Signatures don't match\nGOT: %q\nWANTED: %q", sig, sigExpected)
	}
}

func TestGenerateEcc(t *testing.T) {
	k, err := alsdk.GenerateElliptic()
	if err != nil {
		t.Errorf("Generate errored %q", err)
		return
	}

	if k == (alsdk.Key{}) {
		t.Errorf("Got empty key")
		return
	}

	kType := k.GetType()

	if kType != alsdk.Elliptic {
		t.Errorf("Got wrong key type")
		return
	}
}

func TestECCDifferent(t *testing.T) {

	keys := []alsdk.KeyHandler{}

	for i := 0; i < 10; i++ {
		k, err := alsdk.GenerateElliptic()
		if err != nil {
			t.Errorf("Errored %q", err)
		}

		keys = append(keys, k)
	}

	dupesGen := 0

	for kin, v := range keys {
		curKey := v.GetPrivatePEM()

		for k, v := range keys {
			if k == kin {
				continue
			}

			if v.GetPrivatePEM() == curKey {
				dupesGen++
			}
		}
	}

	if dupesGen > 0 {
		t.Errorf("Expected no duplicate keys but got %q duplicates", dupesGen)
	}
}

func BenchmarkECCGen(b *testing.B) {

	for i := 0; i < b.N; i++ {
		_, err := alsdk.GenerateElliptic()
		if err != nil {
			b.Errorf("Errored %q", err)
		}
	}
}

func TestECCGetPrivatePem(t *testing.T) {

	k, err := alsdk.GenerateElliptic()

	if err != nil {
		t.Errorf("Errored %q", err)
	}

	pem := k.GetPrivatePEM()

	if pem == "" {
		t.Error("Private pem is blank")
	}
}

func TestECCGetPublicPem(t *testing.T) {

	k, err := alsdk.GenerateElliptic()

	if err != nil {
		t.Errorf("Errored %q", err)
	}

	pem := k.GetPublicPEM()

	if pem == "" {
		t.Error("Public pem is blank")
	}
}

func TestECCSetKeyViaPem(t *testing.T) {

	pem := "-----BEGIN EC PRIVATE KEY-----\nMHQCAQEEIGy9NY1t/9qj/JUSgWOEJKGBkEEsbQrbJzmx1TlJRsaAoAcGBSuBBAAK\noUQDQgAEHOTxSNzRBgFpOr2owGOQQ5neVXiXorfNEJBcds+3s1V6qi3R3EHa0+7A\nqgWYNF4HUnjirjQm+DMwq/7hPZvaUw==\n-----END EC PRIVATE KEY-----\n"

	newK, err := alsdk.SetKey(pem, alsdk.Elliptic)

	if err != nil {
		t.Errorf("Error on setting %q", err)
	}

	prvPem := newK.GetPrivatePEM()

	if prvPem == "" {
		t.Error("Private PEM is blank")
		return
	}

	if pem != prvPem {
		t.Errorf("New key doesn't match old key\nGOT: %q\nWANTED: %q", prvPem, pem)
	}

}

func TestECCSignAndVerify(t *testing.T) {

	// Verify is run as part of the sigining process, if signing suceeds verify is working
	/*
		testData := "activeledger test data"
		b64Sig := "kUIx13/A46xx7Bv2y56mos8Bge6bHquu4Yf3fFreef/U7Zm8VKQQ/rZzKpnH7g4h8h77/Wx5G8dhxFm1BZSgu4wYOeSJNBqBNUR3rS6CZNDOXSaWj7Vo9AZm8rTrge0e4PMcNdFvKGCTOmCpqkRgUhRG146447NhUixMKqI5RdpUGI61BpS7P4s0/LTwtwgTmLg1Bw1W2LZMCcqlaRs+Rr/zfx8h5BM/3j9PLKCmU0eb8G5Gcc4hmpEbGBwuhAGnE5QEHBSRuGOMHS4hBJ6MD8uNcDMetViDlkNRAOOni+LZzImMQGHkIN5IXqKAzzt6RKR67OKo2mVILVSnlhygsg=="
		pem := "-----BEGIN EC PRIVATE KEY-----\nMHQCAQEEIGy9NY1t/9qj/JUSgWOEJKGBkEEsbQrbJzmx1TlJRsaAoAcGBSuBBAAK\noUQDQgAEHOTxSNzRBgFpOr2owGOQQ5neVXiXorfNEJBcds+3s1V6qi3R3EHa0+7A\nqgWYNF4HUnjirjQm+DMwq/7hPZvaUw==\n-----END EC PRIVATE KEY-----"
		sigExpected, err := base64.StdEncoding.DecodeString(b64Sig)
		if err != nil {
			t.Error("Error decoding expected signature")
		}

		h := sha256.New()
		h.Write([]byte(testData))
		digestExpected := h.Sum(nil)

		k, err := alsdk.SetKey(pem, alsdk.RSA)
		if err != nil {
			t.Errorf("Error on setting %q", err)
		}

		sig, digest, err := k.Sign([]byte(testData))
		if err != nil {
			t.Errorf("Error signing %q", err)
			return
		}

		if string(digestExpected) != string(digest) {
			t.Errorf("Hashes don't match\nGOT: %q\nWANTED: %q", string(digest), string(digestExpected))
		}

		if !bytes.Equal(sig, sigExpected) {
			t.Errorf("Signatures don't match\nGOT: %q\nWANTED: %q", sig, sigExpected)
		}
	*/
}

func TestECCVerifyUsingPem(t *testing.T) {

	testData := "activeledger test data"

	k, err := alsdk.GenerateElliptic()
	if err != nil {
		t.Errorf("Errored %q", err)
		return
	}

	sig, hash, err := k.Sign([]byte(testData))
	if err != nil {
		t.Errorf("Error signing test data %q", err)
		return
	}

	pubPem := k.GetPublicPEM()

	verified, err := alsdk.VerifyUsingPem(sig, hash, pubPem, alsdk.Elliptic)
	if err != nil {
		t.Errorf("Error verifying using pem %q", err)
		return
	}

	if !verified {
		t.Error("Signature verification came back false")
	}
}
