import {
  SigningKeyPair,
  SigningPrivateKey,
  SigningPublicKey,
  SIGNING_ALGO_RSA,
  SIGNING_ALGO_ED25519
} from '.';

const msg = 'coucou, tu veux voir mon message ?';
const password = 'Some super secure password';

const tests = {
  [SIGNING_ALGO_RSA.name]: {
    pub: `-----BEGIN RSA PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAwbDQMRGdKagiaphXwA3c
dtLsce+JAhVSN/EAtLT0BnmjyIi+M+f4Akc7Fi4a1FAmpfN6GmCjjZlnKxdM+/p1
5vrM416uzKehuN1WFaWTcbwQKj4PeHugHSqrbmZ/l0Qi2YaEqXn1KpCcwX83t+xK
IW+8H/yRbrTcHhJs6YO+xC9A/0bAQLgZwycr1ngE2hQedyKdUhAZSB8jx9CKNBVz
y2Ut00eEilspGnpDbmy2XvYrTZ+UtUTxy2yvh8/X/QaMDJxK4js4jmWuAHYapx8O
7pFqNPFZMibFUcHb3HMGM/UD3grZNK18rm4FikNZ/9ul1O7cl0/Ko9AUOwVpDEGj
0QIDAQAB
-----END RSA PUBLIC KEY-----`,
    priv: `-----BEGIN RSA PRIVATE KEY-----
MIIEvwIBADANBgkqhkiG9w0BAQEFAASCBKkwggSlAgEAAoIBAQDBsNAxEZ0pqCJq
mFfADdx20uxx74kCFVI38QC0tPQGeaPIiL4z5/gCRzsWLhrUUCal83oaYKONmWcr
F0z7+nXm+szjXq7Mp6G43VYVpZNxvBAqPg94e6AdKqtuZn+XRCLZhoSpefUqkJzB
fze37Eohb7wf/JFutNweEmzpg77EL0D/RsBAuBnDJyvWeATaFB53Ip1SEBlIHyPH
0Io0FXPLZS3TR4SKWykaekNubLZe9itNn5S1RPHLbK+Hz9f9BowMnEriOziOZa4A
dhqnHw7ukWo08VkyJsVRwdvccwYz9QPeCtk0rXyubgWKQ1n/26XU7tyXT8qj0BQ7
BWkMQaPRAgMBAAECggEBAJ85bfxYgX1EJX7BW6ma+3iG7i6/fj7DLkKkkTL8anqE
Nnrcxpc/A2dEDTOvlQiiFxNnMyJJ/UmjKOeIkRW3kILf+9yR8lp1F4I0GddTtQDT
W+qN+APQhRBVCnaINi0wqwFtDtOPWVazaNm8bh55VXtlMh6NbzS14xmphfT1A7ab
vn5be3L5FzRQEIhai6Uqc2SY3iAfc+honElnYwL0ND7hoU+wJgs8Btvb2Um3fMA5
4WDM0tSrLCnGMzCjn9PuROQav0F8nEqq3/zAEB1UBCjNitUnjGUDNGsWM4/GtWDs
R12H0Vg9Pb4nfnPPfD8PWUuTNhD/RTzeP73BS1SaJcECgYEA8oI8DtZFEsNXfeq7
qw079+FAWjB14HXwyhZsl2Qd8jlahpRfUH0HUGsHBT4bydYtfvyJ2yjza/fhZdZC
k1wTPGp84y5WAvGqkYAsPDbM3Fez7O1PQ4ZJw7JYW/mjo2r+3KYKLixshVaWDcAC
F5J10cp6R8DEMejBs9VKSwhJDFkCgYEAzHdSH0J3MtKY36B2iwBFn5fTeKyFhLsQ
7dVG8R+22Sd17rNtUeG0yn4RFK36GRLgPl4kRYlrfLBiXbVqdtBfUaffvoteTv6k
++86KQjSo7veUCsRkT9HSB4+G7vQ59v3IqwYpCbFe5iwgufCPsVJskBnfMAhNqni
xFYB2yKghDkCgYEA45isyvP34bMpcsiRluiVxn9FyR9AEgg+kztWcQMKQ+Hl/vZT
OhQNgEDiVt5CcDwteMeEjgYx5ru+c7gRxYEdoI8EZKaBHMQ4Y9PaMCzyOT2qZIsX
3/SxWBQSb0esd1uck/LVDR6uPrnTnFX+4KaZIuqXtq3ItFqRKLjdv+unuwkCgYBk
wK9g4/mku43FNGb1m86zE7eLEUhB3YQ8DgqFKuGJJB7C3vuRi6zw0ypLjGdfD6Qc
V3t8IHks2iW+k3TA03EE5bolRLvWJTjbREjei5BwSlUEIBTqA8p2SSDFvcj1V7jy
Bueli81oWBcyik13bPQhuAbGvE4hh5lMsiz79JYwUQKBgQDTwiOYbrrB/zNS6VdP
n8Q0GxDbvDQRd0JjCp7aw4cX9g+gvsX9CETocAPQXpBD+f/6+Y5pvJN8BoZKdSqF
HDIuKefy+M1zAbIbFLmWBNQZCUlq57jOZ/1BG3Y/qO3FD869ltwA/lYjUYv2pfGY
RLJR2hWagXEb4vUCyY/Hhplv5A==
-----END RSA PRIVATE KEY-----`,
    encPriv: `-----BEGIN ENCRYPTED PRIVATE KEY-----
MIIFHzBJBgkqhkiG9w0BBQ0wPDAbBgkqhkiG9w0BBQwwDgQIVo5htt7OGUACAggA
MB0GCWCGSAFlAwQBKgQQx7KMHS5Y/S3u+DNgmHF86ASCBNDRodrII14WzjZaVLSf
KNdUTl3c9qPeahaWH1/yHeUzQHc5muOxgbWe9jqez+XYn4R3yZF+rusAT+pvT+/A
Xc93beJCOBtLASgGENLk1M0voiJ9HH1gIA2H3o0GzrukllQpKRIYXbxlDvkeyl8g
05252QJQXL7KWd245ZEqByXXEOjYikQopeZH69vN1l/FDKPeGilpFbXqclmBBSXt
ebDbqSW2ztZkxST9qd3JMgURbewXb4Ei59+m9tIjO0khAiwk41hmskhek4RzF+w3
tcE12PkFrpuMigal07K7+MI7+nLVPyXyeVFqEOGM3VpoTLVbxAlpXWerLgwLFCi7
csEAxWBP3lKRWw63x8sOE2F1qfjN7BVLnWT8KwBOIH/wm2JV2pcTPPCf+r3yMoKh
ezKz7d+cuTVbb8KRidKvovhBLM10GMZoBJ9LopLystQ91yhNOrWD+5PGB/h2ZQC5
ia4KFaOsycb4GKXuc30cPWZf7+9JtpJrMpj9hRljEd5RCxfJFeZxia0D+lxm9Npc
kzpMOx3ZTpEmxYK6wzBEiUlFkkLLwORHW+l9JougBhp+qYCwAXQp14dnIb9MbslF
v2WrLq8nN5+uvJCxvwnYkE0czrfgUk8725RmO9vH0qBFrL/ST8fg8WP3hU1LF8Om
dX+nYmbJ+/HpZ4nT8xUShzdAlWskrivBXMrL+jIk1TXp/tEkIR2fPuOHhmHmO4Vd
JlJffSZHGM32krORTOLOZdB6jr7LNlahyYso5/fac43JgTGDdJE6gXCMWKCNoKds
gGxj1+/oRUMWZIle/mtkmy9LWkwU7oqZjHFqrPrDXY6BR142klin4PHUHcythKee
5hIuVlJjGe66r50lnuYluiY6Z6of6wezBCAEQIr2juyL+9ql6POOetatr4nbpojM
88huxsLKmgUgMlblyWVHDraB0SMvQnBDgebBIk1RfL45sCBFimOHJr8WZ1lrkqCE
BGS9yDI6KCk/tubfPYsmbKeElSAVctOZ4Qgt7Oc3HfxhmapM1ft6GYm+3rB1G+YX
V+FWoXJnqiHXopOnUp4zIcdeIb86FFdFj6U/qK4rFacUXUaUosbjE0mJxfJ7YYam
WINxYV5QPmMHsRkS/SedxKxiZXSZFjMNGRvtUVrmFLsFi+aGgHZDpOLCqN3AOXH4
f4l5XVRWtioDEYofG+QzwKqk0dK//c7nw7sGXlH5hVa1FyPByX5kt6cp8q5osfMb
SdhJ867BbuuCJBckc1u5rPbNbOCRlRaNxFjH1RZ0tdPyPvrSzwHOzcQcTtqB6ow+
nUfRzST52EDYeVsFM3onI8DUWg1UQXWrx3wFJNQqXEMjY09pIp5sntI5Hp1K8Xo/
o+wFa66ozmT0dC30BnPSxfdRGTskom2bJD5Ah6NI1I73J/WGOwhBvtEZTV5YNC4g
gAkqf7dXDmp+DdSpMvsDwwzmAEXxdAMXhv9JVKE8OXEUVdJlZEn3Q9PHckBZ758B
EFd8JzzxXq61eF8i0r71NsBE/lZzK7llad+T79KLAQ9nMi4dSzVJK8fLwS7Ioj6v
qJEhiu4DRaAh5ztd8x4jS/CgjuVU/3es5UKzDStEiut7e0GoeqE773d1f145FcdE
XVISCHgIRlxhmvpVXE+AxoI/Pw==
-----END ENCRYPTED PRIVATE KEY-----`,
    sig: `-----BEGIN MESSAGE-----
oWkBzn6ihAFHCXOShuuD/28G02fuN+F1btBQgXG6MR8FEW0ZZvFJ/K6xysmkjE4Y
IsL6gL62xmgTF+MwJKOPgVmm9Or4LVwnvh19bTgDFqy7XxKhvoqOGICqrOL3Buxx
wM3nJsql7w946a3rGIm4DcA2UQ70p9oXJm6VizFcNt+6WBg4rw4F5jmAa7x/grTd
bDMf6fu1d+gj/gHRCAeKAxRC/0t+DeCk6lqwA9bbwclNmpCG4Iw76HNuGaDPORNJ
htM2zU9Zi8riLX5EFIAx8P2aB7SlUWjDkn2KuJ+BMSjpsvePyp9Hkz+c40y4j5hX
TkCTOaREKAXdW6GO2sWs0A==
-----END MESSAGE-----`
  },
  [SIGNING_ALGO_ED25519.name]: {
    pub: `-----BEGIN ED25519 PUBLIC KEY-----
MCwwBwYDK2VwBQADIQAeyiwPz5Io5oOQYsccTDDpzYRBkJt9D2Vo3RAG/EgAlQ==
-----END ED25519 PUBLIC KEY-----`,
    priv: `-----BEGIN ED25519 PRIVATE KEY-----
MFACAQAwBwYDK2VwBQAEQgRA4cAiLhzwwoR4jjyYrrBw0tRaYPR3kxtkHU2c6Jhg
4EgeyiwPz5Io5oOQYsccTDDpzYRBkJt9D2Vo3RAG/EgAlQ==
-----END ED25519 PRIVATE KEY-----`,
    encPriv: `-----BEGIN ENCRYPTED PRIVATE KEY-----
MIGtMEkGCSqGSIb3DQEFDTA8MBsGCSqGSIb3DQEFDDAOBAiXAdBN0dbCmwICCAAw
HQYJYIZIAWUDBAEqBBAiZii0e84FaKFc54vYnQLeBGAC4T+qHGqIjX2XLsYaSTtN
/ZRR0PotI5fkycxA/PtW+WZ36Yt45YtL/tPem3MfXYd/gApghrtpsMfvWir1Gd05
q2b77avGAlgk2h1je5mikzAZOykMujukmfayDxi846M=
-----END ENCRYPTED PRIVATE KEY-----`,
    sig: `-----BEGIN MESSAGE-----
3Y3grd1YBhBkScl0MdBHeiqxyh2zQBXZJbRzP2wI4tXclk025nqnatxmG2l9C13g
rQciFPa8bbWWPNebFpgiAA==
-----END MESSAGE-----`
  }
};

describe('Signatures', () => {
  Object.entries(tests).forEach(([k, v]) => {
    describe(k, () => {
      describe('Key Pair', () => {
        it('should generate', () => {
          const kp = new SigningKeyPair({ algo: k });
          expect(kp.private).not.toBeFalsy();
          expect(kp.public).not.toBeFalsy();
        });

        it('should load private key', () => {
          const kp = new SigningKeyPair({ pemPrivateKey: v.priv });
          expectPEMStringsEqual(kp.private.export(), v.priv);
          expectPEMStringsEqual(kp.public.export(), v.pub);
        });

        it('should load encrypted key', () => {
          const kp = new SigningKeyPair({
            pemPrivateKey: v.encPriv,
            password
          });
          expectPEMStringsEqual(kp.private.export(), v.priv);
          expectPEMStringsEqual(kp.public.export(), v.pub);
        });

        it('should encrypt and export', () => {
          const kp = new SigningKeyPair({ algo: k });
          const enc = kp.private.export(password);

          const kp2 = new SigningKeyPair({ pemPrivateKey: enc, password });
          expectPEMStringsEqual(kp.private.export(), kp2.private.export());
        });
      });

      describe('Private Key', () => {
        it('should load and export', () => {
          const key = new SigningPrivateKey({ pemPrivateKey: v.priv });
          expectPEMStringsEqual(key.export(), v.priv);
        });

        it('should load encrypted key', () => {
          const key = new SigningPrivateKey({
            pemPrivateKey: v.encPriv,
            password
          });
          expectPEMStringsEqual(key.export(), v.priv);
        });

        it('should encrypt and export', () => {
          const key = new SigningPrivateKey({ algo: k });
          const enc = key.export(password);

          const key2 = new SigningPrivateKey({ pemPrivateKey: enc, password });
          expectPEMStringsEqual(key.export(), key2.export());
        });

        it('should sign message', () => {
          const key = new SigningPrivateKey({ pemPrivateKey: v.priv });
          const sig = key.sign(msg);
          expectPEMStringsEqual(sig, v.sig);
        });
      });
      describe('Key Pair', () => {
        it('should generate', () => {
          const kp = new SigningKeyPair({ algo: k });
          expect(kp.private).not.toBeFalsy();
          expect(kp.public).not.toBeFalsy();
        });

        it('should load private key', () => {
          const kp = new SigningKeyPair({ pemPrivateKey: v.priv });
          expectPEMStringsEqual(kp.private.export(), v.priv);
          expectPEMStringsEqual(kp.public.export(), v.pub);
        });

        it('should load encrypted key', () => {
          const kp = new SigningKeyPair({
            pemPrivateKey: v.encPriv,
            password
          });
          expectPEMStringsEqual(kp.private.export(), v.priv);
          expectPEMStringsEqual(kp.public.export(), v.pub);
        });

        it('should encrypt and export', () => {
          const kp = new SigningKeyPair({ algo: k });
          const enc = kp.private.export(password);

          const kp2 = new SigningKeyPair({ pemPrivateKey: enc, password });
          expectPEMStringsEqual(kp.private.export(), kp2.private.export());
        });
      });

      describe('Private Key', () => {
        it('should load and export', () => {
          const key = new SigningPrivateKey({ pemPrivateKey: v.priv });
          expectPEMStringsEqual(key.export(), v.priv);
        });

        it('should load encrypted key', () => {
          const key = new SigningPrivateKey({
            pemPrivateKey: v.encPriv,
            password
          });
          expectPEMStringsEqual(key.export(), v.priv);
        });

        it('should encrypt and export', () => {
          const key = new SigningPrivateKey({ algo: k });
          const enc = key.export(password);

          const key2 = new SigningPrivateKey({ pemPrivateKey: enc, password });
          expectPEMStringsEqual(key.export(), key2.export());
        });

        it('should sign message', () => {
          const key = new SigningPrivateKey({ pemPrivateKey: v.priv });
          const sig = key.sign(msg);
          expectPEMStringsEqual(sig, v.sig);
        });
      });

      describe('Public Key', () => {
        it('should load and export', () => {
          const key = new SigningPublicKey({ pemPublicKey: v.pub });
          expectPEMStringsEqual(key.export(), v.pub);
        });

        it('should verify signature', () => {
          const key = new SigningPublicKey({ pemPublicKey: v.pub });
          expect(key.verify(msg, v.sig)).toBe(true);
        });
      });
    });
  });
});

// Remove new lines fomr PEM strings before comparing them
const expectPEMStringsEqual = (str1, str2) => {
  const rmNewLines = str => str.replace(/\r\n|\n/gm, '');
  expect(rmNewLines(str1)).toBe(rmNewLines(str2));
};
