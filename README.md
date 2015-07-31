# xmldsig\_js
No-frills XML-Dsig javascript implementation.

## No-frills ? ##
xmldsig\_js attempts to provide in a simple and convient way nothing more then a valid XML-Dsig signature, for situations in which such a signature suffices. This does not exclude further developments providing more advanced signatures, which will have their own repositories.

Instead of having Javascript generating and parsing XML, the XML is simply hard-coded and concatenated in order to obtain a satisfactory result in a short time.

## PKCS\#11 ##
PKCS\#11 functionality (aka smartcard access) is provided by a module which should be interchangeable with others once they're available (or once PKCS#11 will be natively supported by the browsers).

The current module is based on the Estonian open-eID effort, hwcrypto.js, which provides the required primitives necessary for electronic signatures.

Other basic crypto functionalites are provided by the web.crypto API standardized by the W3C and currently implemented by the browser vendors.

# How to use ?#
Besides including the necessary files (see demo.html for working example):

```javascript
pkcs11_hwcrypto.init();
xmldsig_js.set({pkcs11: pkcs11_hwcrypto});

var xmldsig_promise = xmldsig_js.sign("Your Text");
```

# What does the result look like ?#
XML-Dsig signature, signed with a belgian eID card (X509 certificate stripped out):

```xml
<?xml version="1.0" encoding="UTF-8"?>
<Signature xmlns="http://www.w3.org/2000/09/xmldsig#">
<SignedInfo>
  <CanonicalizationMethod Algorithm="http://www.w3.org/TR/2001/REC-xml-c14n-20010315"></CanonicalizationMethod>
  <SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"></SignatureMethod>
  <Reference URI="#object">
    <DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"></DigestMethod>
    <DigestValue>rvb+z3l1XwG3+YHrAYksBd2ihLHyDG9VgosZ4+hcU08=</DigestValue>
  </Reference>
</SignedInfo>
<SignatureValue>E7jKkRl1cbHGcHbB3WXkKPtWGhA1nyS8V3ifnQes7hS8oz4W/1blrrmRQhuYQeQE
DEZ4s1EXZjgMUuYGNbMzUhsrFOcR6gLPFPBQ6uOoBgn9tBS2ZF6C4EkQWFCVy+Nc
g4LPrN6moysut1KRTFBPwZKWl0cmlL61KrKkljd+t1YI6nSzYLQdy/YVwlj0x3A2
gGVEyG04UNff2bSgZjH/MnSaheDgXuJrJHerUESpnjqPH9sE6ts3+KreuDgpiOoP
a7NaRBbK2EakGq3oq4wwzQYCUa18yfmFc6Y0GAw2/LbbWDxr/29kdqL2s7C6EcXM
HcGpBgXTFydUecG+MjeQ0Q==</SignatureValue>
<KeyInfo>
  <KeyValue>
    <RSAKeyValue>
      <Modulus>uK2G/ksNZFMQ3laEH4PnewthiQqeAmBJTzhtNoMwkLhU/Z3R+Pqn1/Nt0fmaSwY0
      xdHijxY3Uxhq7r3HtGrF285ZqxKM6zUmlLo3OudIG7RhJ4wmXPvOgDAycTJggpyS
      jzdAwt3OpgbTmzX0HbNJQwKrhoj8tUgWEK3P+b/NFHX3oYlxMOjAMe4z9JIF+uFj
      IZ73HAuATHuQI0ZwBhL37JF+0aaHXLkZJzztaaUnmV5kG7riqh9lPrzN3zt5nnHn
      Ni1wrJFxAc5r34gnmLXbUkOt3xLLZM4qJkeFjhy9Sp+V2kCqy2fYjI5Q2GmWlb51
      kX7NQXeG/xM1q/zpfmHCxQ==</Modulus>
      <Exponent>AQAB</Exponent>
    </RSAKeyValue>
  </KeyValue>
  <X509Data>
    <X509SubjectName>CN=Pieterjan Montens (Signature),C=BE,UID=[..]</X509SubjectName>
    <X509IssuerSerial>
      <X509IssuerName>CN=Citizen CA,C=BE</X509IssuerName>
      <X509IssuerSerialNumber>201501</X509IssuerSerialNumber>
    </X509IssuerSerial>
    <X509Certificate>[...]</X509Certificate>
  </X509Data>
</KeyInfo>
<Object Id="object">Your Text</Object>
</Signature>
```
The resulting signature can be [verified here](https://www.aleksey.com/xmlsec/xmldsig-verifier.html).

## pkcs11\_hwcrypto.js requirements ##
The `hwcrypto` module needs access to a PKCS#11 backend. The Estonian open-eid project provides add-ons for Firefox, Chrome, and Safari should work as well. These extensions should be available in each of the browser's extension stores. IE11 (aka edge) should have support in the future. Older IE versions can also be supported but need more work (such as using a promises polyfill for missing javascript functionality).


Note to developers:
-------------------
Never trust browser-originating content, verify server-side.

TODO :
-----------------------
- Don't forget a single-file minimized container for easy integration.
