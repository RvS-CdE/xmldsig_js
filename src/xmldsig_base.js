// See :
// https://github.com/RvS-CdE/xmldsig_js
//
// The object still needs a pkcs#11 services provider.

(function()
    {
    var root = this,
        w    = window,
        defaults = {log : false
                   ,pkcs11 : null
                   ,hashf  : 'SHA-256'
                   },
        params = defaults;

    ////////////////////////////////////////////// API
    //////////////////////////////////////////////////
    //////////////////////////////////////////////////
    w.xmldsig_js = {set  : set_params
                   ,sign : xmldsig_promise
                   };

    function set_params(P)
        {
        if (P.hashf != null && HashSettings[P.hashf] == null)
            throw 'xmldsig_hash_function_not_defined';

        for (var key in P)
            {
            if (P.hasOwnProperty(key))
                params[key] = P[key]
            }
        _log("I Parameters set, current config:",params);
        return this;
        }

    function xmldsig_promise(RawText)
        {
        assert_only_unicode(RawText);
        if (params.pkcs11 == null)
            throw 'xmldsig_no_pkcs11_defined'

        return build_xmldsig(RawText);
        }

    ///////////////////////////////// XMLDSig creation
    //////////////////////////////////////////////////
    //////////////////////////////////////////////////
    var XML_MASK = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"+
"<Signature %PROP%>\n"+
"%SIGNEDINFO%\n"+
"<SignatureValue>%SIGNATUREVALUE%</SignatureValue>\n"+
"%KEYINFO%\n"+
"%OBJECT%\n"+
"</Signature>";

    var XML_PROP = 'xmlns="http://www.w3.org/2000/09/xmldsig#"';

    var OBJ_MASK = "<Object%PROP% Id=\"object\">%OBJECT%</Object>";

    var SINFO_MASK = "<SignedInfo%PROP%>\n"+
"  <CanonicalizationMethod Algorithm=\"http://www.w3.org/TR/2001/REC-xml-c14n-20010315\"></CanonicalizationMethod>\n"+
"  <SignatureMethod Algorithm=\"%SIGN_ALGO%\"></SignatureMethod>\n"+
"  <Reference URI=\"#object\">\n"+
"    <DigestMethod Algorithm=\"%DIGEST_ALGO%\"></DigestMethod>\n"+
"    <DigestValue>%DIGEST%</DigestValue>\n"+
"  </Reference>\n"+
"</SignedInfo>";

    var KEYINFO_MASK = "<KeyInfo>\n"+
"  <KeyValue>\n"+
"    <RSAKeyValue>\n"+
"      <Modulus>%MODULUS%</Modulus>\n"+
"      <Exponent>%EXPONENT%</Exponent>\n"+
"    </RSAKeyValue>\n"+
"  </KeyValue>\n"+
"  <X509Data>\n"+
"    <X509SubjectName>%SUBJECTNAME%</X509SubjectName>\n"+
"    <X509IssuerSerial>\n"+
"      <X509IssuerName>%ISSUERNAME%</X509IssuerName>\n"+
"      <X509IssuerSerialNumber>%ISSUERSERIAL%</X509IssuerSerialNumber>\n"+
"    </X509IssuerSerial>\n"+
"    <X509Certificate>%CERT%</X509Certificate>\n"+
"  </X509Data>\n"+
"</KeyInfo>";

    var HashSettings = {'SHA-256' : {xmldigest_signalgo   : "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"
                                    ,xmldigest_digestalgo : "http://www.w3.org/2001/04/xmlenc#sha256"}
                       ,'SHA-1'    : {xmldigest_signalgo   : "http://www.w3.org/2000/09/xmldsig#rsa-sha1"
                                    ,xmldigest_digestalgo : "http://www.w3.org/2000/09/xmldsig#sha1"}
                       ,'SHA-512' : {xmldigest_signalgo   : "http://www.w3.org/2001/04/xmldsig-more#rsa-sha512"
                                    ,xmldigest_digestalgo : "http://www.w3.org/2001/04/xmlenc#sha512"}
                       ,'SHA-384' : {xmldigest_signalgo   : "http://www.w3.org/2001/04/xmldsig-more#rsa-sha384"
                                    ,xmldigest_digestalgo : "http://www.w3.org/2001/04/xmldsig-more#sha384"}
                       ,'SHA-224' : {xmldigest_signalgo   : "http://www.w3.org/2001/04/xmldsig-more#rsa-sha224"
                                    ,xmldigest_digestalgo : "http://www.w3.org/2001/04/xmldsig-more#sha224"}
                       };


    function build_xmldsig(Text)
        {
        _log('I Preparing XMLDSig for ',Text);
        var CanonicalForm = compose_object(Text,true);
        _log('I Canonical form: ',CanonicalForm);

        return defaults.pkcs11.certificate().then(function(Cert)
                        {
                        var A = ASN1.decode(Hex.decode(Cert.hex));
                        var C = X509_2_json(A);
                        if (C.Certificate.Subject.SerialNumber != null && C.Certificate.Subject.UID == null)
                            C.Certificate.Subject.UID = C.Certificate.Subject.SerialNumber;

                        var KeyMatch = C.Certificate.SubjectPublicKeyInfo.SubjectPublicKey.Modulus.match(/\(([0-9]+).*\)/);
                        var HashF = defaults.hashf;
                        var SignF = defaults.hashf

                        if (KeyMatch[1] != null)
                            {
                            // Downgrade hash to 224 for 1024 bit keys
                            if (KeyMatch[1] == '1024' && HashF != 'SHA-1')
                                {
                                _log('W Downgraded signature hash function to SHA-1: 1024 bit key detected, crypto.subtle does not support SHA-224');
                                SignF = 'SHA-1';
                                HashF = 'SHA-1';
                                }
                            }

                        var payload = {'cert_raw' : Cert.raw
                                      ,'cert_hex' : Cert.hex
                                      ,'cert_json': C
                                      ,'keyLength': KeyMatch[1] != null ? KeyMatch[1] : 'unknown'
                                      ,'hashf'    : HashF
                                      ,'signf'    : SignF};

                        _log('I Initalizing payload: ',payload);

                        return hash_promise(CanonicalForm,payload.hashf).then(function(Digest)
                                            {
                                            payload.digest = Digest;
                                            return payload;
                                            });
                        },function(err)
                        {
                        _log('E get certificate failed',err);
                        throw('xmldsig_failed_cert_retrieval');
                        })
                   .then(function(payload)
                       {
                       var ToSign = compose_signedinfo(payload.digest, true,payload.hashf,payload.signf);
                       _log('I To Sign:', ToSign);
                       return hash_promise(ToSign,payload.hashf).then(function(signedinfo_digest)
                                              {
                                              payload.sign_digest = signedinfo_digest;
                                              return payload
                                              });
                       })
                  .then(function(payload)
                       {
                       var PKCS11_payload = {'base64hash' : payload.sign_digest
                                            ,'digest_alg' : payload.signf
                                            ,'cert'   : payload.cert_raw};

                       _log('I PKCS11 Payload',PKCS11_payload);
                       return defaults.pkcs11.sign(PKCS11_payload)
                                      .then(function(signature)
                                              {
                                              payload.sign_hex = signature.hex;
                                              return payload
                                              });
                       })
                  .then(function(payload)
                       {
                       var Signature = hexToBase64(payload.sign_hex);
                       _log('I Signature:', Signature);
                       return compose_xml(compose_object(Text)
                                         ,compose_signedinfo(payload.digest,false,payload.hashf,payload.signf)
                                         ,compose_keyinfo(payload.cert_json,payload.cert_hex)
                                         ,Signature);
                       });
        }

    function compose_object(RawText, Canonical)
        {
        // This is very incomplete at this moment
        var Canonical = Canonical || false;
        //var CleanText = Canonical ? c14n_text(RawText) : RawText;
        var CleanText = c14n_text(RawText);
        var ExtProp = Canonical ? ' ' + XML_PROP : '';

        return OBJ_MASK.replace('%OBJECT%',CleanText)
                       .replace('%PROP%',ExtProp);
        }

    function compose_signedinfo(Digest,Canonical,HashF,SignF)
        {
        var Canonical = Canonical || false;
        var ExtProp = Canonical ? ' ' + XML_PROP : '';

        return SINFO_MASK.replace('%DIGEST%',Digest)
                         .replace('%SIGN_ALGO%',HashSettings[SignF].xmldigest_signalgo)
                         .replace('%DIGEST_ALGO%',HashSettings[HashF].xmldigest_digestalgo)
                         .replace('%PROP%',ExtProp);
        }

    function compose_keyinfo(C,KeyHex)
        {
        var Exponent = integer2base64(C.Certificate.SubjectPublicKeyInfo.SubjectPublicKey.Exponent);
        var RawMod = C.Certificate.SubjectPublicKeyInfo.SubjectPublicKey.Modulus;
        var CleanMod = RawMod.replace(/^\(.*\)[^0-9]*/,'');
        var Modulus = integer2base64(CleanMod);
        return KEYINFO_MASK.replace('%CERT%',format_b64(hexToBase64(KeyHex),4))
                           .replace('%ISSUERSERIAL%',C.Certificate.Issuer.SerialNumber)
                           .replace('%ISSUERNAME%',compose_ldapname(C.Certificate.Issuer))
                           .replace('%SUBJECTNAME%',compose_ldapname(C.Certificate.Subject))
                           .replace('%EXPONENT%',Exponent)
                           .replace('%MODULUS%',format_b64(Modulus,6));
        }

    function compose_ldapname(D)
        {
        console.log(D);
        var Out = [];
        var Check = ['CN','L','ST','O','OU','C','STREET','DC','UID'];
        for (var i=0,l=Check.length;i<l;i++)
            {
            var el = Check[i];
            if (D.hasOwnProperty(el))
                Out.push(el+'='+c14n_text(D[el].replace(/,/g,'\,')));
            }
        return Out.join(',');
        }

    function compose_xml(Obj,SignedInfo,KeyInfo,Signature)
        {
        // Work in progress
        return XML_MASK.replace('%OBJECT%',Obj)
                       .replace('%SIGNEDINFO%',SignedInfo)
                       .replace('%KEYINFO%',KeyInfo)
                       .replace('%SIGNATUREVALUE%',format_b64(Signature))
                       .replace('%PROP%',XML_PROP);
        }

    function hash_promise(Str,HashF)
        {
        console.log(HashF);
        var buffer = new TextEncoder("utf-8").encode(Str);

        return crypto.subtle.digest(HashF, buffer)
                            .then(function (hashed) {
                                    return hexToBase64(hex(hashed));
                                    });
        }

    ///////////////////////////////// GENERAL PLUMBING
    //////////////////////////////////////////////////
    //////////////////////////////////////////////////
    function hex(buffer) {
        var hexCodes = [];
        var view = new DataView(buffer);
        for (var i = 0; i < view.byteLength; i += 4) 
            {
            // Using getUint32 reduces the number of iterations needed (we process 4 bytes each time)
            var value = view.getUint32(i)
            // toString(16) will give the hex representation of the number without padding
            var stringValue = value.toString(16)
            // We use concatenation and slice for padding
            var padding = '00000000'
            var paddedValue = (padding + stringValue).slice(-padding.length)
            hexCodes.push(paddedValue);
            }
        // Join all the hex strings into one
        return hexCodes.join("");
        }

    function _log()
        {
        if (params.log && window.console && window.console.log)
            window.console.log.apply(console,arguments)
        }

    function integer2base64(IntStr)
        {
        return hexToBase64(dec2hex(IntStr));
        }

    function format_b64(RawIn,Indent)
        {
        var Out = [], buffer = [], pos=0;
        var Indent = Indent || 0;
        var Prefix = new Array(Indent + 1).join(' ');
        var In = RawIn.split('').reverse();
        while (In.length)
            {
            buffer.push(In.pop());
            if (buffer.length == 64)
                {
                Out.push(Prefix + buffer.join(''));
                buffer = [];
                }
            }
        if (buffer.length > 0)
            Out.push(Prefix + buffer.join(''));

        return Out.join("\n").trim();
        }

    function c14n_text(Str)
        {
        Str = Str.replace(/\r/g,'');
        Str = Str.replace(/&/g,'&amp;');
        Str = Str.replace(/</g,'&lt;');
        Str = Str.replace(/>/g,'&gt;');
        //Str = Str.replace(/"/g,'&quot;');
        //Str = Str.replace(/'/g,'&apos;');
        return Str;
        }

    function assert_only_unicode(Str)
        {
        try {
            encodeURIComponent(Str)
            }
        catch(e)
            {
            throw('xmldsig_bad_input_string_encoding');
            }
        }

    // Inspiration:
    // http://stackoverflow.com/questions/23190056/hex-to-base64-converter-for-javascript
    function hexToBase64(str) 
        {
        return btoa(String.fromCharCode
                          .apply(null
                                ,str.replace(/\r|\n/g, "")
                                    .replace(/([\da-fA-F]{2}) ?/g, "0x$1 ")
                                    .replace(/ +$/, "")
                                    .split(" ")
                                ));
        }

    // Inspiration:
    // http://stackoverflow.com/questions/18626844/convert-a-large-integer-to-a-hex-string-in-javascript
    function dec2hex(str)
        {
        var dec = str.toString().split(''), sum = [], hex = [], i, s;
        while(dec.length)
            {
            s = 1 * dec.shift();
            for(i = 0; s || i < sum.length; i++)
                {
                s += (sum[i] || 0) * 10;
                sum[i] = s % 16;
                s = (s - sum[i]) / 16;
                }
            }

        if (sum.length % 2 > 0)
            sum.push('0');

        while(sum.length)
            hex.push(sum.pop().toString(16));

        return hex.join('');
        }
    /////////////////////////////////// ASN.1 to JSON
    //////////////////////////////////////////////////
    //////////////////////////////////////////////////
    function sequence_convert(Part,A)
        {
        var S = get_sequence(Part,A);
        return sequence_2_json(S,A);
        }

    function sequence_2_json(S)
        {
        if (S == null) return null;

        if (!S.tag.tagConstructed)
            return S.content();

        if (S.sub.length == 1)
            {
            if (S.tag.tagConstructed)
                return sequence_2_json(S.sub[0]);
            else
                return S.sub[0].content();
            }

        if (S.sub.length == 2 && S.sub[0].typeName() == 'OBJECT_IDENTIFIER')
            {
            var key = oid2description(S.sub[0].content());
            if (S.sub[1].typeName() == 'NULL')
                return key;
            var val = S.sub[1].content();
            return eval('({\''+key+'\':\''+val+'\'})');
            }

        if (S.sub[0].typeName() == 'SET')
            {
            var Out = {}
            for (var i=0,l=S.sub.length;i<l;i++)
                {
                var Temp = sequence_2_json(S.sub[i]);
                for (var key in Temp)
                    Out[key] = Temp[key];
                }
            return Out;
            }

        _log('E Sequence fail to jsonize:',S);
        return "Sequence case not defined";
        }

    function get_sequence(Part,A)
        {
        var N = cert_has_version(A) ? 0 : 1;
        switch (Part)
            {
            case 'Certificate': return A.sub[0];
            case 'Certificate Signature Algorithm': return A.sub[1];
            case 'Certificate Signature': return A.sub[2];

            case 'Version': return N == 0 ? get_sequence('Certificate',A).sub[0] : null;
            case 'Serial Number': return get_sequence('Certificate',A).sub[1-N];
            case 'Algorithm ID': return get_sequence('Certificate',A).sub[2-N];
            case 'Issuer': return get_sequence('Certificate',A).sub[3-N];
            case 'Validity': return get_sequence('Certificate',A).sub[4-N];
                    case 'Not Before': return get_sequence('Validity',A).sub[0];
                    case 'Not After': return get_sequence('Validity',A).sub[1];
            case 'Subject': return get_sequence('Certificate',A).sub[5-N];
            case 'Subject Public Key Info': return get_sequence('Certificate',A).sub[6-N];
                case 'Public Key Algorithm': return get_sequence('Subject Public Key Info',A).sub[0];
                case 'Subject Public Key': return get_sequence('Subject Public Key Info',A).sub[1];
                    case 'RSA Modulus': return get_sequence('Subject Public Key',A).sub[0].sub[0];
                    case 'RSA Exponent': return get_sequence('Subject Public Key',A).sub[0].sub[1];
            }
        }

    function X509_2_json(X509)
        {
        return {'Certificate' : {'Version' : sequence_convert('Version',X509)
                                ,'SerialNumber' : sequence_convert('Serial Number',X509)
                                ,'AlgorithmID' : sequence_convert('Algorithm ID',X509)
                                ,'Issuer' : sequence_convert('Issuer',X509)
                                ,'Validity' : {'NotBefore' : sequence_convert('Not Before',X509)
                                              ,'NotAfter'  : sequence_convert('Not After',X509)}
                                ,'Subject' : sequence_convert('Subject',X509)
                                ,'SubjectPublicKeyInfo' :
                                              {'PublicKeyAlgorithm' : sequence_convert('Public Key Algorithm', X509)
                                              ,'SubjectPublicKey' : {'Modulus'  : sequence_convert('RSA Modulus', X509)
                                                                    ,'Exponent' : sequence_convert('RSA Exponent', X509) } 
                                              }
                                }
               };
        }

    /////////////////////////////////// ASN.1 PLUMBING
    //////////////////////////////////////////////////
    //////////////////////////////////////////////////
    var oid2key = {'1.2.840.113549.1.1.5' : 'sha1WithRSAEncryption'
                  ,'1.2.840.113549.1.1.1' : 'rsaEncryption'
                  ,'1.2.840.113549.1.1.11' : 'sha256WithRSAEncryption'
                  ,'2.5.4.3'  : 'CN'
                  ,'2.5.4.4'  : 'SN'
                  ,'2.5.4.42' : 'GN'
                  ,'2.5.4.11' : 'OU'
                  ,'2.5.4.10' : 'O'
                  ,'2.5.4.7'  : 'L'
                  ,'2.5.4.8'  : 'S'
                  ,'2.5.4.6'  : 'C'
                  ,'2.5.4.5'  : 'SerialNumber'
                  }

    function cert_has_version(A)
        {
        var VersionSeq = A.sub[0].sub[0];
        if (VersionSeq.sub == null
           || VersionSeq.sub[0] == null
           || VersionSeq.sub[0].typeName() != "INTEGER")
            return false;

        return true;
        }

    function oid2description(Oid)
        {
        var t = oid2key[Oid];
        return t != null ? t : Oid;
        }

    })();
