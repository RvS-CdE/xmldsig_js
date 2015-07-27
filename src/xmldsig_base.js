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
                   ,sign : sign_text
                   };

    function set_params(P)
        {
        for (var key in P)
            {
            if (P.hasOwnProperty(key))
                params[key] = P[key]
            }
        _log("I Parameters set, current config:",params);
        return this;
        }

    function sign_text(RawTxt)
        {
        var CleanText = RawTxt.replace(/\r/g,'');
        //var MsgDigest = 
        return new Promise(
            function(resolve,reject)
                {
                try
                    {
                    build_xmldsig(RawTxt).then(function(XMLDSig)
                        {
                        resolve(XMLDSig);
                        });
                    }
                catch (e)
                    {
                    reject(e);
                    }
                });
        }

    ////////////////////////// TEST STUFF AND PLUMBING
    //////////////////////////////////////////////////
    //////////////////////////////////////////////////
    function digest(Str)
        {
        var buffer = new TextEncoder("utf-8").encode(Str);
        return crypto.subtle.digest(defaults.hashf, buffer)
                            .then(function (hash) {
                                    return btoa(hex(hash));
                                    });
        }

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

    ///////////////////////////////// XMLDSig creation
    //////////////////////////////////////////////////
    //////////////////////////////////////////////////
    var XML_MASK = '\<?xml version="1.0" encoding="UTF-8"?>\
<Signature xmlns="http://www.w3.org/2000/09/xmldsig#">\
<SignedInfo>\
  <CanonicalizationMethod Algorithm="http://www.w3.org/TR/2001/REC-xml-c14n-20010315" />\
  <SignatureMethod Algorithm="http://www.w3.org/2000/09/xmldsig#rsa-sha256" />\
  <Reference URI="#object">\
    <DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha256" />\
    <DigestValue>%DIGEST%</DigestValue>\
  </Reference>\
</SignedInfo>\
<SignatureValue>%SIGNATUREVALUE%</SignatureValue>\
<KeyInfo>\
  <KeyValue>\
    <RSAKeyValue>\
      <Modulus>%MODULUS%</Modulus>\
      <Exponent>AQAB</Exponent>\
    </RSAKeyValue>\
  </KeyValue>\
</KeyInfo>\
<Object Id="object">%OBJECT%</Object>\
</Signature>';

    var OBJ_CANONICAL_MASK = '<Object xmlns="http://www.w3.org/2000/09/xmldsig#" Id="object">%OBJECT%</Object>';

    var SINFO_CANONICAL_MASK = '<SignedInfo xmlns="http://www.w3.org/2000/09/xmldsig#">\
  <CanonicalizationMethod Algorithm="http://www.w3.org/TR/2001/REC-xml-c14n-20010315"></CanonicalizationMethod>\
  <SignatureMethod Algorithm="http://www.w3.org/2000/09/xmldsig#rsa-sha256"></SignatureMethod>\
  <Reference URI="#object">\
    <DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha256"></DigestMethod>\
    <DigestValue>%DIGEST%</DigestValue>\
  </Reference>\
</SignedInfo>';

    function build_xmldsig(Text)
        {
        _log('I Preparing XMLDSig for ',Text);
        var CanonicalForm = canonicalize(Text);
        _log('I Canonical form: ',CanonicalForm);
        return hash(CanonicalForm).then(function(Digest)
                                           {
                                           _log('I Digest: ',Digest);
                                           var ToSign        = encapsulate(Digest);
                                           _log('I To Sign:', ToSign);
                                           return defaults.pkcs11.sign(hash(ToSign),defaults.hashf)
                                                          .then(function(sign_hex)
                                                                  {
                                                                  return {sign_hex:sign_hex,digest:Digest};
                                                                  });
                                           })
                                  .then(function(data)
                                           {
                                           var Signature     = btoa(data.sign_hex);
                                           _log('I Signature:', Signature);
                                           return compose_xml(Text,data.digest,Signature);
                                           });
        }

    function canonicalize(RawText)
        {
        // This is very incomplete at this moment
        var CleanText = RawText.replace(/\r/g,'');
        return OBJ_CANONICAL_MASK.replace('%OBJECT%',CleanText);
        }

    function hash(Str)
        {
        var buffer = new TextEncoder("utf-8").encode(Str);
        return crypto.subtle.digest(defaults.hashf, buffer)
                            .then(function (hashed) {
                                    return btoa(hex(hashed));
                                    });
        }

    function encapsulate(Digest)
        {
        return SINFO_CANONICAL_MASK.replace('%DIGEST%',Digest);
        }

    function compose_xml(RawText,Digest,Signature)
        {
        // Work in progress
        var CleanText = RawText;
        return XML_MASK.replace('%OBJECT%',CleanText)
                       .replace('%DIGEST%',Digest)
                       .replace('%SIGNATUREVALUE%',Signature);
        }

    })();
